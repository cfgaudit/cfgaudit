// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Settings is a partial representation of Claude Code's settings.json.
// Unknown keys are preserved in the raw map so rules can inspect them.
type Settings struct {
	Permissions *Permissions           `json:"permissions,omitempty"`
	Env         map[string]string      `json:"env,omitempty"`
	Hooks       map[string][]HookGroup `json:"hooks,omitempty"`
	MCPServers  map[string]MCPServer   `json:"mcpServers,omitempty"`

	// Raw holds the full decoded document for rules that need arbitrary access.
	Raw map[string]json.RawMessage `json:"-"`
}

// CommandHelper is the {"type":"command","command":"…"} shape used by the
// statusLine and fileSuggestion settings.
type CommandHelper struct {
	Type    string `json:"type,omitempty"`
	Command string `json:"command,omitempty"`
}

// StringField returns a top-level key expected to hold a JSON string. Missing
// keys and values of the wrong type both yield "" — accessors stay type-tolerant
// so a single mistyped key never aborts the whole parse (CFG012 reports the
// type mismatch separately). Used for the command-bearing keys Claude Code
// executes besides hooks (apiKeyHelper, awsCredentialExport, awsAuthRefresh,
// gcpAuthRefresh, otelHeadersHelper) — an RCE surface a repo-controlled
// settings.json can abuse, the same class as a malicious hook (CVE-2025-59536).
func (s *Settings) StringField(key string) string {
	raw, ok := s.Raw[key]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// CommandHelperField returns the .command of a {"type":..,"command":..} object
// key (statusLine, subagentStatusLine, fileSuggestion). Missing or mistyped
// values yield "".
func (s *Settings) CommandHelperField(key string) string {
	raw, ok := s.Raw[key]
	if !ok {
		return ""
	}
	var v CommandHelper
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v.Command
}

// MarketplacesKey is the canonical spelling of the settings key that registers
// extra plugin marketplaces, and MarketplacesAliasKey is the alias Claude Code
// 2.1.232 added for it.
const (
	MarketplacesKey      = "extraKnownMarketplaces"
	MarketplacesAliasKey = "additionalMarketplaces"
)

// Marketplaces returns the raw value of the extra-marketplaces key together with
// the spelling it was written with, so a finding can name the key the file
// actually used. The second return is "" when neither spelling is present.
//
// Claude Code documents the alias as "read exactly as if it were spelled
// extraKnownMarketplaces", and resolves a file that carries both in favour of the
// canonical key. Verified against 2.1.241, which accepts an alias-only file
// silently and reports the other case as: "additionalMarketplaces" is an alias
// for "extraKnownMarketplaces" and this file sets both; the
// "additionalMarketplaces" value was ignored.
//
// The conflict is judged per file, which is why this reads one Settings rather
// than a merged view: a repository spelling it one way and a user file the other
// are two separate declarations, each honoured in its own file.
func (s *Settings) Marketplaces() (json.RawMessage, string) {
	if s == nil {
		return nil, ""
	}
	if raw, ok := s.Raw[MarketplacesKey]; ok && len(raw) > 0 {
		return raw, MarketplacesKey
	}
	if raw, ok := s.Raw[MarketplacesAliasKey]; ok && len(raw) > 0 {
		return raw, MarketplacesAliasKey
	}
	return nil, ""
}

// SettingsMarketplace is one entry of the extra-marketplaces object in a settings
// file. It carries the same source shape as a marketplace manifest, plus the
// inline plugin catalog a settings-declared marketplace may bring with it.
//
// The command-bearing fields are the reason this is decoded: Claude Code's own
// dangerous-settings inventory lists exactly
// `extraKnownMarketplaces[].source.headersHelper`,
// `extraKnownMarketplaces[].headersHelper` and
// `extraKnownMarketplaces[].plugins[].source.command`.
type SettingsMarketplace struct {
	Source        MarketplaceSource         `json:"source"`
	HeadersHelper string                    `json:"headersHelper"`
	Plugins       []SettingsMarketplacePlug `json:"plugins"`
}

// SettingsMarketplacePlug is one entry of a settings-inline plugin catalog.
type SettingsMarketplacePlug struct {
	Name   string            `json:"name"`
	Source MarketplaceSource `json:"source"`
}

// MarketplaceEntries decodes the extra-marketplaces object, resolving the alias
// spelling the same way Marketplaces does. Names are returned sorted so findings
// are stable. A value that does not decode yields no entries rather than an
// error: the schema gains fields over time, and refusing to parse a newer shape
// would drop the whole block instead of the part cfgaudit does not model yet.
func (s *Settings) MarketplaceEntries() ([]NamedSettingsMarketplace, string) {
	raw, key := s.Marketplaces()
	if len(raw) == 0 {
		return nil, ""
	}
	var decoded map[string]SettingsMarketplace
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, key
	}
	names := make([]string, 0, len(decoded))
	for name := range decoded {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]NamedSettingsMarketplace, 0, len(names))
	for _, name := range names {
		out = append(out, NamedSettingsMarketplace{Name: name, Entry: decoded[name]})
	}
	return out, key
}

// NamedSettingsMarketplace pairs a decoded entry with the name it was declared
// under, so a finding can name the marketplace rather than an index.
type NamedSettingsMarketplace struct {
	Name  string
	Entry SettingsMarketplace
}

// SandboxConfig is the subset of the sandbox settings object cfgaudit inspects.
// excludedCommands run outside the execution sandbox; bwrapPath/socatPath point
// the sandbox's bubblewrap binary and network proxy and are documented as
// honored only from managed settings. allowAppleEvents (macOS) lifts the Apple
// Events block, which removes code-execution isolation; it is honored only from
// user/managed/CLI settings (project settings cannot enable it).
//
// The remaining fields are additional sandbox-weakening keys (CFG022). Their
// per-key settings-scope honoring, verified against the Claude Code sandbox docs,
// is what decides whether a committed value is a real finding or inert:
//   - network.allowUnixSockets / allowAllUnixSockets and filesystem.allowWrite are
//     array/merge keys honored from every scope, so a project value applies,
//     except while managed settings require the sandbox: then project settings
//     contribute none (2.1.288's "as enforced" schema, #618).
//   - enableWeakerNestedSandbox / enableWeakerNetworkIsolation are booleans; a
//     managed value wins, but absent one a project/user value applies.
//   - filesystem.disabled is honored ONLY from user/managed/CLI settings; a
//     project value is ignored (like allowAppleEvents), so it must not be flagged
//     from a project file.
type SandboxConfig struct {
	ExcludedCommands []string `json:"excludedCommands,omitempty"`
	BwrapPath        string   `json:"bwrapPath,omitempty"`
	SocatPath        string   `json:"socatPath,omitempty"`
	AllowAppleEvents bool     `json:"allowAppleEvents,omitempty"`
	// AllowNestedUserNamespaces (Claude Code 2.1.305) lets sandboxed commands on
	// Linux and WSL2 create user namespaces; honoured from user, managed and
	// --settings values only.
	AllowNestedUserNamespaces bool `json:"allowNestedUserNamespaces,omitempty"`

	EnableWeakerNestedSandbox    bool               `json:"enableWeakerNestedSandbox,omitempty"`
	EnableWeakerNetworkIsolation bool               `json:"enableWeakerNetworkIsolation,omitempty"`
	Filesystem                   *SandboxFilesystem `json:"filesystem,omitempty"`
	Network                      *SandboxNetwork    `json:"network,omitempty"`
}

// SandboxFilesystem is the sandbox.filesystem object. allowWrite grants
// subprocess write access outside the working directory (merged across scopes);
// disabled turns the whole filesystem-isolation layer off (user/managed only).
type SandboxFilesystem struct {
	AllowWrite []string `json:"allowWrite,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
}

// SandboxNetwork is the sandbox.network object. allowUnixSockets lists specific
// Unix-socket paths the sandbox may reach; allowAllUnixSockets opens all of them.
type SandboxNetwork struct {
	AllowUnixSockets    []string `json:"allowUnixSockets,omitempty"`
	AllowAllUnixSockets bool     `json:"allowAllUnixSockets,omitempty"`
}

// Sandbox decodes the top-level sandbox object. Returns nil when absent or of the
// wrong type (CFG012 reports the schema mismatch separately).
func (s *Settings) Sandbox() *SandboxConfig {
	raw, ok := s.Raw["sandbox"]
	if !ok {
		return nil
	}
	var sc SandboxConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil
	}
	return &sc
}

type Permissions struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
	// Ask forces a confirmation prompt even where an allow rule would match. It
	// is read by CFG101, which judges an ask rule by the same evasion the deny
	// rules are judged by: a rule that does not match is a prompt that does not
	// happen.
	Ask []string `json:"ask,omitempty"`
	// DefaultMode is the permission mode, nested under permissions in the schema
	// (permissions.defaultMode) — NOT a top-level settings key. Read by CFG004.
	DefaultMode string `json:"defaultMode,omitempty"`
}

// HookGroup is the per-event hook entry: a matcher plus the commands it triggers.
// Claude Code's hooks schema nests command definitions under a matcher group.
type HookGroup struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []HookCommand `json:"hooks,omitempty"`
}

type HookCommand struct {
	Type string `json:"type,omitempty"`
	// Name identifies the hook. Gemini CLI keys its hooksConfig.disabled kill list
	// by this name, so it is read to skip a handler the same file has disabled.
	Name    string `json:"name,omitempty"`
	Command string `json:"command,omitempty"`
	// Args is the exec form of a Claude Code command hook (2.1.207+): command
	// names the executable and args is its argument vector, spawned without a
	// shell. The command rules read the two joined (#773).
	Args []string `json:"args,omitempty"`
	// Prompt is the injected context for a type:"prompt" hook — text Claude Code
	// feeds into its own context when the hook event fires. Like an instruction
	// file, it is read as trusted guidance, so it is a prompt-injection surface
	// the instruction-content rules must scan (see instructionSources).
	Prompt string `json:"prompt,omitempty"`
	// Timeout is a number of seconds, and fractions are valid: Claude Code loads
	// "timeout": 0.5, so an int field here turned a working file into a parse
	// error (CFG109) that hid every finding in it (#639).
	Timeout float64 `json:"timeout,omitempty"`

	// URL, Headers and AllowedEnvVars belong to a type:"http" handler, which POSTs
	// the event payload to an endpoint instead of running a command (CFG088).
	// Continue's hooks use this same matcher-group shape and support that handler
	// type; Copilot's equivalent fields live on AgentHook, whose file format is a
	// flat event → handlers map rather than matcher groups. Absent for Claude
	// Code, Grok, Gemini and qwen, whose handlers carry no URL.
	URL            string            `json:"url,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	AllowedEnvVars []string          `json:"allowedEnvVars,omitempty"`
}

type MCPServer struct {
	// OAuthClientSecret is a literal OAuth client secret the server declaration
	// carries. Filled by the Codex mapping from [mcp_servers.<name>.oauth]
	// client_secret (#615); no JSON shape cfgaudit reads has one.
	OAuthClientSecret string `json:"-"`

	// BearerTokenFile is a local file whose contents the agent sends as the
	// server's bearer token. Filled by the Grok mapping from bearer_token_file
	// (#616); no JSON shape cfgaudit reads has one.
	BearerTokenFile string `json:"-"`

	// Auth is Cursor's static OAuth block on a remote server (#649):
	// {"CLIENT_ID", "CLIENT_SECRET", "scopes"} per Cursor's MCP docs ("Static
	// OAuth for remote servers"). CLIENT_SECRET is a literal credential unless
	// written as ${env:...}.
	Auth *MCPStaticOAuth `json:"auth,omitempty"`

	Command                 string            `json:"command,omitempty"`
	Args                    []string          `json:"args,omitempty"`
	AlwaysAllow             []string          `json:"alwaysAllow,omitempty"`
	Env                     map[string]string `json:"env,omitempty"`
	DangerouslyAllowBrowser bool              `json:"dangerouslyAllowBrowser,omitempty"`

	// Remote-transport fields (HTTP/SSE/WebSocket MCP servers). URL is the
	// endpoint the agent connects to; Type is the transport ("http"/"sse"/…);
	// Headers are sent on every request (often carrying auth secrets). Empty for
	// stdio servers, which use Command/Args instead.
	URL  string `json:"url,omitempty"`
	Type string `json:"type,omitempty"`
	// Transport is Devin's spelling of Type ("http"/"sse"); ParseDevinConfig
	// folds it into Type so the shared MCP rules only ever read one field.
	Transport string            `json:"transport,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`

	// HeadersHelperKey is the spelling the source file used for HeadersHelper,
	// so a finding names a key the reader can grep for. Empty means the Claude
	// spelling, "headersHelper"; Codex writes "http_headers_helper".
	HeadersHelperKey string `json:"-"`

	// ApprovalModeKey and ApprovedTools carry Codex's approval settings, which
	// remove the confirmation prompt without listing tool names the way
	// alwaysAllow does. ApprovalModeKey is the key that set the server-wide
	// "approve" mode (so a finding can name it), empty when no such mode is set;
	// ApprovedTools are the tools whose own approval_mode is "approve", sorted.
	// Populated by CodexConfig.MCPServerMap; no JSON config spells either.
	ApprovalModeKey string   `json:"-"`
	ApprovedTools   []string `json:"-"`

	// Trust marks a server whose tool calls skip the confirmation prompt. Gemini
	// CLI's key: DiscoveredMCPTool returns false from its confirmation path when
	// `isTrustedFolder() && this.trust`, so it removes the prompt for every tool
	// of that server once the folder is trusted. Only Gemini surfaces declare it,
	// so CFG096 gates on the file the server came from rather than firing wherever
	// the field happens to decode.
	Trust bool `json:"trust,omitempty"`

	// HeadersHelper is a command executed to generate auth headers for a remote
	// MCP server (the per-server analogue of settings.json otelHeadersHelper). It
	// is a shell command, so a repo-controlled value is an RCE surface scanned by
	// the command-content rules (CFG008/009/014/015/027/028/037/038/039/045).
	HeadersHelper string `json:"headersHelper,omitempty"`
}

// MCPConfig is a bare MCP config object whose mcpServers map carries the same
// shape as the inline mcpServers block in settings.json. This covers Claude
// Code's .mcp.json (the file enableAllProjectMcpServers / enabledMcpjsonServers
// auto-approve) as well as other agents' MCP configs (Cursor, VS Code, Windsurf,
// Cline), so the MCP rules reach all of them. VS Code's mcp.json uses a top-level
// "servers" key instead of "mcpServers"; both are decoded and merged.
type MCPConfig struct {
	MCPServers map[string]MCPServer `json:"mcpServers,omitempty"`
	Servers    map[string]MCPServer `json:"servers,omitempty"`
}

// ParseMCPConfig reads and decodes an MCP config file. The VS Code "servers"
// variant is folded into MCPServers so callers see a single map; on a name
// collision the mcpServers entry wins.
// UnwrappedMCPServers reads a repository-root .mcp.json written without the
// mcpServers wrapper, a server-name map at the top level (#614).
//
// VS Code reads that shape since 1.139.0: parseWorkspaceRootMcpConfiguration in
// src/vs/platform/mcp/common/mcpWorkspaceConfiguration.ts takes
// `wrapped ? value.mcpServers : value` (889152a4e), and the discovery that starts
// the servers calls it with trust inherited from the workspace (c81724e65, in
// 1.138.0). Claude Code rejects the same file: on 2.1.288 an unwrapped server
// logged "MCP config errors ... Invalid input: expected record" and did not
// start, while the wrapped control did.
//
// Only applies when the file has neither mcpServers nor servers, and keeps only
// entries that are objects carrying a command or a url, the entries VS Code's
// normalizeMcpServerConfiguration turns into servers. Returns nil when the file
// is absent, wrapped, or holds no such entry.
func UnwrappedMCPServers(path string) (map[string]MCPServer, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if _, ok := top["mcpServers"]; ok {
		return nil, nil
	}
	if _, ok := top["servers"]; ok {
		return nil, nil
	}
	out := map[string]MCPServer{}
	for name, raw := range top {
		var srv MCPServer
		if json.Unmarshal(raw, &srv) != nil {
			continue
		}
		if strings.TrimSpace(srv.Command) == "" && strings.TrimSpace(srv.URL) == "" {
			continue
		}
		out[name] = srv
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func ParseMCPConfig(path string) (*MCPConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// VS Code reads .vscode/mcp.json as JSON with comments, like its other
	// workspace files (#829). The other MCP files stay strict: with a comment
	// in .mcp.json, Claude Code 2.1.310 lists "[Failed to parse] Project config"
	// and loads no server from it, so there it is a real CFG109.
	if isVSCodeWorkspaceFile(path) {
		data = stripJSONC(data)
	}
	var c MCPConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(c.Servers) > 0 {
		if c.MCPServers == nil {
			c.MCPServers = make(map[string]MCPServer, len(c.Servers))
		}
		for name, srv := range c.Servers {
			if _, ok := c.MCPServers[name]; !ok {
				c.MCPServers[name] = srv
			}
		}
		c.Servers = nil
	}
	return &c, nil
}

// isVSCodeWorkspaceFile reports whether path is a file in a .vscode directory.
func isVSCodeWorkspaceFile(path string) bool {
	return filepath.Base(filepath.Dir(path)) == ".vscode"
}

// ParseSettings reads and decodes a settings.json file.
func ParseSettings(path string) (*Settings, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseSettingsBytes(data, path)
}

// ParseSettingsBytes decodes settings.json from an in-memory byte slice.
// path is used only for error messages.
//
// Only a file that is not a JSON object fails. The typed fields are decoded one
// by one and leniently (#826): Claude Code 2.1.310 loads a settings file with
// "env": {"X": 80} or "mcpServers": [...], so failing the whole file on one
// field's type hid every other setting in it from the rules. Whether a wrong
// top-level type makes Claude Code drop the file is decided from Raw
// (rules.SettingsDiscarded), not here.
func ParseSettingsBytes(data []byte, path string) (*Settings, error) {
	var s Settings
	if err := json.Unmarshal(data, &s.Raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.Raw == nil {
		return nil, fmt.Errorf("parse %s: not a JSON object", path)
	}
	s.Permissions = lenientPermissions(s.Raw["permissions"])
	s.Env = lenientEnv(s.Raw["env"])
	s.Hooks = lenientHooks(s.Raw["hooks"])
	s.MCPServers = lenientMap[MCPServer](s.Raw["mcpServers"])
	return &s, nil
}

// lenientPermissions decodes the permissions block, skipping list entries that
// are not strings and a defaultMode that is not one.
func lenientPermissions(raw json.RawMessage) *Permissions {
	var p Permissions
	if len(raw) == 0 || json.Unmarshal(raw, &p) == nil {
		if len(raw) == 0 || string(raw) == "null" {
			return nil
		}
		return &p
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	p = Permissions{Allow: lenientStrings(m["allow"]), Deny: lenientStrings(m["deny"]), Ask: lenientStrings(m["ask"])}
	_ = json.Unmarshal(m["defaultMode"], &p.DefaultMode)
	return &p
}

// lenientStrings decodes a JSON array, keeping only its string elements.
func lenientStrings(raw json.RawMessage) []string {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		var v string
		if json.Unmarshal(it, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// lenientEnv decodes the env block. A number or boolean value is kept as its
// JSON text, the string the variable gets; an object, array or null is skipped.
func lenientEnv(raw json.RawMessage) map[string]string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range m {
		if string(bytes.TrimSpace(v)) == "null" {
			continue
		}
		var str string
		if json.Unmarshal(v, &str) == nil {
			out[k] = str
			continue
		}
		var num json.Number
		var b bool
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		if dec.Decode(&num) == nil {
			out[k] = num.String()
		} else if json.Unmarshal(v, &b) == nil {
			out[k] = strconv.FormatBool(b)
		}
	}
	return out
}

// lenientHooks decodes the hooks block event by event and group by group,
// skipping a group that does not decode.
func lenientHooks(raw json.RawMessage) map[string][]HookGroup {
	var events map[string]json.RawMessage
	if json.Unmarshal(raw, &events) != nil || len(events) == 0 {
		return nil
	}
	out := map[string][]HookGroup{}
	for event, rawGroups := range events {
		var groups []json.RawMessage
		if json.Unmarshal(rawGroups, &groups) != nil {
			continue
		}
		for _, g := range groups {
			var hg HookGroup
			if json.Unmarshal(g, &hg) == nil {
				out[event] = append(out[event], hg)
				continue
			}
			// One handler of the wrong shape: keep the group's other handlers.
			var loose struct {
				Matcher json.RawMessage   `json:"matcher"`
				Hooks   []json.RawMessage `json:"hooks"`
			}
			if json.Unmarshal(g, &loose) != nil {
				continue
			}
			hg = HookGroup{}
			_ = json.Unmarshal(loose.Matcher, &hg.Matcher)
			for _, h := range loose.Hooks {
				var hc HookCommand
				if json.Unmarshal(h, &hc) == nil {
					hg.Hooks = append(hg.Hooks, hc)
				}
			}
			out[event] = append(out[event], hg)
		}
	}
	return out
}

// lenientMap decodes a JSON object of T, skipping entries that do not decode.
func lenientMap[T any](raw json.RawMessage) map[string]T {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return nil
	}
	out := map[string]T{}
	for k, v := range m {
		var t T
		if json.Unmarshal(v, &t) == nil {
			out[k] = t
		}
	}
	return out
}

// MCPStaticOAuth is the part of a Cursor MCP server's `auth` block cfgaudit reads.
type MCPStaticOAuth struct {
	ClientSecret string `json:"CLIENT_SECRET,omitempty"`
}
