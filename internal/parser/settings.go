package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
//     array/merge keys honored from every scope, so a project value applies.
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
	// Prompt is the injected context for a type:"prompt" hook — text Claude Code
	// feeds into its own context when the hook event fires. Like an instruction
	// file, it is read as trusted guidance, so it is a prompt-injection surface
	// the instruction-content rules must scan (see instructionSources).
	Prompt  string `json:"prompt,omitempty"`
	Timeout int    `json:"timeout,omitempty"`

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
func ParseMCPConfig(path string) (*MCPConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
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

// ParseSettings reads and decodes a settings.json file.
func ParseSettings(path string) (*Settings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseSettingsBytes(data, path)
}

// ParseSettingsBytes decodes settings.json from an in-memory byte slice.
// path is used only for error messages.
func ParseSettingsBytes(data []byte, path string) (*Settings, error) {
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.Raw); err != nil {
		return nil, fmt.Errorf("parse raw %s: %w", path, err)
	}
	return &s, nil
}
