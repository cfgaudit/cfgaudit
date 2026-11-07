// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// GrokConfig is the subset of xAI Grok CLI's .grok/config.toml that cfgaudit
// reads. Grok's user guide marks the project file committable ("Project
// (committed) | <project>/.grok/config.toml | Yes (commit it)").
//
// A project-scoped config contributes ONLY [mcp_servers], [plugins] and
// [permission] (plus [mcp] max_output_bytes); every other section — [ui],
// [sandbox], [telemetry], [model.*] — is loaded only from ~/.grok/config.toml
// (05-configuration.md). Reading those from a scanned repo would be a pure false
// positive (the trap .devin/config.json's user-only sandbox.excluded was avoided
// for), so cfgaudit models the two project-contributable tables that carry a
// supply chain: [mcp_servers], whose servers ride ProjectMCP so the shared MCP
// rules apply, and [plugins] (CFG100). No rule reports a [permission] grant
// (#385): its rules merge deny > ask > allow so a user's deny always wins, and
// matching is segmented. It is read for the agent-neutral policy only (#1514).
type GrokConfig struct {
	MCPServers map[string]GrokMCP `toml:"mcp_servers"`

	// Plugins is the [plugins] table. Per xAI's settings reference a project
	// config may contribute it, and its own documentation gives the direction:
	// `enabled` is "explicitly enable plugins (useful when project plugins
	// default off)". Project plugins default to off, so a committed `enabled`
	// turns them on for everyone who opens the repository.
	Plugins *GrokPlugins `toml:"plugins"`

	// Permission is the [permission] table, checked by the agent-neutral policy.
	Permission *GrokPermission `toml:"permission"`
}

// GrokPermission is the [permission] table: the compact allow, deny and ask
// arrays, or the structured rules, which Grok ignores when any array is set.
type GrokPermission struct {
	Allow []string
	Deny  []string
	Ask   []string
	Rules []GrokPermissionRule
	// compact is whether an allow, deny or ask key is set.
	compact bool
}

// UnmarshalTOML reads the table by hand: Grok warns about an entry of the wrong
// type and goes on, and a strict decode would fail the file for every rule that
// reads the rest of it.
func (p *GrokPermission) UnmarshalTOML(v any) error {
	table, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	strs := func(key string) []string {
		list, ok := table[key].([]any)
		if !ok {
			return nil
		}
		p.compact = true
		var out []string
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	p.Allow, p.Deny, p.Ask = strs("allow"), strs("deny"), strs("ask")
	rules, _ := table["rules"].([]map[string]any)
	if list, ok := table["rules"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				rules = append(rules, m)
			}
		}
	}
	for _, m := range rules {
		field := func(key string) string {
			s, _ := m[key].(string)
			return s
		}
		p.Rules = append(p.Rules, GrokPermissionRule{Action: field("action"), Tool: field("tool"), Pattern: field("pattern"), PatternMode: field("pattern_mode")})
	}
	return nil
}

// GrokPermissionRule is one structured rule.
type GrokPermissionRule struct {
	Action, Tool, Pattern, PatternMode string
}

// grokToolNames maps the structured tool names onto the rule string spelling.
var grokToolNames = map[string]string{
	"bash": "Bash", "read": "Read", "edit": "Edit", "grep": "Grep",
	"mcp": "MCPTool", "webfetch": "WebFetch", "websearch": "WebSearch",
}

// entry spells a structured rule as a rule string, or "" for a tool Grok's
// string form has no name for.
func (r GrokPermissionRule) entry() string {
	name := grokToolNames[r.Tool]
	switch {
	case name == "":
		return ""
	case r.Pattern == "":
		return name
	case r.PatternMode == "domain":
		return name + "(domain:" + r.Pattern + ")"
	}
	return name + "(" + r.Pattern + ")"
}

// PolicyEntries returns the allow and deny rules the agent-neutral policy
// checks, in rule string spelling.
func (c *GrokConfig) PolicyEntries() (allow, deny []string) {
	p := c.Permission
	if p == nil {
		return nil, nil
	}
	if p.compact {
		return p.Allow, p.Deny
	}
	for _, r := range p.Rules {
		e := r.entry()
		switch {
		case e == "":
		case r.Action == "allow":
			allow = append(allow, e)
		case r.Action == "deny":
			deny = append(deny, e)
		}
	}
	return allow, deny
}

// GrokPlugins is the [plugins] table.
//
// Disabled is decoded and deliberately never reported: naming a plugin to
// discover but not activate is hardening, the direction that made
// exclude_slash_tmp (Codex) and disableTmpWrite (Cursor) false positives. A real
// committed config uses it exactly that way.
type GrokPlugins struct {
	// Paths are "additional directories to scan for plugins". A repo-relative
	// entry points the loader at code the repository itself ships.
	Paths []string `toml:"paths"`
	// Enabled names plugins to activate.
	Enabled []string `toml:"enabled"`
	// Disabled names plugins to discover but not activate.
	Disabled []string `toml:"disabled"`
}

// PluginPathsInsideRepo splits the plugin search paths into those that resolve
// inside the repository and those that do not, sorted. A repo-relative path is
// the sharper case: the repository supplies the plugin code as well as pointing
// the loader at it.
func (p *GrokPlugins) PluginPathsInsideRepo() (inside, outside []string) {
	if p == nil {
		return nil, nil
	}
	for _, raw := range p.Paths {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		n := strings.ReplaceAll(v, "\\", "/")
		if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "~") || strings.HasPrefix(n, "$") {
			outside = append(outside, v)
			continue
		}
		inside = append(inside, v)
	}
	sort.Strings(inside)
	sort.Strings(outside)
	return inside, outside
}

// GrokMCP is one [mcp_servers.<name>] entry. Grok uses an untagged transport
// (verified against xai-grok-config-types/src/mcp.rs): a stdio server sets
// command/args/env, a streamable-http server sets url/headers/bearer_token_env_var.
// There is NO type/transport discriminator — the transport is inferred from
// whether command or url is present — so both sets of fields live in one struct
// and whichever the TOML provides is decoded.
type GrokMCP struct {
	Command           string            `toml:"command"`
	Args              []string          `toml:"args"`
	Env               map[string]string `toml:"env"`
	URL               string            `toml:"url"`
	Headers           map[string]string `toml:"headers"`
	BearerTokenEnvVar string            `toml:"bearer_token_env_var"`

	// BearerTokenFile is an "absolute or ~/ path to a bearer token, re-read on
	// every request" (#616): Grok reads the file and sends
	// "Authorization: Bearer <contents>" to the server's url
	// (xai-grok-mcp/src/bearer_token_file.rs). A relative path fails the server
	// (mcp_bearer_token_file.rs), so the file is always one on the user's
	// machine, chosen by whoever wrote the config.
	BearerTokenFile string `toml:"bearer_token_file"`
}

// MCPServerMap converts the Grok mcp_servers tables to the shared MCPServer shape
// so the existing MCP rules (CFG010–021, CFG049–059) apply unchanged. Type is
// left empty: Grok carries no transport discriminator, and the MCP rules key on
// command/url/env/headers rather than the type string.
func (c *GrokConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCPServers))
	for name, s := range c.MCPServers {
		out[name] = MCPServer{
			Command:         s.Command,
			Args:            s.Args,
			Env:             s.Env,
			URL:             s.URL,
			Headers:         s.Headers,
			BearerTokenFile: s.BearerTokenFile,
		}
	}
	return out
}

// GrokLSPServer is one entry of .grok/lsp.json (#616), a map from server name to
// its launch config (xai-grok-tools/src/implementations/lsp/config.rs
// LspServerConfig). Only the fields that run something are modelled.
type GrokLSPServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// ParseGrokLSP reads a .grok/lsp.json. Grok decodes it with serde into a
// name → LspServerConfig map and, when that fails, logs "failed to parse
// lsp.json" and uses no servers, so a malformed file is reported as an error
// (CFG109) rather than read.
func ParseGrokLSP(path string) (map[string]GrokLSPServer, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]GrokLSPServer
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// ParseCopilotLSP reads a Copilot CLI .github/lsp.json (#648). The servers sit
// under an `lspServers` key ("Project config: .github/lsp.json" in the CLI's own
// /lsp help) and carry the same command/args/env as a Grok entry, so the Grok
// type is reused.
func ParseCopilotLSP(path string) (map[string]GrokLSPServer, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		LSPServers map[string]GrokLSPServer `json:"lspServers"`
	}
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc.LSPServers, nil
}

// ParseGrokConfig reads a .grok/config.toml. A missing key yields a zero value;
// a malformed file is an error, so a config that is silently not being scanned
// is reported rather than mistaken for empty.
func ParseGrokConfig(path string) (*GrokConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var c GrokConfig
	if _, err := toml.Decode(string(data), &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// GrokHooks is one .grok/hooks/*.json file. Grok's hook file has the same shape
// as Claude Code's — a top-level "hooks" object mapping an event name to matcher
// groups, each carrying a list of handlers — so the shared HookGroup/HookCommand
// types are reused. A handler's type is "command" (shell) or "http"; only the
// command form becomes a command site (verified against xai-grok-hooks/src/config.rs).
// There is no top-level disable switch (no disableAllHooks); Grok disables hooks
// via a separate $GROK_HOME/disabled-hooks name list and per-project trust.
type GrokHooks struct {
	Hooks map[string][]HookGroup `json:"hooks,omitempty"`
}

// ParseGrokHooks reads a .grok/hooks/*.json file. A malformed file is an error,
// so a hook file that is silently not being scanned is reported.
func ParseGrokHooks(path string) (*GrokHooks, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var h GrokHooks
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &h, nil
}
