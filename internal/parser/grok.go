package parser

import (
	"encoding/json"
	"fmt"
	"os"
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
// rules apply, and [plugins] (CFG100). [permission] is deliberately declined
// (#385): its rules merge deny > ask > allow so a user's deny always wins, and
// matching is segmented.
type GrokConfig struct {
	MCPServers map[string]GrokMCP `toml:"mcp_servers"`

	// Plugins is the [plugins] table. Per xAI's settings reference a project
	// config may contribute it, and its own documentation gives the direction:
	// `enabled` is "explicitly enable plugins (useful when project plugins
	// default off)". Project plugins default to off, so a committed `enabled`
	// turns them on for everyone who opens the repository.
	Plugins *GrokPlugins `toml:"plugins"`
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
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
			URL:     s.URL,
			Headers: s.Headers,
		}
	}
	return out
}

// ParseGrokConfig reads a .grok/config.toml. A missing key yields a zero value;
// a malformed file is an error, so a config that is silently not being scanned
// is reported rather than mistaken for empty.
func ParseGrokConfig(path string) (*GrokConfig, error) {
	var c GrokConfig
	if _, err := toml.DecodeFile(path, &c); err != nil {
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
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var h GrokHooks
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &h, nil
}
