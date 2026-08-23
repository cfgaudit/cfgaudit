package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// DevinConfig is the subset of Devin CLI's project config that cfgaudit reads.
// It backs all four project files: .devin/config.json ("Project settings
// (committed)"), .devin/config.local.json ("Project local overrides
// (gitignored)"), .devin/mcp_config.json ("Project MCP servers (committed)") and
// .devin/mcp_config.local.json ("Project local MCP servers (gitignored)"). The
// committed pair is described by Devin's own docs as "shared team configuration
// committed to version control", so it is a committable surface; the gitignored
// pair is read because a committed one still applies, and wins.
//
// Only permissions, read_config_from and hooks are honoured in a *project*
// config, and mcpServers is set at both levels but lives in the dedicated
// mcp_config.json files since v3000.3 ("the Local 3.6 release"). The key is
// still decoded here: older versions read servers from the main config, and
// newer ones migrate such entries on startup, so both locations are real. The
// security-relevant keys are modelled and read_config_from is not. read_config_from is deliberately not one of them: its eight keys all
// default to true when absent, so the only thing a committed value can do is
// NARROW which other tools' files are imported. It grants a repository no
// capability it could not get by writing this file directly. What it does affect
// is documented in the README's Devin section, because it means a repository
// with no .devin/ directory can still reach a Devin session through the Claude,
// Cursor, Windsurf, Copilot, VS Code and Zed files cfgaudit already scans (#474). Keys such as `sandbox` are deliberately absent: Devin documents them as
// user-only, so reading them from a project file would invent a finding on
// configuration the CLI ignores.
type DevinConfig struct {
	MCPServers  map[string]MCPServer   `json:"mcpServers,omitempty"`
	Hooks       map[string][]HookGroup `json:"hooks,omitempty"`
	Permissions *Permissions           `json:"permissions,omitempty"`
}

// ParseDevinConfig reads a .devin/config.json. A missing key yields a zero value
// rather than an error; a malformed file is an error, so a config that is
// silently not being scanned is reported rather than mistaken for an empty one.
//
// Devin spells the remote-transport discriminator `transport` where the rest of
// the MCP ecosystem uses `type`, and it is frequently omitted and inferred from
// whether a url or a command is present. It is folded into Type here so the
// shared MCP rules see one field, and nothing downstream has to know the
// difference.
func ParseDevinConfig(path string) (*DevinConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c DevinConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for name, srv := range c.MCPServers {
		if srv.Type == "" && srv.Transport != "" {
			srv.Type = srv.Transport
			c.MCPServers[name] = srv
		}
	}
	return &c, nil
}
