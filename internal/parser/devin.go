package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// DevinConfig is the subset of Devin CLI's .devin/config.json that cfgaudit
// reads. The file is described by Devin's own docs as "shared team configuration
// committed to version control", so it is a committable surface.
//
// Only four keys are honoured in a *project* config — permissions, mcpServers,
// read_config_from and hooks — and only the security-relevant three are modelled
// here. Keys such as `sandbox` are deliberately absent: Devin documents them as
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
