package parser

import (
	"encoding/json"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// CursorCLIConfig is a project .cursor/cli.json (#649). Cursor's CLI reference:
// "Permissions are set in ~/.cursor/cli-config.json (global) or
// <project>/.cursor/cli.json (project-specific)", and "Only permissions can be
// configured at the project level". Entries are permission tokens such as
// Shell(git), Mcp(server:tool), Read(...), Write(...); deny takes precedence
// over allow.
type CursorCLIConfig struct {
	Permissions *Permissions `json:"permissions,omitempty"`
}

// ParseCursorCLIConfig reads a .cursor/cli.json.
func ParseCursorCLIConfig(path string) (*CursorCLIConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c CursorCLIConfig
	if err := json.Unmarshal(stripJSONC(data), &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
