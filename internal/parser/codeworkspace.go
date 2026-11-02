// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// CodeWorkspace is a VS Code multi-root workspace file (*.code-workspace), read
// by VS Code and its forks when the workspace is opened (#988). It carries the
// same blocks as .vscode/: workspace settings under "settings", workspace tasks
// under "tasks", and MCP servers under "settings.mcp.servers". VS Code 1.116
// reads the servers from that path (getWorkspaceMcpConfigPath returns the
// section ["settings", "mcp"] for the workspace file), not from a top-level
// "mcp" key, which its workspace editor does not list as supported.
type CodeWorkspace struct {
	// Settings is nil when the file has no settings object.
	Settings *VSCodeSettings
	// Tasks is nil when the file has no tasks.
	Tasks *VSCodeTasks
	// MCPServers is nil when settings.mcp names no server.
	MCPServers map[string]MCPServer
}

// ParseCodeWorkspace reads a *.code-workspace file. Like the .vscode/ files it
// is JSON with comments and trailing commas.
func ParseCodeWorkspace(path string) (*CodeWorkspace, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	clean := stripJSONC(data)
	if len(bytes.TrimSpace(clean)) == 0 {
		return &CodeWorkspace{}, nil
	}
	var top struct {
		Settings json.RawMessage `json:"settings"`
		Tasks    json.RawMessage `json:"tasks"`
	}
	if err := json.Unmarshal(clean, &top); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	w := &CodeWorkspace{}
	if isJSONObject(top.Settings) {
		// top.Settings is a JSON object, so it parses as settings.
		s, _ := ParseVSCodeSettingsBytes(top.Settings, path)
		if len(s.Raw) > 0 {
			w.Settings = s
		}
		if raw, ok := s.RawValue("mcp"); ok && isJSONObject(raw) {
			var c MCPConfig
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("parse %s: settings.mcp: %w", path, err)
			}
			if len(c.Servers) > 0 {
				w.MCPServers = c.Servers
			}
		}
	}
	if isJSONObject(top.Tasks) {
		var t VSCodeTasks
		if err := json.Unmarshal(top.Tasks, &t); err != nil {
			return nil, fmt.Errorf("parse %s: tasks: %w", path, err)
		}
		if len(t.Tasks) > 0 {
			w.Tasks = &t
		}
	}
	return w, nil
}

// isJSONObject reports whether raw holds a JSON object.
func isJSONObject(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	return len(b) > 0 && b[0] == '{'
}
