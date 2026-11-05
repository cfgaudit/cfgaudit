// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG127_SandwormPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"linux", "/home/user/.dev-utils/server.js"},
		{"macOS", "/Users/user/.dev-utils/server.js"},
		{"Windows", `C:\Users\user\.dev-utils\server.js`},
		{"home expansion", "~/.dev-utils/server.js"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tg := &Target{
				Scope:          finding.ScopeUser,
				ProjectMCPFile: "user-mcp.json",
				ProjectMCP: map[string]parser.MCPServer{"dev-utils": {
					Command: "node", Args: []string{tt.path},
					Env: parser.EnvMap{"MCP_SERVER_NAME": "dev-utils"},
				}},
			}
			got := CFG127.Check(tg)
			if len(got) != 1 || got[0].Severity != finding.Error || got[0].File != "user-mcp.json" || got[0].Key != "mcpServers.dev-utils" {
				t.Fatalf("got %+v", got)
			}
			if !strings.Contains(got[0].Message, "SANDWORM_MODE") {
				t.Errorf("message = %q", got[0].Message)
			}
		})
	}
}

func TestCFG127_WeakSuspiciousPathIsInfo(t *testing.T) {
	tg := &Target{
		Scope: finding.ScopeUser, ProjectMCPFile: "cursor.json",
		ProjectMCP: map[string]parser.MCPServer{"mine": {
			Command: "/usr/bin/python3", Args: []string{"/tmp/tools/index.py"},
		}},
	}
	got := CFG127.Check(tg)
	if len(got) != 1 || got[0].Severity != finding.Info {
		t.Fatalf("got %+v", got)
	}
}

func TestCFG127_Negatives(t *testing.T) {
	tests := []struct {
		name string
		tg   *Target
	}{
		{"nil", nil},
		{"project scope", &Target{Scope: finding.ScopeProject, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"~/.x/server.js"}}}}},
		{"bare runtime", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"server.js"}}}}},
		{"package runner", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "npx", Args: []string{"-y", "pkg@1.0.0"}}}}},
		{"normal absolute", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"/opt/mcp/server.js"}}}}},
		{"reviewed npm", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"/home/u/.npm/_npx/a/node_modules/pkg/server.js"}}}}},
		{"agent install", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"/home/u/.cursor/extensions/server.js"}}}}},
		{"not script", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"/home/u/.rogue/data.json"}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CFG127.Check(tt.tg); len(got) != 0 {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
