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
		{"root home", "/root/.dev-utils/server.js"},
		{"file URL", "file:///home/user/.dev-utils/server.js"},
		{"nested", "/home/user/.dev-utils/lib/server.js"},
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

func TestCFG127_CorrelationInProjectScope(t *testing.T) {
	tg := &Target{ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"x": {
		Command: "node", Args: []string{"/home/user/.dev-utils/server.js"},
		Env: parser.EnvMap{"MCP_SERVER_NAME": "dev-utils"},
	}}}
	if got := CFG127.Check(tg); len(got) != 1 || got[0].Severity != finding.Error {
		t.Fatalf("got %+v", got)
	}
}

func TestCFG127_WeakSuspiciousPathIsInfo(t *testing.T) {
	for _, p := range []string{
		"/tmp/tools/index.py", "/var/folders/ab/T/index.py", "/dev/shm/x.mjs", "~/.cache/tool/index.py",
		"/Users/u/Library/Caches/tool/index.js", `C:\Users\u\AppData\Local\Temp\tool\index.js`, "~/.rogue/run.rb",
	} {
		for _, command := range []string{"/usr/bin/python3", "python3.12", `C:\Program Files\nodejs\node.exe`} {
			tg := &Target{
				Scope: finding.ScopeUser, ProjectMCPFile: "cursor.json",
				ProjectMCP: map[string]parser.MCPServer{"mine": {Command: command, Args: []string{p}}},
			}
			got := CFG127.Check(tg)
			if len(got) != 1 || got[0].Severity != finding.Info {
				t.Fatalf("%s %s: got %+v", command, p, got)
			}
		}
	}
}

// A matching name in a temporary folder is not the published shape.
func TestCFG127_CorrelationNeedsHiddenHomeDirectory(t *testing.T) {
	tg := &Target{ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"x": {
		Command: "node", Args: []string{"/tmp/tools/server.js"},
		Env: parser.EnvMap{"MCP_SERVER_NAME": "tools"},
	}}}
	if got := CFG127.Check(tg); len(got) != 0 {
		t.Fatalf("project scope: %+v", got)
	}
	tg.Scope = finding.ScopeUser
	if got := CFG127.Check(tg); len(got) != 1 || got[0].Severity != finding.Info {
		t.Fatalf("user scope: %+v", got)
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
		{"project tmp", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"tmp/server.js"}}}}},
		{"project cache", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"./.cache/server.js"}}}}},
		{"tmp in home", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"/home/u/tmp/server.js"}}}}},
		{"file in home", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"~/.server.js"}}}}},
		{"home only", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"/home/.x.js"}}}}},
		{"xdg config", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"~/.config/mcp/server.js"}}}}},
		{"editor", &Target{Scope: finding.ScopeUser, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "node", Args: []string{"~/.vscode/extensions/a/server.js"}}}}},
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
