// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG124_FullAgentMCPForms(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		mode    string
	}{
		{"codex", []string{"mcp-server"}, "codex mcp-server"},
		{"codex", []string{"-c", "x=1", "app-server"}, "codex app-server"},
		{"npx", []string{"-y", "@openai/codex", "app-server"}, "codex app-server"},
		{"claude", []string{"--debug", "mcp", "serve"}, "claude mcp serve"},
		{"npx", []string{"-y", "@anthropic-ai/claude-code", "mcp", "serve"}, "claude mcp serve"},
	}
	for _, tt := range tests {
		target := &Target{ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"agent": {Command: tt.command, Args: tt.args}}}
		f := CFG124.Check(target)
		if len(f) != 1 || !strings.Contains(f[0].Message, tt.mode) {
			t.Errorf("%s %v: expected %s, got %+v", tt.command, tt.args, tt.mode, f)
		}
	}
}

func TestCFG124_FullAgentMCPNegatives(t *testing.T) {
	for _, server := range []parser.MCPServer{
		{Command: "claude", Args: []string{"mcp", "list"}},
		{Command: "node", Args: []string{"server.js", "codex", "app-server"}},
		{Command: "npx", Args: []string{"-y", "unrelated", "mcp", "serve"}},
		{Command: "codex", Args: []string{"-c", "app-server", "mcp", "list"}},
		{Command: "claude", Args: []string{"--model", "mcp", "serve"}},
	} {
		target := &Target{ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"safe": server}}
		if f := CFG124.Check(target); len(f) != 0 {
			t.Errorf("%+v: expected no finding, got %+v", server, f)
		}
	}
}
