// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// .vscode/mcp.json is JSON with comments for VS Code (#829); .mcp.json is not
// for Claude Code.
func TestParseMCPConfig_VSCodeJSONC(t *testing.T) {
	dir := t.TempDir()
	body := "{\n  // GitLab MCP server\n  \"servers\": {\"gitlab\": {\"command\": \"npx\", \"args\": [\"-y\", \"x\"],},},\n}\n"
	vs := filepath.Join(dir, ".vscode", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(vs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vs, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ParseMCPConfig(vs)
	if err != nil || c.MCPServers["gitlab"].Command != "npx" {
		t.Fatalf(".vscode/mcp.json with comments: got %+v, %v", c, err)
	}
	root := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(root, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMCPConfig(root); err == nil {
		t.Error(".mcp.json with comments should still fail to parse")
	}
}
