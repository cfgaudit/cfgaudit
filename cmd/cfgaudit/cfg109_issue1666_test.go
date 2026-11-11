// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #1666: a VS Code task whose windows.command is an array and a .mcp.json
// server with "auth": "oauth" parse, and a .mcp.json that is not JSON is
// still CFG109.
func TestCFG109_Issue1666(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"vscode windows.command array": {".vscode/tasks.json": `{"version":"2.0.0","tasks":[{"label":"build","type":"shell","command":"make","windows":{"command":["cmd","/c","build.bat"]}}]}`},
		"vscode osx.command object":    {".vscode/tasks.json": `{"version":"2.0.0","tasks":[{"label":"build","type":"shell","command":"make","osx":{"command":{"value":"./build.sh","quoting":"escape"}}}]}`},
		"mcp auth string":              {".mcp.json": `{"mcpServers":{"remote":{"type":"http","url":"https://mcp.example.com/mcp","auth":"oauth"}}}`},
	} {
		d := t.TempDir()
		for p, c := range files {
			mustWrite(t, filepath.Join(d, p), c)
		}
		_, out, _ := runCLI(t, "--config", os.DevNull, "--claude-version", "2.1.316", "--format", "json", "--only", "CFG109", d)
		if strings.Contains(out, `"RuleID": "CFG109"`) {
			t.Errorf("%s: want no CFG109, got %s", name, out)
		}
	}

	d := t.TempDir()
	mustWrite(t, filepath.Join(d, ".mcp.json"), `{"mcpServers":{"remote":{"url":"https://mcp.example.com/mcp","auth":"oauth"}`)
	_, out, _ := runCLI(t, "--config", os.DevNull, "--claude-version", "2.1.316", "--format", "json", "--only", "CFG109", d)
	if !strings.Contains(out, `"RuleID": "CFG109"`) || !strings.Contains(out, `"Severity": "error"`) {
		t.Errorf("a .mcp.json that is not JSON: want CFG109 error, got %s", out)
	}
}
