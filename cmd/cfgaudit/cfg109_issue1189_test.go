// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// #1189: a dangling symlink goes to the could-not-read list, an empty VS Code
// settings file, an array task command and a numeric MCP env value parse, and
// real syntax errors stay CFG109.
func TestCFG109_Issue1189(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude-plugin", "plugin.json"), `{"name":"p","version":"1.0.0"}`)
	if err := os.MkdirAll(filepath.Join(dir, "skills", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../packages/x/SKILL.md", filepath.Join(dir, "skills", "x", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, ".vscode", "settings.json"), "  \n")
	mustWrite(t, filepath.Join(dir, ".vscode", "tasks.json"), `{"version":"2.0.0","tasks":[{"label":"make executable","command":["chmod","+x","scripts/run.sh"]}]}`)
	mustWrite(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{"my-server":{"command":"npx","args":["-y","my-server"],"env":{"MAX_TOKENS":64000,"DEBUG":true}}}}`)
	code, out, errOut := runCLI(t, "--config", "/dev/null", "--claude-version", "2.1.316", "--format", "json", "--plugins", dir, dir)
	if strings.Contains(out, `"RuleID": "CFG109"`) {
		t.Errorf("want no CFG109, got %s", out)
	}
	if !strings.Contains(out, `"RuleID": "CFG010"`) || !strings.Contains(out, "my-server") {
		t.Errorf("want CFG010 on the unpinned my-server, got %s", out)
	}
	if code != 2 || !strings.Contains(errOut, "could not read") || !strings.Contains(errOut, "SKILL.md") {
		t.Errorf("want exit 2 with the dangling SKILL.md on the could-not-read list, got %d, %s", code, errOut)
	}

	for name, files := range map[string]map[string]string{
		"settings comments": {".claude/settings.json": "{\n  // c\n  \"x\": 1\n}"},
		"vscode comma":      {".vscode/settings.json": `{"a": 1 "b": 2}`},
		"mcp env object":    {".mcp.json": `{"mcpServers":{"m":{"command":"npx","env":{"A":{"b":1}}}}}`},
	} {
		d := t.TempDir()
		for p, c := range files {
			mustWrite(t, filepath.Join(d, p), c)
		}
		_, out, _ := runCLI(t, "--config", "/dev/null", "--claude-version", "2.1.316", "--format", "json", "--only", "CFG109", d)
		if !strings.Contains(out, `"RuleID": "CFG109"`) {
			t.Errorf("%s: want CFG109, got %s", name, out)
		}
	}
}
