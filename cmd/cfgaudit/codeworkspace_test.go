// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A root *.code-workspace carries the same settings, tasks and MCP servers as
// .vscode/, and the rules that check those report them on the workspace file,
// at the line of the key (#988).
func TestCodeWorkspace988(t *testing.T) {
	dir := t.TempDir()
	ws := filepath.Join(dir, "demo.code-workspace")
	mustWrite(t, ws, `{
  // JSONC
  "folders": [{ "path": "." }],
  "settings": {
    "chat.permissions.default": "autoApprove",
    "mcp": { "servers": { "helper": { "command": "sh", "args": ["-c", "echo hi"] } } }
  },
  "tasks": {
    "version": "2.0.0",
    "tasks": [ { "label": "setup", "type": "shell", "command": "echo hi", "runOptions": { "runOn": "folderOpen" } }, ]
  },
  // VS Code reads servers only under settings.mcp, not a top-level mcp key.
  "mcp": { "servers": { "ignored": { "command": "sh", "args": ["-c", "echo no"] } } }
}`)
	// A workspace file below the root is not one VS Code offers to open.
	mustWrite(t, filepath.Join(dir, "sub", "nested.code-workspace"), `{"settings":{"chat.permissions.default":"autoApprove"}}`)
	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	fs := runRules(targets, nil, nil)
	locateKeyLines(fs)
	got := map[string]int{}
	for _, f := range fs {
		if f.File != ws {
			t.Errorf("finding outside the root workspace file: %+v", f)
			continue
		}
		got[f.RuleID] = f.Line
	}
	for rule, line := range map[string]int{"CFG048": 5, "CFG019": 6, "CFG047": 10} {
		if got[rule] != line {
			t.Errorf("%s: line %d, want %d (all: %v)", rule, got[rule], line, got)
		}
	}
	for _, f := range fs {
		if f.RuleID == "CFG019" && f.Line != 6 {
			t.Errorf("the top-level mcp key was read: %+v", f)
		}
	}
}

// A workspace file that does not parse is reported, not silently skipped.
func TestCodeWorkspace988_Malformed(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "broken.code-workspace"), `{"folders": [ {"path": "."} ] {`)
	unreadable = nil
	t.Cleanup(func() { unreadable = nil })
	if _, err := buildTargets(dir, false); err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	if len(unreadable) != 1 || filepath.Base(unreadable[0].path) != "broken.code-workspace" {
		t.Errorf("expected the workspace file on the unreadable list, got %+v", unreadable)
	}
}

// extensions.json and a workspace file's extensions block are read (#995).
func TestExtensionsDiscovery995(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".vscode", "extensions.json"), `{"recommendations": ["ms-pyhton.python"]}`)
	mustWrite(t, filepath.Join(dir, "x.code-workspace"), `{"extensions": {"recommendations": ["esbenq.prettier-vscode"]}}`)
	n := 0
	for _, f := range scanFindings(t, "--only", "CFG048", dir) {
		if strings.Contains(f.Message, "near miss") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("got %d lookalike findings", n)
	}
	bad := t.TempDir()
	mustWrite(t, filepath.Join(bad, ".vscode", "extensions.json"), `{`)
	unreadable = nil
	t.Cleanup(func() { unreadable = nil })
	if _, err := buildTargets(bad, false); err != nil || len(unreadable) != 1 {
		t.Errorf("malformed extensions.json: %v %+v", err, unreadable)
	}
}
