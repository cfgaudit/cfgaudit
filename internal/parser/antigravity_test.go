// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeAG(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// #1057: Antigravity's mcp_config.json and hooks.json.
func TestParseAntigravityMCP(t *testing.T) {
	servers, err := ParseAntigravityMCP(writeAG(t, `{
	  // a comment
	  "mcpServers": {
	    "a": {"serverUrl": "https://a.example/mcp"},
	    "b": {"url": "https://b.example/mcp", "serverUrl": "https://ignored.example"},
	    "c": {"command": "node"},
	    "d": {"command": 1}
	  }
	}`))
	if err != nil || servers["a"].URL != "https://a.example/mcp" || servers["b"].URL != "https://b.example/mcp" || servers["c"].Command != "node" || len(servers) != 3 {
		t.Fatalf("%v %v", servers, err)
	}
	if _, err := ParseAntigravityMCP(writeAG(t, `{`)); err == nil {
		t.Error("broken file parsed")
	}
	if _, err := ParseAntigravityMCP(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing file parsed")
	}
}

func TestParseAntigravityHooks(t *testing.T) {
	h, err := ParseAntigravityHooks(writeAG(t, `{
	  "b": {"SessionStart": [{"command": "echo start"}], "PreToolUse": [{"matcher": "run_command", "hooks": [{"command": "./check.sh"}]}]},
	  "a": {"enabled": false, "Stop": [{"command": "echo off"}]},
	  "c": {"enabled": true, "PostToolUse": {"bad": 1}, "Stop": "bad"},
	  "d": 3
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Hooks) != 2 || h.Hooks["SessionStart"][0].Command != "echo start" || h.Hooks["PreToolUse"][0].Matcher != "run_command" || h.Hooks["Stop"] != nil {
		t.Errorf("%+v", h.Hooks)
	}
	if _, err := ParseAntigravityHooks(writeAG(t, `[]`)); err == nil {
		t.Error("wrong shape parsed")
	}
	if _, err := ParseAntigravityHooks(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing file parsed")
	}
}
