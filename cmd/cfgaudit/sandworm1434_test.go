// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/rules"
)

// #1434: --user discovers every JSON MCP file targeted by SANDWORM_MODE. The
// three Claude Desktop paths are enumerated on every host so the test remains
// hermetic and protects cross-platform discovery from a Linux CI runner.
func TestBuildTargets_UserSandwormMCPFiles(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	files := []string{
		filepath.Join(".cursor", "mcp.json"),
		filepath.Join(".windsurf", "mcp.json"),
		filepath.Join(".continue", "config.json"),
		filepath.Join(".config", "Claude", "claude_desktop_config.json"),
		filepath.Join("Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join("AppData", "Roaming", "Claude", "claude_desktop_config.json"),
	}
	for i, rel := range files {
		name := "server" + string(rune('a'+i))
		mustWrite(t, filepath.Join(home, rel), `{"mcpServers":{"`+name+`":{"command":"node","args":["/home/user/.`+name+`/server.js"],"env":{"MCP_SERVER_NAME":"`+name+`"}}}}`)
	}

	targets, err := buildTargets(t.TempDir(), true)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	found := map[string]bool{}
	for _, target := range targets {
		if target.Scope != finding.ScopeUser || target.ProjectMCPFile == "" {
			continue
		}
		findings := rules.CFG127.Check(target)
		if len(findings) != 1 || findings[0].Severity != finding.Error {
			t.Fatalf("%s: got %+v", target.ProjectMCPFile, findings)
		}
		found[target.ProjectMCPFile] = true
	}
	for _, rel := range files {
		path := filepath.Join(home, rel)
		if !found[path] {
			t.Errorf("did not discover %s", path)
		}
	}
}

func TestBuildTargets_UserSandwormMCPFilesRequireUserFlag(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	mustWrite(t, filepath.Join(home, ".windsurf", "mcp.json"), `{"mcpServers":{"x":{"command":"node","args":["~/.x/server.js"]}}}`)
	targets, err := buildTargets(t.TempDir(), false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	for _, target := range targets {
		if target.ProjectMCPFile == filepath.Join(home, ".windsurf", "mcp.json") {
			t.Fatal("user-global MCP config discovered without --user")
		}
	}
}
