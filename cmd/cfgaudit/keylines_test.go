// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// #927: findings in JSON files carry the line of the key they report, so the
// SARIF result has a region and GitHub can annotate the changed line.
func TestKeyLines927(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{
  "permissions": {
    "defaultMode": "bypassPermissions",
    "allow": ["Bash(*)", "WebFetch"],
    "deny": ["Read(./.env)"]
  },
  "enableAllProjectMcpServers": true,
  "hooks": {
    "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo done"}]}]
  }
}
`)
	mustWrite(t, filepath.Join(dir, ".mcp.json"), `{
  "mcpServers": {
    "browser": { "command": "npx", "args": ["-y", "@playwright/mcp@latest"] },
    "docs": { "type": "http", "url": "http://docs.example.com/mcp" }
  }
}
`)

	_, out, _ := runCLI(t, "--claude-version", "2.1.310", "--format", "sarif", "--only",
		"CFG001,CFG003,CFG004,CFG010,CFG040,CFG049,CFG067", dir)
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           *struct{ StartLine, StartColumn int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, r := range log.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		uri := loc.ArtifactLocation.URI
		key := r.RuleID + " " + uri[strings.LastIndexAny(uri, `/\`)+1:]
		if loc.Region == nil {
			got[key] = "no region"
			continue
		}
		got[key] = fmt.Sprintf("%d:%d", loc.Region.StartLine, loc.Region.StartColumn)
	}
	want := map[string]string{
		"CFG001 settings.json": "4:15", // the "Bash(*)" element
		"CFG003 settings.json": "7:3",  // the enableAllProjectMcpServers key
		"CFG004 settings.json": "3:5",  // defaultMode, named without its parent
		"CFG040 settings.json": "4:26", // the "WebFetch" element
		"CFG067 settings.json": "8:3",  // the hooks key, through Finding.Key
		"CFG010 .mcp.json":     "3:51", // the unpinned argument
		"CFG049 .mcp.json":     "4:31", // the url key holding the cleartext URL
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s at %q, want %s; all: %v", k, got[k], v, got)
		}
	}
}
