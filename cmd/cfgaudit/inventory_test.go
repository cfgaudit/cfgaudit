// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/rules"
)

func inventoryRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"cfgaudit", "inventory"}, args...), nil, &out, &errb)
	return code, out.String(), errb.String()
}

// The inventory lists the files per agent and what they run, in text, JSON
// and CycloneDX (#1000).
func TestInventory1000(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(git status)"]},"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"./scripts/fmt.sh"}]}]}}`)
	mustWrite(t, filepath.Join(dir, "scripts", "fmt.sh"), "#!/bin/sh\ngofmt -w .\n")
	mustWrite(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{"docs":{"command":"npx","args":["-y","docs-mcp@1.2.3"]},"loose":{"command":"uvx","args":["srv"]},"remote":{"url":"https://mcp.example.com/mcp"},"local":{"command":"node","args":["s.js"]}}}`)
	mustWrite(t, filepath.Join(dir, "AGENTS.md"), "# p\n")
	mustWrite(t, filepath.Join(dir, ".cursor", "mcp.json"), `{`)

	code, text, _ := inventoryRun(t, dir)
	for _, want := range []string{
		"Claude Code\n  .claude/settings.json\n    command hooks.PostToolUse command: ./scripts/fmt.sh",
		"setting permissions.allow: Bash(git status)",
		"MCP server docs (stdio): npx -y docs-mcp@1.2.3, pinned: yes",
		"MCP server loose (stdio): uvx srv, pinned: no",
		"MCP server local (stdio): node s.js\n",
		"MCP server remote (http): https://mcp.example.com/mcp",
		"shared\n  AGENTS.md",
		"script started by the hooks.PostToolUse command: sha256 ",
		"Not read\n  .cursor/mcp.json:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if code != 0 {
		t.Errorf("code %d", code)
	}

	_, js, _ := inventoryRun(t, "--format", "json", dir)
	var inv inventory
	if err := json.Unmarshal([]byte(js), &inv); err != nil || len(inv.Agents) != 3 || len(inv.Unreadable) != 1 {
		t.Errorf("json: %v %+v", err, inv)
	}

	_, cdx, _ := inventoryRun(t, "--format", "cyclonedx", dir)
	var bom cdxBOM
	if err := json.Unmarshal([]byte(cdx), &bom); err != nil || bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Fatalf("cyclonedx: %v %s", err, cdx)
	}
	var mcp, files int
	for _, c := range bom.Components {
		if c.Type == "file" && len(c.Hashes) == 1 {
			files++
		}
		mcp += len(c.Components)
	}
	if files < 4 || mcp != 4 {
		t.Errorf("files %d, mcp %d", files, mcp)
	}
	if _, again, _ := inventoryRun(t, "--format", "cyclonedx", dir); again != cdx {
		t.Error("the BOM is not deterministic")
	}
}

func TestInventory1000_Edges(t *testing.T) {
	if code, out, _ := inventoryRun(t, t.TempDir()); code != 0 || !strings.Contains(out, "no agent configuration found") {
		t.Errorf("empty: %d %s", code, out)
	}
	if _, cdx, _ := inventoryRun(t, "--format", "cyclonedx", t.TempDir()); !strings.Contains(cdx, `"components": []`) {
		t.Errorf("empty BOM: %s", cdx)
	}
	for _, args := range [][]string{{"--format", "xml"}, {"a", "b"}, {"--bogus"}, {filepath.Join(t.TempDir(), "missing")}} {
		if code, _, _ := inventoryRun(t, args...); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
	if code, _, _ := inventoryRun(t, "-h"); code != 0 {
		t.Errorf("-h: code %d", code)
	}
	for rel, want := range map[string]string{
		"x.code-workspace": "vscode", ".github/copilot-instructions.md": "copilot", ".claude/agents/a.md": "claude-code",
		".gitmodules": "git", "skills/x/SKILL.md": "shared", ".roomodes": "roo-code",
	} {
		if got := agentOfPath(rel); got != want {
			t.Errorf("%s: %s, want %s", rel, got, want)
		}
	}
}

// Branches of buildInventory: a content-paths target is not listed, entries
// and MCP servers in a file that does not exist are dropped, and a path that
// exists but cannot be read is listed as not read (#1323).
func TestInventoryBranches1323(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	targets := []*rules.Target{
		{ContentPath: true, InstructionFile: filepath.Join(dir, "README.md")},
		{SettingsFile: missing, Settings: &parser.Settings{Permissions: &parser.Permissions{Allow: []string{"Bash(ls)"}}}},
		{ProjectMCPFile: missing, ProjectMCP: map[string]parser.MCPServer{"x": {Command: "npx", Args: []string{"y"}}}},
	}
	if inv := buildInventory(dir, targets, nil); len(inv.Agents) != 0 {
		t.Errorf("got %+v", inv.Agents)
	}

	root := runFixture(t, map[string]string{
		".claude/settings.json":     errorSettings,
		".claude/skills/x/SKILL.md": "---\nname: x\ndescription: y\n---\nhi\n",
	})
	lockPath(t, filepath.Join(root, ".claude", "skills"))
	_, out, _ := inventoryRun(t, root)
	if !strings.Contains(out, "Not read\n  .claude/skills: exists but could not be read") {
		t.Errorf("unreadable path missing:\n%s", out)
	}
}
