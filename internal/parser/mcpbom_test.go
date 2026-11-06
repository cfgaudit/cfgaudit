// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// Only the repository-root .mcp.json accepts a leading BOM; a plugin's
// .mcp.json, read through ParseMCPConfig, stays strict (#1092).
func TestParseProjectMCPConfig_BOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcp.json")
	if err := os.WriteFile(path, []byte("\xef\xbb\xbf"+`{"mcpServers":{"a":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseProjectMCPConfig(path)
	if err != nil || cfg.MCPServers["a"].Command != "x" {
		t.Errorf("ParseProjectMCPConfig = %+v, %v; want server a", cfg, err)
	}
	if _, err := ParseMCPConfig(path); err == nil {
		t.Error("ParseMCPConfig accepted a BOM; plugin and other MCP files must stay strict")
	}
	if _, err := ParseProjectMCPConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("ParseProjectMCPConfig: want an error for a missing file")
	}
}

// What Cursor 3.29.9 does with .cursor/mcp.json, from its loader (#1189):
// comments and trailing commas load, a byte-order mark and an empty file do not.
func TestParseMCPConfig_Cursor(t *testing.T) {
	const server = `"mcpServers": {"s": {"command": "node"}}`
	for name, c := range map[string]struct {
		content string
		ok      bool
	}{
		"plain":          {"{" + server + "}", true},
		"line comment":   {"// note\n{" + server + "}", true},
		"block comment":  {"/* note */{" + server + "}", true},
		"trailing comma": {"{" + server + ",}", true},
		"bom":            {"\uFEFF{" + server + "}", false},
		"empty":          {"", false},
		"only comment":   {"// note\n", false},
		"missing comma":  {`{"a": 1 "b": 2}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".cursor", "mcp.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := ParseMCPConfig(path)
			if c.ok && (err != nil || len(cfg.MCPServers) != 1) {
				t.Errorf("cfg %+v, err %v", cfg, err)
			}
			if !c.ok && err == nil {
				t.Errorf("parsed: %+v", cfg)
			}
		})
	}
}

// The same comment in a file with the same name elsewhere stays an error.
func TestParseMCPConfig_CommentsOnlyInCursorsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte("// note\n{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMCPConfig(path); err == nil {
		t.Error("a comment was accepted outside .cursor")
	}
}
