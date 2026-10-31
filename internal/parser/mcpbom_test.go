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
