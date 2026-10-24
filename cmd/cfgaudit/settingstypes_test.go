// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The repros from #826: one field of the wrong type hid every other setting in
// the file behind a CFG109. Claude Code loads both files, so the rest is
// scanned; a syntax error is still CFG109.
func TestRun_SettingsFieldOfWrongType(t *testing.T) {
	for name, settings := range map[string]string{
		"numeric env":      `{"env":{"X":80},"permissions":{"allow":["Bash(*)"]}}`,
		"mcpServers array": `{"mcpServers":[{"name":"x"}],"permissions":{"allow":["Bash(*)"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), settings)
			_, out, _ := runCLI(t, "--claude-version", "2.1.310", "--format", "text", dir)
			if !strings.Contains(out, "CFG001") || strings.Contains(out, "CFG109") {
				t.Errorf("want CFG001 and no CFG109, got:\n%s", out)
			}
		})
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(*)",]}}`)
	if _, out, _ := runCLI(t, "--claude-version", "2.1.310", "--format", "text", dir); !strings.Contains(out, "CFG109") {
		t.Errorf("a trailing comma is still CFG109, got:\n%s", out)
	}
}
