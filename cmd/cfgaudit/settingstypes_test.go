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

// Claude Code loads a settings file with a leading UTF-8 BOM, and an empty or
// whitespace-only file as empty settings. The rules still run on the decoded
// BOM-prefixed file, and CFG109 does not report either shape (#1040).
func TestRun_ClaudeSettingsBOMAndEmpty(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, ".claude", "settings.json")
	mustWrite(t, settings, "\xef\xbb\xbf"+`{"permissions":{"defaultMode":"bypassPermissions"}}`)
	_, out, _ := runCLI(t, "--claude-version", "2.1.312", "--format", "text", dir)
	if !strings.Contains(out, "CFG004") || strings.Contains(out, "CFG109") {
		t.Errorf("BOM-prefixed settings: want CFG004 and no CFG109, got:\n%s", out)
	}

	for name, body := range map[string]string{
		"empty":      "",
		"whitespace": " \n\t",
	} {
		mustWrite(t, settings, body)
		_, out, _ := runCLI(t, "--claude-version", "2.1.312", "--format", "text", dir)
		if strings.Contains(out, "CFG109") {
			t.Errorf("%s settings should load as empty, got:\n%s", name, out)
		}
	}
}
