// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// CFG013 runs once per project, also when .claude/settings.local.json is the
// repository's only Claude file and no project target exists (#1632).
func TestCFG013LocalSettingsOnly1632(t *testing.T) {
	const local = `{"permissions":{"allow":["Read"]}}`
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"only settings.local.json, no .gitignore", map[string]string{".claude/settings.local.json": local}, 1},
		{"only settings.local.json, .gitignore without it", map[string]string{
			".claude/settings.local.json": local, ".gitignore": "node_modules/\n"}, 1},
		{"only settings.local.json, covered by .gitignore", map[string]string{
			".claude/settings.local.json": local, ".gitignore": ".claude/settings.local.json\n"}, 0},
		{"settings.local.json and CLAUDE.local.md", map[string]string{
			".claude/settings.local.json": local, "CLAUDE.local.md": "# mine\n"}, 2},
		{"settings.json and settings.local.json", map[string]string{
			".claude/settings.local.json": local, ".claude/settings.json": `{}`}, 1},
		{"settings.local.json and an unwrapped .mcp.json", map[string]string{
			".claude/settings.local.json": local, ".mcp.json": `{"x":{"command":"node","args":["s.js"]}}`}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, body := range c.files {
				mustWrite(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
			}
			fs := scanFindings(t, "--only", "CFG013", dir)
			if len(fs) != c.want {
				t.Fatalf("got %d CFG013 findings, want %d: %+v", len(fs), c.want, fs)
			}
			for _, f := range fs {
				if f.Severity != finding.Warn {
					t.Errorf("severity %s, want warn: %+v", f.Severity, f)
				}
			}
		})
	}
}
