// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #1412: a folder under .claude/skills named with --plugins is a plain skill
// when its plugin manifest is absent: no CFG109 and no exit 2, inside and
// outside the scan root. A present but malformed manifest stays CFG109.
func TestCFG109_Issue1412(t *testing.T) {
	const skill = "---\nname: demo\ndescription: Demo skill.\n---\n\nBody.\n"
	for name, manifest := range map[string]string{
		"absent":    "",
		"malformed": `{"name":`,
		"valid":     `{"name":"demo","version":"1.0.0"}`,
	} {
		t.Run(name+" inside", func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, ".claude", "skills", "demo", "SKILL.md"), skill)
			if manifest != "" {
				mustWrite(t, filepath.Join(dir, ".claude", "skills", "demo", ".claude-plugin", "plugin.json"), manifest)
			}
			code, out, _ := runCLI(t, "--config", os.DevNull, "--claude-version", "2.1.316", "--format", "json", "--only", "CFG109", "--plugins", filepath.Join(dir, ".claude", "skills", "demo"), dir)
			if code == 2 {
				t.Errorf("%s: want no parse error, got exit 2, %s", name, out)
			}
			if name == "malformed" {
				if !strings.Contains(out, `"RuleID": "CFG109"`) {
					t.Errorf("malformed: want CFG109, got %s", out)
				}
				return
			}
			if strings.Contains(out, `"RuleID": "CFG109"`) || strings.Contains(out, "plugin.json") {
				t.Errorf("%s: want no CFG109, got %s", name, out)
			}
		})
	}

	// Outside the scan root the same absent-manifest skill gives no finding.
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, ".claude", "skills", "demo", "SKILL.md"), skill)
	scan := t.TempDir()
	code, out, _ := runCLI(t, "--config", os.DevNull, "--claude-version", "2.1.316", "--format", "json", "--only", "CFG109", "--plugins", filepath.Join(outside, ".claude", "skills", "demo"), scan)
	if code == 2 || strings.Contains(out, `"RuleID": "CFG109"`) {
		t.Errorf("outside: want no finding and no exit 2, got %d, %s", code, out)
	}
}
