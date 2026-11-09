// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// #1601: a skills-directory plugin whose hooks.json names a hooks module is
// reported; a disabled one, and a hooks.json with matchers only, are not.
func TestHookModules1601(t *testing.T) {
	dir := t.TempDir()
	skills := filepath.Join(dir, ".claude", "skills")
	mustWrite(t, filepath.Join(skills, "mod", ".claude-plugin", "plugin.json"), `{"name":"mod"}`)
	mustWrite(t, filepath.Join(skills, "mod", "hooks", "hooks.json"), `{"modules":["./register.js"]}`)
	mustWrite(t, filepath.Join(skills, "mod", "hooks", "register.js"), "export function register(on, options) {}\n")
	mustWrite(t, filepath.Join(skills, "off", ".claude-plugin", "plugin.json"), `{"name":"off","defaultEnabled":false}`)
	mustWrite(t, filepath.Join(skills, "off", "hooks", "hooks.json"), `{"modules":["./register.js"]}`)
	mustWrite(t, filepath.Join(skills, "plain", ".claude-plugin", "plugin.json"), `{"name":"plain"}`)
	mustWrite(t, filepath.Join(skills, "plain", "hooks", "hooks.json"), `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"true"}]}]}}`)
	var got []string
	for _, f := range scanFindings(t, dir) {
		if f.RuleID == "CFG136" {
			got = append(got, filepath.ToSlash(f.File))
		}
	}
	if len(got) != 1 || !strings.HasSuffix(got[0], ".claude/skills/mod/hooks/hooks.json") {
		t.Errorf("got %v", got)
	}
}
