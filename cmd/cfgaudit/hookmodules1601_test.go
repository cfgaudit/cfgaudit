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
			got = append(got, filepath.ToSlash(f.File)+" "+string(f.Severity))
		}
	}
	if len(got) != 1 || !strings.HasSuffix(got[0], ".claude/skills/mod/hooks/hooks.json warn") {
		t.Errorf("got %v", got)
	}
}

// A plugin package scanned with --plugins lists its module at info: it loads
// only once someone installs it.
func TestHookModulesPackage1601(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "pkg")
	mustWrite(t, filepath.Join(pkg, ".claude-plugin", "plugin.json"), `{"name":"pkg"}`)
	mustWrite(t, filepath.Join(pkg, "hooks", "hooks.json"), `{"modules":["./register.ts"]}`)
	var got []string
	for _, f := range scanFindings(t, "--plugins", pkg, dir) {
		if f.RuleID == "CFG136" {
			got = append(got, string(f.Severity))
		}
	}
	if len(got) != 1 || got[0] != "info" {
		t.Errorf("got %v", got)
	}
}

// A skills-directory plugin inside a repository that is itself a plugin
// package is still the auto-loading kind.
func TestHookModulesNestedSkillsDir1601(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude-plugin", "plugin.json"), `{"name":"repo"}`)
	sk := filepath.Join(dir, ".claude", "skills", "inner")
	mustWrite(t, filepath.Join(sk, ".claude-plugin", "plugin.json"), `{"name":"inner"}`)
	mustWrite(t, filepath.Join(sk, "hooks", "hooks.json"), `{"modules":["./register.ts"]}`)
	var got []string
	for _, f := range scanFindings(t, dir) {
		if f.RuleID == "CFG136" {
			got = append(got, string(f.Severity))
		}
	}
	if len(got) != 1 || got[0] != "warn" {
		t.Errorf("got %v", got)
	}
}
