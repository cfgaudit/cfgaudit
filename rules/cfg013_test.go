// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// projectTarget creates a ScopeProject Target rooted at dir.
func projectTarget(dir string) *Target {
	return &Target{
		SettingsFile: filepath.Join(dir, ".claude", "settings.json"),
		ProjectDir:   dir,
		Scope:        finding.ScopeProject,
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCFG013_NoLocalFiles_NoFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 0 {
		t.Errorf("expected no finding when no local files exist, got %d: %+v", len(f), f)
	}
}

func TestCFG013_LocalSettingsLocal_NotIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, ".claude/settings.local.json") {
		t.Errorf("message should name the file, got: %s", f[0].Message)
	}
}

func TestCFG013_BothLocalFiles_TwoIndependentFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "personal notes")
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (one per local file), got %d", len(f))
	}
}

func TestCFG013_NoGitignoreAtAll(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "personal notes")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when .gitignore is absent, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "CLAUDE.local.md") {
		t.Errorf("message should mention CLAUDE.local.md, got: %s", f[0].Message)
	}
}

func TestCFG013_GitignoreLiteralPath_NoFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), ".claude/settings.local.json\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 0 {
		t.Errorf("expected no finding when literal path is in .gitignore, got: %+v", f)
	}
}

func TestCFG013_GitignoreWildcardPatterns_NoFinding(t *testing.T) {
	cases := map[string]string{
		"trailing-wildcard":      ".claude/settings.local.*",
		"mid-segment-wildcard":   ".claude/*.local.*",
		"basename-wildcard":      "*.local.json",
		"basename-prefix-suffix": "settings.local.*",
	}
	for name, pattern := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
			writeFile(t, filepath.Join(dir, ".gitignore"), pattern+"\n")
			f := CFG013.Check(projectTarget(dir))
			if len(f) != 0 {
				t.Errorf("pattern %q should cover .claude/settings.local.json, got %d findings: %+v",
					pattern, len(f), f)
			}
		})
	}
}

func TestCFG013_GitignoreCoversClaudeLocalMd(t *testing.T) {
	cases := map[string]string{
		"literal":           "CLAUDE.local.md",
		"basename-wildcard": "*.local.md",
		"prefix-wildcard":   "CLAUDE.local.*",
	}
	for name, pattern := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "x")
			writeFile(t, filepath.Join(dir, ".gitignore"), pattern+"\n")
			f := CFG013.Check(projectTarget(dir))
			if len(f) != 0 {
				t.Errorf("pattern %q should cover CLAUDE.local.md, got %d findings: %+v",
					pattern, len(f), f)
			}
		})
	}
}

func TestCFG013_GitignoreNegation_RefiresFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.local.json\n!.claude/settings.local.json\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 1 {
		t.Fatalf("expected negation to override the ignore, got %d findings", len(f))
	}
}

func TestCFG013_OnlyFiresOnProjectScope(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "x")
	// ProjectLocal: must not fire (avoids double emission when both settings files exist).
	tgt := projectTarget(dir)
	tgt.Scope = finding.ScopeProjectLocal
	if f := CFG013.Check(tgt); len(f) != 0 {
		t.Errorf("CFG013 should not fire on ScopeProjectLocal, got %+v", f)
	}
	// User: must not fire (no project dir concept).
	tgt.Scope = finding.ScopeUser
	if f := CFG013.Check(tgt); len(f) != 0 {
		t.Errorf("CFG013 should not fire on ScopeUser, got %+v", f)
	}
}

func TestCFG013_NoProjectDir_NoFinding(t *testing.T) {
	if f := CFG013.Check(&Target{Scope: finding.ScopeProject}); len(f) != 0 {
		t.Errorf("expected no finding when ProjectDir is empty, got %+v", f)
	}
}

// writeIndex writes a version 2 git index under dir/.git that tracks paths.
func writeIndex(t *testing.T, dir string, paths ...string) {
	t.Helper()
	var b []byte
	b = append(b, "DIRC"...)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = binary.BigEndian.AppendUint32(b, uint32(len(paths))) // #nosec G115 -- a handful of test paths
	for _, p := range paths {
		start := len(b)
		b = append(b, make([]byte, 60)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(p))) // #nosec G115 -- short test paths
		b = append(b, p...)
		n := len(b) - start
		b = append(b, make([]byte, (n+8)&^7-n)...)
	}
	writeFile(t, filepath.Join(dir, ".git", "index"), string(b))
}

// #1206: with a git index, a committed local file is reported as committed,
// with git rm --cached, whether or not .gitignore covers it.
func TestCFG013_Issue1206(t *testing.T) {
	committed := func(t *testing.T, gitignore string) []finding.Finding {
		t.Helper()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
		if gitignore != "" {
			writeFile(t, filepath.Join(dir, ".gitignore"), gitignore)
		}
		writeIndex(t, dir, ".claude/settings.json", ".claude/settings.local.json")
		return CFG013.Check(projectTarget(dir))
	}
	for name, gitignore := range map[string]string{"not covered": "node_modules/\n", "covered": ".claude/settings.local.json\n"} {
		f := committed(t, gitignore)
		if len(f) != 1 || !strings.Contains(f[0].Message, "is committed") || !strings.Contains(f[0].Message, "git rm --cached .claude/settings.local.json") {
			t.Errorf("tracked, %s: got %+v", name, f)
		}
		if name == "covered" && !strings.Contains(f[0].Message, "does not untrack") {
			t.Errorf("tracked, covered: message should say .gitignore does not untrack it: %s", f[0].Message)
		}
	}

	// Untracked, with an index present: the .gitignore check as before.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	writeIndex(t, dir, ".claude/settings.json")
	if f := CFG013.Check(projectTarget(dir)); len(f) != 1 || !strings.Contains(f[0].Message, "not covered by .gitignore") {
		t.Errorf("untracked, not covered: got %+v", f)
	}
	writeFile(t, filepath.Join(dir, ".gitignore"), ".claude/settings.local.json\n")
	if f := CFG013.Check(projectTarget(dir)); len(f) != 0 {
		t.Errorf("untracked, covered: got %+v", f)
	}

	// No .git: as today, and the message mentions git rm --cached for the
	// case that the file is committed.
	dir = t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	if f := CFG013.Check(projectTarget(dir)); len(f) != 1 || !strings.Contains(f[0].Message, "not covered by .gitignore") || !strings.Contains(f[0].Message, "git rm --cached") {
		t.Errorf("no .git: got %+v", f)
	}
}
