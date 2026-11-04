// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func symlink1417(t *testing.T, target, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func cfg115ByName1417(t *testing.T, dir string) map[string]finding.Finding {
	t.Helper()
	got := map[string]finding.Finding{}
	for _, f := range scanFindings(t, "--only", "CFG115", dir) {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil {
			t.Fatal(err)
		}
		got[filepath.ToSlash(rel)] = f
	}
	return got
}

// Any link that leaves the repository is reported by its text, whether or not
// the target exists here; a link that stays inside is not.
func TestLeavingLinks1417(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "CLAUDE.md"), "# p\n")
	mustWrite(t, filepath.Join(dir, "docs", "a.md"), "text\n")
	for link, target := range map[string]string{
		"keys":            "~/.ssh/authorized_keys",
		"docs/notes.txt":  "../../outside/notes.txt",
		"bin/tool":        "/opt/tool",
		"shared":          "../shared",
		"rc":              "../../home/u/.bashrc",
		"AGENTS.md":       "CLAUDE.md",
		"docs/inside.txt": "a.md",
		"docs/up.txt":     "../CLAUDE.md",
		"self":            filepath.Join(dir, "CLAUDE.md"),
		"sub/deep.md":     "../docs/a.md",
	} {
		symlink1417(t, target, filepath.Join(dir, filepath.FromSlash(link)))
	}
	got := cfg115ByName1417(t, dir)
	want := map[string]finding.Severity{
		"keys": finding.Error, "rc": finding.Error,
		"docs/notes.txt": finding.Warn, "bin/tool": finding.Warn, "shared": finding.Warn,
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for name, sev := range want {
		f, ok := got[name]
		if !ok || f.Severity != sev {
			t.Errorf("%s: want %s, got %+v", name, sev, f)
		}
		if ok && !strings.Contains(f.Message, "committed symbolic link") {
			t.Errorf("%s: message %q", name, f.Message)
		}
	}
	if !strings.Contains(got["keys"].Message, "sensitive location") {
		t.Errorf("keys: message %q", got["keys"].Message)
	}
}

// With a git index only a committed link counts; a local link does not.
func TestLeavingLinks_OnlyCommitted1417(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "CLAUDE.md"), "# p\n")
	symlink1417(t, "/opt/committed", filepath.Join(dir, "committed"))
	for _, args := range [][]string{{"init", "-q"}, {"add", "CLAUDE.md", "committed"}} {
		cmd := exec.Command("git", args...) // #nosec G204 -- fixed arguments
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	symlink1417(t, "/opt/local", filepath.Join(dir, "local"))
	got := cfg115ByName1417(t, dir)
	if _, ok := got["committed"]; !ok || len(got) != 1 {
		t.Errorf("got %+v", got)
	}
}

// A linked config directory is one finding, at the file an agent reads, and a
// config path keeps its message. The dependency trees stay unwalked.
func TestLeavingLinks_NoDoubleReport1417(t *testing.T) {
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "settings.json"), "{}\n")
	mustWrite(t, filepath.Join(outside, "mcp.json"), "{}\n")
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "CLAUDE.md"), "# p\n")
	symlink1417(t, outside, filepath.Join(dir, ".claude"))
	symlink1417(t, filepath.Join(outside, "mcp.json"), filepath.Join(dir, ".mcp.json"))
	symlink1417(t, "/opt/dep", filepath.Join(dir, "node_modules", "dep", "link"))
	symlink1417(t, "/opt/py", filepath.Join(dir, ".venv", "bin", "python"))
	got := cfg115ByName1417(t, dir)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, name := range []string{".claude/settings.json", ".mcp.json"} {
		f, ok := got[name]
		if !ok || !strings.Contains(f.Message, "no other rule ran on it") {
			t.Errorf("%s: got %+v", name, f)
		}
	}
}
