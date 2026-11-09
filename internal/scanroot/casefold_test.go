// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package scanroot

import (
	"os"
	"path/filepath"
	"testing"
)

// caseInsensitiveFS reports whether dir is on a filesystem that ignores case,
// as macOS and Windows do by default; there the OS resolves the spelling and
// no alias is recorded.
func caseInsensitiveFS(t *testing.T, dir string) bool {
	t.Helper()
	p := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(p) }()
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

// A path absent under the spelling asked for is read under its committed
// spelling, and the alias is recorded (#990).
func TestCaseResolve990(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".Cursor", "rules"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".Cursor", "MCP.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".Cursor", "rules", "a.mdc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	insensitive := caseInsensitiveFS(t, dir)
	if err := Set(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })

	if data, err := ReadFile(filepath.Join(dir, ".cursor", "mcp.json")); err != nil || string(data) != "{}" {
		t.Fatalf("ReadFile: %q, %v", data, err)
	}
	if _, err := Stat(filepath.Join(dir, ".cursor", "rules")); err != nil {
		t.Errorf("Stat: %v", err)
	}
	if es, err := ReadDir(filepath.Join(dir, ".cursor", "rules")); err != nil || len(es) != 1 {
		t.Errorf("ReadDir: %v, %v", es, err)
	}
	if m, _ := Glob(filepath.Join(dir, ".cursor", "rules", "*.mdc")); len(m) != 1 {
		t.Errorf("Glob: %v", m)
	}
	if f, err := Open(filepath.Join(dir, ".cursor", "rules", "a.mdc")); err != nil {
		t.Errorf("Open: %v", err)
	} else {
		_ = f.Close()
	}
	walked := 0
	_ = WalkDir(filepath.Join(dir, ".cursor"), func(string, os.DirEntry, error) error { walked++; return nil })
	if walked < 3 {
		t.Errorf("WalkDir saw %d entries", walked)
	}
	a := Aliases()
	if insensitive {
		if len(a) != 0 {
			t.Errorf("the OS resolves case here, but aliases were recorded: %v", a)
		}
		return
	}
	if got := a[filepath.Join(dir, ".cursor", "mcp.json")]; got != filepath.Join(dir, ".Cursor", "MCP.json") {
		t.Errorf("alias: %v", a)
	}
	// A cached alias resolves the same, and a relative path stays relative.
	if got := caseResolve(filepath.Join(dir, ".cursor", "mcp.json")); got != filepath.Join(dir, ".Cursor", "MCP.json") {
		t.Errorf("cached: %s", got)
	}
	t.Chdir(dir)
	if got := caseResolve(filepath.Join(".cursor", "rules", "a.mdc")); got != filepath.Join(".Cursor", "rules", "a.mdc") {
		t.Errorf("relative: %s", got)
	}
}

// Nothing is resolved when no other spelling exists, when two do, outside the
// scanned directory, or with the check off.
func TestCaseResolve990_NoAlias(t *testing.T) {
	dir := t.TempDir()
	if caseInsensitiveFS(t, dir) {
		t.Skip("the filesystem ignores case")
	}
	for _, d := range []string{".CURSOR", ".Cursor"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := Set(""); err != nil {
		t.Fatal(err)
	}
	if got := caseResolve(filepath.Join(dir, ".cursor")); got != filepath.Join(dir, ".cursor") {
		t.Errorf("check off: %s", got)
	}
	if err := Set(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })
	for _, p := range []string{
		filepath.Join(dir, ".cursor"),        // two other spellings
		filepath.Join(dir, ".vscode", "x"),   // none
		filepath.Join(dir),                   // the root itself
		filepath.Join(t.TempDir(), "AGENTS"), // outside the scanned directory
	} {
		if got := caseResolve(p); got != p {
			t.Errorf("%s resolved to %s", p, got)
		}
	}
	if len(Aliases()) != 0 {
		t.Errorf("aliases: %v", Aliases())
	}
}
