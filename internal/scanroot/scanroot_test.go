// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package scanroot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// symlink creates a link or skips the test where the platform refuses (Windows
// without the privilege).
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadFile(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	write(t, filepath.Join(base, "outside", "secret"), "GH_TOKEN=x")
	write(t, filepath.Join(repo, "CLAUDE.md"), "inside")
	write(t, filepath.Join(repo, "docs", "real.md"), "inside too")
	symlink(t, "CLAUDE.md", filepath.Join(repo, "AGENTS.md"))
	symlink(t, filepath.Join("docs", "real.md"), filepath.Join(repo, "GEMINI.md"))
	symlink(t, filepath.Join("..", "outside", "secret"), filepath.Join(repo, ".mcp.json"))
	symlink(t, filepath.Join("..", "outside"), filepath.Join(repo, ".cursor"))
	if err := Set(repo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })

	for _, name := range []string{"CLAUDE.md", "AGENTS.md", "GEMINI.md"} {
		if _, err := ReadFile(filepath.Join(repo, name)); err != nil {
			t.Errorf("%s: a file or link inside the repository must be read: %v", name, err)
		}
	}

	for _, name := range []string{".mcp.json", filepath.Join(".cursor", "secret")} {
		data, err := ReadFile(filepath.Join(repo, name))
		if !errors.Is(err, fs.ErrNotExist) || data != nil {
			t.Errorf("%s: a link leaving the repository must read as absent, got %q, %v", name, data, err)
		}
		if f, err := Open(filepath.Join(repo, name)); err == nil {
			_ = f.Close()
			t.Errorf("%s: Open followed a link leaving the repository", name)
		}
	}

	want := []Escape{
		{Path: filepath.Join(repo, ".mcp.json"), Link: filepath.Join("..", "outside", "secret")},
		{Path: filepath.Join(repo, ".cursor", "secret"), Link: filepath.Join("..", "outside")},
	}
	got := Escapes()
	if len(got) != len(want) {
		t.Fatalf("escapes = %+v, want %+v (each path once)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("escape %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// A missing file is still reported by the open itself, not as an escape.
	if _, err := ReadFile(filepath.Join(repo, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if n := len(Escapes()); n != len(want) {
		t.Errorf("a missing file was recorded as an escape (%d escapes)", n)
	}
}

func TestReadFile_PathsOutsideTheScanAreNotChecked(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	write(t, filepath.Join(repo, "CLAUDE.md"), "x")
	write(t, filepath.Join(base, "dotfiles", "settings.json"), "{}")
	home := filepath.Join(base, "home", ".claude")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	// A user-scope file linked into a dotfiles checkout is ordinary.
	symlink(t, filepath.Join(base, "dotfiles", "settings.json"), filepath.Join(home, "settings.json"))
	if err := Set(repo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })
	if _, err := ReadFile(filepath.Join(home, "settings.json")); err != nil {
		t.Errorf("a user-named path outside the scan was refused: %v", err)
	}
	if len(Escapes()) != 0 {
		t.Errorf("escapes = %+v, want none", Escapes())
	}
}

func TestSet_ScanRootThatIsItselfALink(t *testing.T) {
	base := t.TempDir()
	write(t, filepath.Join(base, "real", "CLAUDE.md"), "x")
	symlink(t, filepath.Join(base, "real"), filepath.Join(base, "link"))
	if err := Set(filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })
	if _, err := ReadFile(filepath.Join(base, "link", "CLAUDE.md")); err != nil {
		t.Errorf("scanning through a linked directory refused its own files: %v", err)
	}
}

func TestReadFile_NoRootSetChecksNothing(t *testing.T) {
	_ = Set("")
	base := t.TempDir()
	write(t, filepath.Join(base, "outside"), "x")
	symlink(t, filepath.Join(base, "outside"), filepath.Join(base, "link"))
	if _, err := ReadFile(filepath.Join(base, "link")); err != nil {
		t.Errorf("with no scan root set, ReadFile must behave like os.ReadFile: %v", err)
	}
}

func TestSet_MissingDirectory(t *testing.T) {
	t.Cleanup(func() { _ = Set("") })
	if err := Set(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("Set of a directory that does not exist must fail")
	}
}

func TestOpen(t *testing.T) {
	base := t.TempDir()
	scan := filepath.Join(base, "repo")
	write(t, filepath.Join(scan, "CLAUDE.md"), "x")
	write(t, filepath.Join(base, "secret"), "s")
	if err := Set(scan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })

	f, err := Open(filepath.Join(scan, "CLAUDE.md"))
	if err != nil {
		t.Fatalf("Open of a file in the scan: %v", err)
	}
	_ = f.Close()

	// The scan root itself is inside the scan, so it is not an escape; as a
	// directory it reads as absent (#828).
	if _, err := Open(scan); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open of the scan root directory: want not-exist, got %v", err)
	}
	if esc := Escapes(); len(esc) != 0 {
		t.Fatalf("the scan root was recorded as an escape: %+v", esc)
	}

	symlink(t, filepath.Join(base, "secret"), filepath.Join(scan, "link"))
	if _, err := Open(filepath.Join(scan, "link")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open through a link leaving the scan: err = %v, want not-exist", err)
	}
}

// A directory where a file is expected, and a path through a file, read as
// absent (#828).
func TestReadFile_FileDirectoryMixups(t *testing.T) {
	dir := t.TempDir()
	if err := Set(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Set("") })
	if err := os.Mkdir(filepath.Join(dir, ".rules"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".codex"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, ".rules"), filepath.Join(dir, ".codex", "config.toml")} {
		if _, err := ReadFile(p); !errors.Is(err, fs.ErrNotExist) || !IsAbsent(err) {
			t.Errorf("ReadFile(%s): want not-exist, got %v", p, err)
		}
		if _, err := Open(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Open(%s): want not-exist, got %v", p, err)
		}
	}
	if _, err := os.ReadDir(filepath.Join(dir, ".codex", "skills")); !IsAbsent(err) {
		t.Errorf("IsAbsent should cover a directory read through a file, got %v", err)
	}
}
