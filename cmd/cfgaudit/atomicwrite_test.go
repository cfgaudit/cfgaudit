// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// tempFiles returns the leftover temporary files writeFileAtomic would create
// for a target named base in dir.
func tempFiles(t *testing.T, dir, base string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "."+base+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWriteFileAtomic_NewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := writeFileAtomic(path, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: a path in the test's temp dir
	if err != nil || string(b) != "{}\n" {
		t.Fatalf("got %q, %v", b, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("new file mode %v, want 0600", info.Mode().Perm())
		}
	}
}

// Replacing a file keeps its permission bits, as os.WriteFile did.
func TestWriteFileAtomic_ReplaceKeepsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil { //nolint:gosec // G306: the mode under test
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path) //nolint:gosec // G304: a path in the test's temp dir
	info, _ := os.Stat(path)
	if string(b) != "new" || info.Mode().Perm() != 0o644 {
		t.Errorf("got %q mode %v, want \"new\" mode 0644", b, info.Mode().Perm())
	}
	if left := tempFiles(t, dir, "settings.json"); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// A failure before the rename leaves the original untouched and removes the
// temporary file.
func TestWriteFileAtomic_FailureKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("rename failed")
	renameFile = func(string, string) error { return failed }
	t.Cleanup(func() { renameFile = os.Rename })

	if err := writeFileAtomic(path, []byte("new")); !errors.Is(err, failed) {
		t.Fatalf("err = %v, want the rename error", err)
	}
	b, _ := os.ReadFile(path) //nolint:gosec // G304: a path in the test's temp dir
	if string(b) != "original" {
		t.Errorf("original changed to %q", b)
	}
	if left := tempFiles(t, dir, "settings.json"); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// A directory that cannot hold the temporary file is an error, and nothing is
// written.
func TestWriteFileAtomic_MissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "settings.json")
	if err := writeFileAtomic(path, []byte("x")); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

// A target that is not a regular file is refused rather than replaced.
func TestWriteFileAtomic_NotRegular(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("x")); err == nil {
		t.Fatal("expected an error for a directory target")
	}
}

// A symlinked target is written through, as os.WriteFile did: the link stays
// and the file it points to gets the new content.
func TestWriteFileAtomic_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeFileAtomic(link, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v, %v", info, err)
	}
	b, _ := os.ReadFile(target) //nolint:gosec // G304: a path in the test's temp dir
	if string(b) != "new" {
		t.Errorf("link target got %q, want \"new\"", b)
	}
}
