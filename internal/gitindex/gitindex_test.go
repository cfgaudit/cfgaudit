// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package gitindex

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// buildIndex writes an index file in the given format version holding paths.
func buildIndex(version uint32, paths []string) []byte {
	var b bytes.Buffer
	b.WriteString("DIRC")
	_ = binary.Write(&b, binary.BigEndian, version)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(paths))) // #nosec G115 -- a handful of test paths
	prev := ""
	for _, p := range paths {
		start := b.Len()
		b.Write(make([]byte, 60))
		_ = binary.Write(&b, binary.BigEndian, uint16(min(len(p), 0xfff)))
		if version == 4 {
			common := 0
			for common < len(prev) && common < len(p) && prev[common] == p[common] {
				common++
			}
			b.WriteByte(byte(len(prev) - common)) // #nosec G115 -- short test paths fit in one varint byte
			b.WriteString(p[common:])
			b.WriteByte(0)
		} else {
			b.WriteString(p)
			n := b.Len() - start
			b.Write(make([]byte, (n+8)&^7-n))
		}
		prev = p
	}
	return b.Bytes()
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestParse(t *testing.T) {
	paths := []string{".claude/settings.json", ".claude/settings.local.json", "CLAUDE.md", "a", "src/main.go"}
	for _, v := range []uint32{2, 3, 4} {
		got, err := parse(buildIndex(v, paths))
		if err != nil {
			t.Fatalf("version %d: %v", v, err)
		}
		if !reflect.DeepEqual(keys(got), paths) {
			t.Errorf("version %d: got %v, want %v", v, keys(got), paths)
		}
	}
	for name, data := range map[string][]byte{
		"empty":     nil,
		"magic":     []byte("XXXX\x00\x00\x00\x02\x00\x00\x00\x00"),
		"version":   []byte("DIRC\x00\x00\x00\x09\x00\x00\x00\x00"),
		"truncated": buildIndex(2, paths)[:40],
		"no nul":    append(buildIndex(4, []string{"a"})[:12+62+1], 'b'),
	} {
		if _, err := parse(data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestVarint(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0x80, 0x00}, 128, 2},
		{[]byte{0x80}, 0, 0},
		{nil, 0, 0},
	} {
		if v, n := varint(tc.in); v != tc.want || n != tc.n {
			t.Errorf("varint(%x) = %d, %d; want %d, %d", tc.in, v, n, tc.want, tc.n)
		}
	}
}

func TestTracked(t *testing.T) {
	dir := t.TempDir()
	if _, ok := Tracked(dir); ok {
		t.Error("no .git: expected ok=false")
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok := Tracked(dir); ok {
		t.Error(".git without an index: expected ok=false")
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "index"), buildIndex(2, []string{"CLAUDE.local.md"}), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := Tracked(dir); !ok || !got["CLAUDE.local.md"] {
		t.Errorf("Tracked = %v, %v", got, ok)
	}

	// A .git file naming a directory inside the working tree is followed; one
	// naming a directory outside it is not.
	wt := t.TempDir()
	inner := filepath.Join(wt, "gitdirs", "main")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "index"), buildIndex(2, []string{"x"}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: gitdirs/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := Tracked(wt); !ok || !got["x"] {
		t.Errorf(".git file inside: Tracked = %v, %v", got, ok)
	}
	for _, content := range []string{"gitdir: " + filepath.Join(dir, ".git") + "\n", "gitdir: ../outside\n", "not a gitdir line\n"} {
		if err := os.WriteFile(filepath.Join(wt, ".git"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := Tracked(wt); ok {
			t.Errorf(".git file %q: expected ok=false", content)
		}
	}
}

// The reader agrees with git itself, for index versions 2 and 4.
func TestTracked_RealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, version := range []string{"2", "4"} {
		dir := t.TempDir()
		files := []string{".claude/settings.local.json", ".claude/settings.json", "CLAUDE.md", "docs/a/b/c.md", "docs/a/b/d.md"}
		for _, f := range files {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, args := range [][]string{{"init", "-q"}, {"add", "-f", "."}, {"update-index", "--index-version", version}} {
			cmd := exec.Command("git", args...) // #nosec G204 -- fixed git arguments in a test
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v: %s", args, err, out)
			}
		}
		got, ok := Tracked(dir)
		sort.Strings(files)
		if !ok || !reflect.DeepEqual(keys(got), files) {
			t.Errorf("index version %s: Tracked = %v, %v; want %v", version, keys(got), ok, files)
		}
	}
}
