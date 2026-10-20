package version

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"2.1.148", Version{2, 1, 148}, false},
		{"Claude Code v2.1.148\n", Version{2, 1, 148}, false},
		{"v0.2.21 (build 12345)", Version{0, 2, 21}, false},
		{"no version here", Version{}, true},
		{"1.2", Version{}, true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAtLeast(t *testing.T) {
	cases := []struct {
		v, min Version
		want   bool
	}{
		{Version{2, 1, 148}, Version{2, 1, 148}, true},
		{Version{2, 1, 149}, Version{2, 1, 148}, true},
		{Version{2, 2, 0}, Version{2, 1, 999}, true},
		{Version{3, 0, 0}, Version{2, 99, 99}, true},
		{Version{2, 1, 147}, Version{2, 1, 148}, false},
		{Version{2, 0, 999}, Version{2, 1, 0}, false},
		{Version{1, 99, 99}, Version{2, 0, 0}, false},
	}
	for _, c := range cases {
		got := c.v.AtLeast(c.min)
		if got != c.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", c.v, c.min, got, c.want)
		}
	}
}

func TestString(t *testing.T) {
	v := Version{Major: 2, Minor: 1, Patch: 148}
	if got := v.String(); got != "2.1.148" {
		t.Errorf("String() = %q, want %q", got, "2.1.148")
	}
}

// fakeClaude puts a `claude` shell script printing out and exiting with code
// first on PATH. Shell scripts do not run on Windows, so the test skips there.
func fakeClaude(t *testing.T, out string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nexit %d\n", out, code)
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o700); err != nil { // #nosec G306 -- the test needs an executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestDetect(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		fakeClaude(t, "2.1.150 (Claude Code)", 0)
		v, ok, err := Detect()
		if err != nil || !ok || v != (Version{2, 1, 150}) {
			t.Errorf("Detect() = %v, %v, %v; want 2.1.150, true, nil", v, ok, err)
		}
	})
	t.Run("not installed", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, ok, err := Detect(); ok || err != nil {
			t.Errorf("Detect() without claude = %v, %v; want false, nil", ok, err)
		}
	})
	t.Run("fails", func(t *testing.T) {
		fakeClaude(t, "", 3)
		if _, ok, err := Detect(); ok || err == nil {
			t.Errorf("Detect() with a failing claude = %v, %v; want false and an error", ok, err)
		}
	})
	t.Run("no version in output", func(t *testing.T) {
		fakeClaude(t, "unknown", 0)
		if _, ok, err := Detect(); ok || err == nil {
			t.Errorf("Detect() with unparseable output = %v, %v; want false and an error", ok, err)
		}
	})
}
