// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package safeyaml

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crash is the document the fuzz job found (#846).
const crash = "? -\n? <<\n"

func TestUnmarshal_PanicBecomesError(t *testing.T) {
	var m map[string]any
	if err := Unmarshal([]byte(crash), &m); err == nil {
		t.Fatal("expected an error for a document the decoder panics on")
	}
	var s struct {
		Models []map[string]any `yaml:"models"`
	}
	if err := Unmarshal([]byte("models:\n  - "+"? -\n    ? <<\n"), &s); err == nil {
		t.Fatal("expected an error for the nested document")
	}
}

func TestUnmarshal_Valid(t *testing.T) {
	var m map[string]any
	if err := Unmarshal([]byte("name: x\ntools: [Read]\n"), &m); err != nil || m["name"] != "x" {
		t.Fatalf("got %v, %v", m, err)
	}
	if err := Unmarshal([]byte("a: [unclosed\n"), &m); err == nil {
		t.Fatal("expected the decoder's own error")
	}
}

// Every YAML decode in cfgaudit goes through Unmarshal, so a decoder panic
// cannot come back through a new call site.
func TestNoDirectYAMLUnmarshal(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			filepath.Base(filepath.Dir(path)) == "safeyaml" {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: a path from walking the repository
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "yaml.Unmarshal(") && !strings.Contains(line, "safeyaml.Unmarshal(") {
				t.Errorf("%s:%d calls yaml.Unmarshal; use safeyaml.Unmarshal", path, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
