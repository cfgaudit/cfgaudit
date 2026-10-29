// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package benchcorpus

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: reads the tree this test wrote
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The benchmark numbers compare across commits only if the corpus is the same
// on every run, and is sized as documented.
func TestWrite_ReproducibleAndSized(t *testing.T) {
	for _, c := range []struct {
		name  string
		p     Profile
		files int
	}{
		{"Repo", Repo, 37},
		{"Large", Large, 119},
	} {
		a, b := t.TempDir(), t.TempDir()
		if err := Write(a, c.p); err != nil {
			t.Fatal(err)
		}
		if err := Write(b, c.p); err != nil {
			t.Fatal(err)
		}
		ta, tb := readTree(t, a), readTree(t, b)
		if len(ta) != c.files {
			t.Errorf("%s: %d files, want %d", c.name, len(ta), c.files)
		}
		for rel, content := range ta {
			if tb[rel] != content {
				t.Errorf("%s: %s differs between two runs", c.name, rel)
			}
		}
	}
}

func TestWrite_FailsOnUnwritableDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(file, Repo); err == nil {
		t.Error("expected an error when the target directory is a file")
	}
}

func TestInputs(t *testing.T) {
	first, second := Instruction(200), Instruction(200)
	if first != second {
		t.Error("Instruction is not reproducible")
	}
	if n := strings.Count(Instruction(200), "\n"); n < 200 || n > 220 {
		t.Errorf("Instruction(200) has %d lines", n)
	}
	for name, s := range map[string]string{"LongLine": LongLine(5000), "DenseLine": DenseLine(5000)} {
		if len(s) < 5000 || strings.Contains(s, "\n") {
			t.Errorf("%s: %d bytes, newline %v", name, len(s), strings.Contains(s, "\n"))
		}
	}
	var v struct {
		Permissions struct{ Allow, Deny []string }
	}
	if err := json.Unmarshal([]byte(LargeSettings(10)), &v); err != nil || len(v.Permissions.Allow) != 10 || len(v.Permissions.Deny) != 10 {
		t.Errorf("LargeSettings(10): %v, %+v", err, v.Permissions)
	}
}
