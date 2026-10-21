// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	goCopyright = "// Copyright the cfgaudit contributors"
	goSPDX     = "// SPDX-License-Identifier: Apache-2.0"
	shCopyright = "# Copyright the cfgaudit contributors"
	shSPDX     = "# SPDX-License-Identifier: Apache-2.0"
)

func TestSourceHeaders(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(thisFile)

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !ownedSource(path, root) {
			return nil
		}
		checkHeader(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func ownedSource(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.Contains(filepath.ToSlash(rel), "/testdata/") {
		return false
	}
	switch filepath.Ext(path) {
	case ".go", ".sh", ".py":
		return true
	case ".yml", ".yaml":
		rel = filepath.ToSlash(rel)
		return strings.HasPrefix(rel, ".github/workflows/") || rel == ".gitlab-ci.yml" || strings.HasPrefix(rel, "templates/")
	default:
		return false
	}
}

func checkHeader(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("read %s: %v", path, err)
		return
	}
	text := string(b)
	var copyright, spdx string
	if filepath.Ext(path) == ".go" {
		copyright, spdx = goCopyright, goSPDX
	} else {
		copyright, spdx = shCopyright, shSPDX
	}
	if !strings.Contains(text, copyright) || !strings.Contains(text, spdx) {
		t.Errorf("%s is missing the copyright and SPDX header", path)
	}
	if filepath.Ext(path) == ".go" {
		packageAt := strings.Index(text, "\npackage ")
		if packageAt < 0 || strings.Index(text, copyright) > packageAt || strings.Index(text, spdx) > packageAt {
			t.Errorf("%s has its header below the package clause", path)
		}
	}
}
