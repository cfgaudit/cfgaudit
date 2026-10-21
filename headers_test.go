// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
)

// TestSourceHeaders checks that every source and build file carries the
// copyright and license lines (#758). Fixtures under testdata are scanned input
// and stay byte-exact.
func TestSourceHeaders(t *testing.T) {
	// Only a checkout holds the whole tree. Tools that copy the package
	// elsewhere to run its tests (gobco in the Branch coverage job) do not.
	if _, err := os.Stat(".git"); err != nil {
		t.Skip("not a git checkout")
	}
	repo := os.DirFS(".")
	err := fs.WalkDir(repo, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Hidden directories other than .github hold local tool state
			// (.git, editor and agent caches), not project sources.
			hidden := strings.HasPrefix(d.Name(), ".") && name != "." && name != ".github"
			switch {
			case hidden, d.Name() == "testdata", d.Name() == "node_modules", d.Name() == "vendor":
				return fs.SkipDir
			}
			return nil
		}
		prefix := headerPrefix(name)
		if prefix == "" {
			return nil
		}
		b, err := fs.ReadFile(repo, name)
		if err != nil {
			return err
		}
		// The header comes first, after a shebang line if there is one. A
		// Windows checkout may have converted line endings to CRLF.
		lines := strings.SplitN(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n", 4)
		if strings.HasPrefix(lines[0], "#!") {
			lines = lines[1:]
		}
		if len(lines) < 2 ||
			lines[0] != prefix+" Copyright the cfgaudit contributors" ||
			lines[1] != prefix+" SPDX-License-Identifier: Apache-2.0" {
			t.Errorf("%s does not start with the copyright and SPDX lines:\n%s Copyright the cfgaudit contributors\n%s SPDX-License-Identifier: Apache-2.0", name, prefix, prefix)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// headerPrefix returns the comment marker for a file that needs the header, or
// "" for one that does not.
func headerPrefix(name string) string {
	switch {
	case strings.HasSuffix(name, ".go"), strings.HasSuffix(name, ".js"):
		return "//"
	case strings.HasSuffix(name, ".yml"), strings.HasSuffix(name, ".yaml"),
		strings.HasSuffix(name, ".sh"), strings.HasSuffix(name, ".py"),
		path.Base(name) == "Dockerfile", path.Dir(name) == "bin":
		return "#"
	}
	return ""
}
