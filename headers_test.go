// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
)

// TestSourceHeaders checks that every tracked source and build file carries
// the copyright and license lines (#758). Fixtures under testdata are scanned
// input and stay byte-exact. Only tracked files count, so local tool state and
// files that tools generate next to the sources (gobco in the Branch coverage
// job) are left out.
func TestSourceHeaders(t *testing.T) {
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		prefix := headerPrefix(name)
		if prefix == "" {
			continue
		}
		b, err := os.ReadFile(name) // #nosec G304 -- names come from git ls-files of this repository
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		// The header comes first, after a shebang line if there is one. A
		// Windows checkout may have converted line endings to CRLF.
		lines := strings.SplitN(string(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))), "\n", 4)
		if strings.HasPrefix(lines[0], "#!") {
			lines = lines[1:]
		}
		// The expected lines are strings here, not this file's header; the
		// markers keep reuse lint from reading them as one (#789).
		// REUSE-IgnoreStart
		if len(lines) < 2 ||
			lines[0] != prefix+" Copyright the cfgaudit contributors" ||
			lines[1] != prefix+" SPDX-License-Identifier: Apache-2.0" {
			t.Errorf("%s does not start with the copyright and SPDX lines:\n%s Copyright the cfgaudit contributors\n%s SPDX-License-Identifier: Apache-2.0", name, prefix, prefix)
		}
		// REUSE-IgnoreEnd
	}
}

// headerPrefix returns the comment marker for a file that needs the header, or
// "" for one that does not.
func headerPrefix(name string) string {
	if strings.HasPrefix(name, "testdata/") || strings.Contains(name, "/testdata/") {
		return ""
	}
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
