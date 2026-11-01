// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// An unclosed backtick before a code span that starts with @ used to make
// the scan read a path with NUL bytes, report the repository root as
// unreadable and exit 2 (#1166).
func TestRun_UnclosedBacktickBeforeAtSpan(t *testing.T) {
	root := runFixture(t, map[string]string{
		"AGENTS.md": "# Notes\n\n- Unit tests filtering to file: `npm run test-unit -- **/fileName.ts\n\nIt is installed via the `@typescript/native-preview` package, see `docs`.\n",
	})
	code, _, errOut := runCLI(t, "--claude-version", "2.1.316", "--format", "json", root)
	if code != 0 || strings.Contains(errOut, "could not read") {
		t.Fatalf("exit %d, stderr:\n%s", code, errOut)
	}
}
