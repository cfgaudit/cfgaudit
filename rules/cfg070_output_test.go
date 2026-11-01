// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// #1211: a command under a build or install output directory that is not in
// the tree is info with its own message; a committed file there, and any
// other repo-relative path, keeps the warning.
func TestCFG070_BuildOutput1211(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "vendor", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "bin", "my-tool"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cmd  string
		want finding.Severity
		msg  string
	}{
		{"./target/release/my-server", finding.Info, "locally built or installed"},
		{".venv/bin/my-server", finding.Info, "locally built or installed"},
		{`node_modules\.bin\server`, finding.Info, "locally built or installed"},
		{"vendor/bin/my-tool", finding.Warn, "committed in-repo executable"},
		{"./gradlew", finding.Warn, "committed in-repo executable"},
		{"./bin/start-mcp.sh", finding.Warn, "committed in-repo executable"},
	} {
		tg := &Target{
			ProjectDir:     dir,
			ProjectMCP:     map[string]parser.MCPServer{"m": {Command: tc.cmd}},
			ProjectMCPFile: filepath.Join(dir, ".mcp.json"),
		}
		f := CFG070.Check(tg)
		if len(f) != 1 || f[0].Severity != tc.want || !strings.Contains(f[0].Message, tc.msg) {
			t.Errorf("%s: want one %s finding with %q, got %+v", tc.cmd, tc.want, tc.msg, f)
		}
	}
}
