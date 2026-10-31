// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lockPath removes every permission bit from path and restores them when the
// test ends, so the temp dir can be cleaned up. It skips where permission bits
// do not stop reads: on Windows and for root.
func lockPath(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits do not stop reads here")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, info.Mode().Perm()) })
}

// scanJSON runs a JSON scan of root and returns the exit code, the rule IDs
// reported and stderr.
func scanJSON(t *testing.T, root string) (int, []string, string) {
	t.Helper()
	code, stdout, stderr := runCLI(t, "--format", "json", "--claude-version", "2.1.0", root)
	var findings []struct{ RuleID string }
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, stdout)
	}
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return code, ids, stderr
}

// wantIncomplete checks the stderr list of unreadable paths, relative to root.
func wantIncomplete(t *testing.T, stderr, root string, paths ...string) {
	t.Helper()
	want := fmt.Sprintf("cfgaudit: could not read %d %s, results are incomplete:\n", len(paths), pluralize("path", len(paths)))
	for _, p := range paths {
		want += "  " + filepath.Join(root, filepath.FromSlash(p)) + "\n"
	}
	if !strings.HasSuffix(stderr, want) {
		t.Errorf("stderr =\n%s\nwant it to end with\n%s", stderr, want)
	}
}

// An unreadable directory in the skills walk is named and fails the scan; it
// used to be skipped with a clean result (#1043). The rest is still scanned.
func TestRun_UnreadableSkillsDir(t *testing.T) {
	root := runFixture(t, map[string]string{
		".claude/settings.json":     errorSettings,
		".claude/skills/x/SKILL.md": "---\nname: x\ndescription: y\n---\nhi\n",
	})
	lockPath(t, filepath.Join(root, ".claude", "skills"))
	code, ids, stderr := scanJSON(t, root)
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
	if !strings.Contains(strings.Join(ids, " "), "CFG004") {
		t.Errorf("the readable settings.json was not scanned: %v", ids)
	}
	wantIncomplete(t, stderr, root, ".claude/skills")
}

// An unreadable JSON config is an incomplete scan, not CFG109: git does not
// record read permissions, so the committed file is not broken.
func TestRun_UnreadableSettingsIsNotCFG109(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": errorSettings, "AGENTS.md": "# p\n"})
	lockPath(t, filepath.Join(root, ".claude", "settings.json"))
	code, ids, stderr := scanJSON(t, root)
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
	for _, id := range ids {
		if id == "CFG109" {
			t.Errorf("CFG109 reported for a permission error: %v", ids)
		}
	}
	wantIncomplete(t, stderr, root, ".claude/settings.json")
}

// An unreadable .vscode/ is one entry; the files cfgaudit looks for in it are
// not reported, since they do not exist.
func TestRun_UnreadableEmptyDir(t *testing.T) {
	root := runFixture(t, map[string]string{"AGENTS.md": "# p\n"})
	vscode := filepath.Join(root, ".vscode")
	if err := os.Mkdir(vscode, 0o750); err != nil {
		t.Fatal(err)
	}
	lockPath(t, vscode)
	code, ids, stderr := scanJSON(t, root)
	if code != 2 || len(ids) != 0 {
		t.Errorf("exit code %d, findings %v; want 2 and none", code, ids)
	}
	wantIncomplete(t, stderr, root, ".vscode")
}

// Two unreadable paths in one scan are both listed, and a file that used to
// end the scan at the first error (CLAUDE.md) no longer does.
func TestRun_UnreadablePathsAllListed(t *testing.T) {
	root := runFixture(t, map[string]string{
		".claude/settings.json": errorSettings,
		"CLAUDE.md":             "# p\n",
		".claude/agents/a.md":   "---\nname: a\n---\nhi\n",
	})
	lockPath(t, filepath.Join(root, "CLAUDE.md"))
	lockPath(t, filepath.Join(root, ".claude", "agents"))
	code, ids, stderr := scanJSON(t, root)
	if code != 2 || !strings.Contains(strings.Join(ids, " "), "CFG004") {
		t.Errorf("exit code %d, findings %v; want 2 with the settings findings", code, ids)
	}
	wantIncomplete(t, stderr, root, ".claude/agents", "CLAUDE.md")
	// The note for a directory without agent config must not appear for one
	// whose config could not be read.
	if strings.Contains(stderr, "no agent configuration") {
		t.Errorf("unexpected no-config note: %q", stderr)
	}
}

// cfgaudit's own .cfgaudit.yml still stops the scan before it starts.
func TestRun_UnreadableCfgauditYmlStops(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": errorSettings, ".cfgaudit.yml": "strict: true\n"})
	lockPath(t, filepath.Join(root, ".cfgaudit.yml"))
	code, stdout, stderr := runCLI(t, "--claude-version", "2.1.0", root)
	if code != 2 || stdout != "" || !strings.Contains(stderr, "permission denied") {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 2, no report, a permission error", code, stdout, stderr)
	}
}
