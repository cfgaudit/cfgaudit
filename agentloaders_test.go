// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeLoaderGH answers like gh from files: <dir>/latest is the latest tag,
// <dir>/releases the release list, <dir>/repo/<ref>/<path> a file at a ref,
// <dir>/open the number of an open issue. Every command that changes an issue
// is appended to <dir>/calls.
const fakeLoaderGH = `#!/usr/bin/env bash
dir=$(dirname "$0")
case "$1 $2" in
  "issue list") cat "$dir/open" 2>/dev/null; exit 0 ;;
  "issue create"|"api -X") echo "$*" >>"$dir/calls"; exit 0 ;;
esac
for arg in "$@"; do
  case "$arg" in
    */releases\?*) cat "$dir/releases"; exit 0 ;;
    */releases/latest) [ -e "$dir/down" ] && { echo "HTTP 502" >&2; exit 1; }; cat "$dir/latest"; exit 0 ;;
    *contents/*)
      p=${arg#*contents/}; path=${p%%\?ref=*}; ref=${p##*ref=}
      f="$dir/repo/$ref/$path"
      [ -e "$f" ] || { echo "HTTP 404" >&2; exit 1; }
      cat "$f"; exit 0 ;;
  esac
done
exit 1
`

type loaderCheck struct {
	t        *testing.T
	dir, out string
}

// newLoaderCheck sets up a config for one agent with the files a.ts and b.ts,
// a reviewed release v1 and a fake gh.
func newLoaderCheck(t *testing.T, latest string) *loaderCheck {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the script runs on the Linux runner")
	}
	for _, tool := range []string{"bash", "jq", "diff", "cmp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	c := &loaderCheck{t: t, dir: t.TempDir(), out: t.TempDir()}
	c.write("gh", fakeLoaderGH)
	if err := os.Chmod(filepath.Join(c.dir, "gh"), 0o700); err != nil { //nolint:gosec // G302: the fake gh has to be executable
		t.Fatal(err)
	}
	c.write("latest", latest+"\n")
	cfg, err := json.Marshal(map[string]any{"agents": []map[string]any{{
		"agent": "demo", "repo": "o/r", "reviewed_tag": "v1", "files": []string{"src/a.ts", "src/b.ts"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	c.write("config.json", string(cfg))
	return c
}

func (c *loaderCheck) write(name, text string) {
	c.t.Helper()
	p := filepath.Join(c.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		c.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		c.t.Fatal(err)
	}
}

func (c *loaderCheck) run(env ...string) (string, int) {
	c.t.Helper()
	cmd := exec.Command("bash", ".github/scripts/check-agent-loaders.sh", filepath.Join(c.dir, "config.json"), c.out) //nolint:gosec // G204: fixed script, test paths
	cmd.Env = append(append(os.Environ(), "PATH="+c.dir+string(os.PathListSeparator)+os.Getenv("PATH"), "GITHUB_REPOSITORY=o/self"), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		c.t.Fatal(err)
	}
	return string(out), code
}

func (c *loaderCheck) calls() string {
	c.t.Helper()
	data, err := os.ReadFile(filepath.Join(c.dir, "calls"))
	if err != nil && !os.IsNotExist(err) {
		c.t.Fatal(err)
	}
	return string(data)
}

func TestAgentLoaders_ReviewedIsLatest(t *testing.T) {
	c := newLoaderCheck(t, "v1")
	out, code := c.run()
	if code != 0 || !strings.Contains(out, "v1 is the latest release") || c.calls() != "" {
		t.Errorf("exit %d, calls %q:\n%s", code, c.calls(), out)
	}
}

func TestAgentLoaders_NoLoaderFileChanged(t *testing.T) {
	c := newLoaderCheck(t, "v2")
	for _, ref := range []string{"v1", "v2"} {
		c.write("repo/"+ref+"/src/a.ts", "same\n")
		c.write("repo/"+ref+"/src/b.ts", "same\n")
	}
	out, code := c.run()
	if code != 0 || !strings.Contains(out, "no loader file changed between v1 and v2") || c.calls() != "" {
		t.Errorf("exit %d, calls %q:\n%s", code, c.calls(), out)
	}
}

func TestAgentLoaders_ChangeOpensAnIssueWithADiff(t *testing.T) {
	c := newLoaderCheck(t, "v2")
	c.write("repo/v1/src/a.ts", "old\n")
	c.write("repo/v2/src/a.ts", "new\n")
	c.write("repo/v1/src/b.ts", "same\n")
	c.write("repo/v2/src/b.ts", "same\n")
	out, code := c.run()
	if code != 0 || !strings.Contains(c.calls(), "issue create --title Agent loader changed: demo since v1") {
		t.Fatalf("exit %d, calls %q:\n%s", code, c.calls(), out)
	}
	diff, err := os.ReadFile(filepath.Join(c.out, "demo", "src_a.ts.diff"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diff), "-old") || !strings.Contains(string(diff), "+new") {
		t.Errorf("diff:\n%s", diff)
	}
	if _, err := os.Stat(filepath.Join(c.out, "demo", "src_b.ts.diff")); err == nil {
		t.Error("a diff for the unchanged file")
	}
}

func TestAgentLoaders_RemovedFileCounts(t *testing.T) {
	c := newLoaderCheck(t, "v2")
	c.write("repo/v1/src/a.ts", "old\n")
	c.write("repo/v1/src/b.ts", "same\n")
	c.write("repo/v2/src/b.ts", "same\n")
	out, code := c.run("DRY_RUN=true", "RUN_URL=https://example.invalid/run/1")
	if code != 0 || !strings.Contains(out, "- `src/a.ts`") || strings.Contains(out, "- `src/b.ts`") ||
		!strings.Contains(out, "https://example.invalid/run/1") || c.calls() != "" {
		t.Errorf("exit %d, calls %q:\n%s", code, c.calls(), out)
	}
}

func TestAgentLoaders_OpenIssueIsUpdated(t *testing.T) {
	c := newLoaderCheck(t, "v3")
	c.write("repo/v1/src/a.ts", "old\n")
	c.write("repo/v3/src/a.ts", "new\n")
	c.write("open", "42\n")
	out, code := c.run()
	if code != 0 || !strings.Contains(c.calls(), "api -X PATCH repos/o/self/issues/42 -F body=@") || strings.Contains(c.calls(), "issue create") {
		t.Errorf("exit %d, calls %q:\n%s", code, c.calls(), out)
	}
}

// tagPattern replaces the config with one that limits the tags to a pattern.
func (c *loaderCheck) tagPattern(pattern string) {
	c.t.Helper()
	cfg, err := json.Marshal(map[string]any{"agents": []map[string]any{{
		"agent": "demo", "repo": "o/r", "reviewed_tag": "v1", "tag_pattern": pattern, "files": []string{"src/a.ts"},
	}}})
	if err != nil {
		c.t.Fatal(err)
	}
	c.write("config.json", string(cfg))
}

// The newest release of the repository is another product, then a nightly and
// a draft; the check has to skip them and take the newest matching full release.
func TestAgentLoaders_TagPattern(t *testing.T) {
	c := newLoaderCheck(t, "sdk-v9")
	c.tagPattern(`^v[0-9]+$`)
	c.write("releases", `[
		{"tag_name":"sdk-v9","draft":false,"prerelease":false},
		{"tag_name":"v3-nightly","draft":false,"prerelease":true},
		{"tag_name":"v4","draft":true,"prerelease":false},
		{"tag_name":"v3","draft":false,"prerelease":true},
		{"tag_name":"v2","draft":false,"prerelease":false},
		{"tag_name":"v1","draft":false,"prerelease":false}]`)
	c.write("repo/v1/src/a.ts", "old\n")
	c.write("repo/v2/src/a.ts", "new\n")
	out, code := c.run("DRY_RUN=true")
	if code != 0 || !strings.Contains(out, "between `v1` and `v2`") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestAgentLoaders_TagPatternMatchesNothing(t *testing.T) {
	c := newLoaderCheck(t, "sdk-v9")
	c.tagPattern(`^v[0-9]+$`)
	c.write("releases", `[{"tag_name":"sdk-v9","draft":false,"prerelease":false}]`)
	if out, code := c.run(); code == 0 || !strings.Contains(out, "unexpected release tag") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestAgentLoaders_Failures(t *testing.T) {
	t.Run("outage", func(t *testing.T) {
		c := newLoaderCheck(t, "v2")
		c.write("down", "")
		if out, code := c.run(); code == 0 || c.calls() != "" {
			t.Errorf("exit %d, calls %q:\n%s", code, c.calls(), out)
		}
	})
	t.Run("unexpected tag", func(t *testing.T) {
		c := newLoaderCheck(t, "$(id)")
		if out, code := c.run(); code == 0 || !strings.Contains(out, "unexpected release tag") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})
}
