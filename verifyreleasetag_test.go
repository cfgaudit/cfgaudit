// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gitIn runs git in dir with a fixed identity and no user or system config.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed binary, arguments from the test
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// sshKey writes an ed25519 key pair and returns the private key path and the
// public key line.
func sshKey(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path).CombinedOutput(); err != nil { //nolint:gosec // G204: fixed binary, a path in the test's temp dir
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(path + ".pub") //nolint:gosec // G304: a path in the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(pub))
	return path, f[0] + " " + f[1]
}

// The release gate passes only a tag that points at the release commit and is
// signed by a key in the allowed signers file the workflow passes in, which
// comes from main, not from the tagged commit (#1098).
func TestVerifyReleaseTag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the gate runs on the Linux runner")
	}
	for _, tool := range []string{"bash", "git", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	tmp := t.TempDir()
	listed, listedPub := sshKey(t, tmp, "maintainer")
	other, otherPub := sshKey(t, tmp, "someone-else")
	signers := filepath.Join(tmp, "allowed_signers")
	if err := os.WriteFile(signers, []byte("maintainer@example.com "+listedPub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join(tmp, "repo")
	if err := os.Mkdir(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "init", "-q")
	// The tagged commit lists the other key itself; the gate must not read it.
	if err := os.MkdirAll(filepath.Join(repo, ".github"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".github", "allowed_signers"), []byte("x@example.com "+otherPub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "release")
	sha := gitIn(t, repo, "rev-parse", "HEAD")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "later")
	later := gitIn(t, repo, "rev-parse", "HEAD")

	sign := func(tag, key, commit string) {
		gitIn(t, repo, "-c", "gpg.format=ssh", "-c", "user.signingkey="+key, "tag", "-s", tag, "-m", tag, commit)
	}
	sign("v1.0.0", listed, sha)
	sign("v1.0.1", other, sha)
	gitIn(t, repo, "tag", "-a", "v1.0.2", "-m", "unsigned", sha)
	gitIn(t, repo, "tag", "v1.0.3", sha)
	sign("v1.0.4", listed, later)

	for _, tt := range []struct {
		name, tag, want string
		ok              bool
	}{
		{"signed by a listed key", "v1.0.0", "is signed by a listed key", true},
		{"signed by a key only the tagged commit lists", "v1.0.1", "not signed by a key in .github/allowed_signers", false},
		{"annotated but unsigned", "v1.0.2", "not signed by a key in .github/allowed_signers", false},
		{"lightweight", "v1.0.3", "lightweight tag", false},
		{"signed, but on another commit", "v1.0.4", "points at " + later, false},
		{"missing", "v9.9.9", "not found", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("bash", ".github/scripts/verify-release-tag.sh", "check", repo, tt.tag, sha, signers) //nolint:gosec // G204: fixed script, arguments from the test table
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
			out, err := cmd.CombinedOutput()
			if (err == nil) != tt.ok || !strings.Contains(string(out), tt.want) {
				t.Errorf("exit ok=%v, want %v; output does not contain %q:\n%s", err == nil, tt.ok, tt.want, out)
			}
		})
	}
}
