// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestWrapperVerifiesDownload runs the plugin wrapper bin/cfgaudit against a
// fake curl that serves local fixtures, with a PATH that holds only the tools
// the script needs. A download is run only when its SHA-256 matches its entry
// in checksums.txt; no hashing tool or no entry refuses it like a mismatch
// (#768).
func TestWrapperVerifiesDownload(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the wrapper downloads binaries for linux and darwin only")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("no release archive for " + runtime.GOARCH)
	}
	wrapper, err := filepath.Abs(filepath.Join("bin", "cfgaudit"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(wrapper) // #nosec G304 -- fixed path in this repository
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^VERSION="([^"]+)"$`).FindSubmatch(src)
	if m == nil {
		t.Fatal("no VERSION line in bin/cfgaudit")
	}
	asset := "cfgaudit_" + string(m[1]) + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	archive := wrapperArchive(t, "#!/bin/sh\necho wrapped-ok \"$@\"\n")
	sum := sha256.Sum256(archive)
	good := hex.EncodeToString(sum[:])

	tests := []struct {
		name      string
		checksums string
		hasher    bool
		wantErr   string
	}{
		{"match", good + "  " + asset + "\n", true, ""},
		{"mismatch", strings.Repeat("0", 64) + "  " + asset + "\n", true, "checksum mismatch"},
		{"no entry", good + "  cfgaudit_0.0.0_other.tar.gz\n", true, "has no entry"},
		{"no hashing tool", good + "  " + asset + "\n", false, "neither sha256sum nor shasum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			fixtures := filepath.Join(dir, "fixtures")
			mustWrite(t, filepath.Join(fixtures, asset), archive, 0o600)
			mustWrite(t, filepath.Join(fixtures, "checksums.txt"), []byte(tt.checksums), 0o600)
			tools := filepath.Join(dir, "tools")
			wrapperTools(t, tools, tt.hasher)

			cmd := exec.Command("/bin/sh", wrapper, "--version") // #nosec G204 -- fixed script in this repository
			cmd.Env = []string{
				"PATH=" + tools,
				"HOME=" + dir,
				"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"),
				"FIXTURES=" + fixtures,
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			cached, _ := filepath.Glob(filepath.Join(dir, "cache", "cfgaudit", "cfgaudit-*"))
			if tt.wantErr == "" {
				if err != nil || !strings.Contains(stdout.String(), "wrapped-ok --version") {
					t.Fatalf("want the verified binary to run, got err=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				if len(cached) != 1 {
					t.Fatalf("want the verified binary cached, got %v", cached)
				}
				return
			}
			if err == nil || !strings.Contains(stderr.String(), tt.wantErr) {
				t.Fatalf("want refusal %q, got err=%v stderr=%q", tt.wantErr, err, stderr.String())
			}
			if strings.Contains(stdout.String(), "wrapped-ok") || len(cached) != 0 {
				t.Fatalf("unverified binary ran or was cached: stdout=%q cache=%v", stdout.String(), cached)
			}
		})
	}
}

// wrapperArchive returns a release-shaped .tar.gz holding a cfgaudit script.
func wrapperArchive(t *testing.T, script string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "cfgaudit", Mode: 0o755, Size: int64(len(script))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// wrapperTools fills dir with links to the host tools the wrapper uses, a fake
// curl that copies from $FIXTURES, and sha256sum/shasum only when hasher is set.
func wrapperTools(t *testing.T, dir string, hasher bool) {
	t.Helper()
	names := []string{"uname", "tr", "dirname", "mktemp", "rm", "grep", "awk", "tar", "gzip", "mkdir", "mv", "chmod", "cat"}
	if hasher {
		names = append(names, "sha256sum", "shasum")
	}
	linked := map[string]bool{}
	for _, name := range names {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		linked[name] = true
	}
	if hasher && !linked["sha256sum"] && !linked["shasum"] {
		t.Skip("no sha256sum or shasum on this host")
	}
	curl := "#!/bin/sh\n# curl -fsSL URL -o DEST\ncat \"$FIXTURES/${2##*/}\" > \"$4\"\n"
	mustWrite(t, filepath.Join(dir, "curl"), []byte(curl), 0o755)
}

func mustWrite(t *testing.T, name string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil { // #nosec G703 -- name is under t.TempDir()
		t.Fatal(err)
	}
	if err := os.WriteFile(name, b, mode); err != nil { // #nosec G703 -- name is under t.TempDir()
		t.Fatal(err)
	}
}
