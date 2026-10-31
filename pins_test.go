// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var (
	wrapperVersionRe = regexp.MustCompile(`(?m)^VERSION="([^"]+)"$`)
	// A GitLab component reference or the release image, as the README,
	// docs, templates and action.yml pin them.
	componentPinRe = regexp.MustCompile(`gitlab\.com/cfgaudit/cfgaudit/[a-z-]+@v(\d+\.\d+\.\d+)`)
	imagePinRe     = regexp.MustCompile(`ghcr\.io/cfgaudit/cfgaudit:(\d+\.\d+\.\d+)(@sha256:[0-9a-f]+)?`)
	templateDefRe  = regexp.MustCompile(`(?m)^\s+default: "(\d+\.\d+\.\d+)"$`)
)

// TestVersionPinsAgree checks that every place the release pull request moves
// to the new version pins the same one (#1104), so the Action, the plugin and
// the GitLab components never run an older release than the one tagged. The
// version in bin/cfgaudit is the reference. RELEASING.md lists the same
// places under "Version pins".
func TestVersionPinsAgree(t *testing.T) {
	data, err := os.ReadFile("bin/cfgaudit")
	if err != nil {
		t.Fatal(err)
	}
	m := wrapperVersionRe.FindSubmatch(lf(data))
	if m == nil {
		t.Fatal(`bin/cfgaudit: no VERSION="X.Y.Z" line`)
	}
	want := string(m[1])

	var plugin struct{ Version string }
	data, err = os.ReadFile(".claude-plugin/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &plugin); err != nil {
		t.Fatal(err)
	}
	if plugin.Version != want {
		t.Errorf(".claude-plugin/plugin.json: version %q, bin/cfgaudit has %q", plugin.Version, want)
	}

	// Each file must pin at least once, so a pin that was rewritten into a
	// form the patterns miss fails here instead of passing silently.
	required := map[string]bool{
		"action.yml":                          true,
		"templates/cfgaudit.yml":              true,
		"templates/cfgaudit-code-quality.yml": true,
		"README.md":                           true,
	}
	out, err := exec.Command("git", "ls-files", "-z", "*.md", "*.yml", "*.yaml").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		// Fixtures are scanned input, and the changelog names old releases
		// on purpose.
		if strings.Contains(path, "testdata/") || path == "CHANGELOG.md" {
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec // a tracked file of this repository
		if err != nil {
			t.Fatal(err)
		}
		text := string(lf(data))
		var found []string
		for _, m := range componentPinRe.FindAllStringSubmatch(text, -1) {
			found = append(found, m[1])
		}
		for _, m := range imagePinRe.FindAllStringSubmatch(text, -1) {
			// A digest-pinned image is a deliberate, immutable pin (the
			// repository's own GitLab pipeline), not one the release moves.
			if m[2] == "" {
				found = append(found, m[1])
			}
		}
		if strings.HasPrefix(path, "templates/") {
			for _, m := range templateDefRe.FindAllStringSubmatch(text, -1) {
				found = append(found, m[1])
			}
		}
		if required[path] && len(found) == 0 {
			t.Errorf("%s: no version pin found; update the patterns in this test if the pin moved", path)
		}
		for _, v := range found {
			if v != want {
				t.Errorf("%s: pins %s, bin/cfgaudit has %s; move every pin in the release pull request (RELEASING.md, Version pins)", path, v, want)
			}
		}
	}
}

// lf turns CRLF line ends into LF: a Windows checkout with core.autocrlf has
// them, and the patterns anchor on the end of the line.
func lf(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}
