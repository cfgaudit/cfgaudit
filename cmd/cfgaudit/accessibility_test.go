// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #1624, ACCESSIBILITY.md: the text and table output carry each finding's
// severity as a word, never through colour alone. Colour off (--no-color,
// NO_COLOR, a non-terminal) emits no ANSI escape; colour on only adds to the
// words.
func TestOutput_SeverityIsTextNotColourAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	// CFG001 error, CFG002 warn, CFG067 info.
	settings := `{"permissions":{"allow":["Bash","Edit(./**)"]},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"go vet ./..."}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	const esc = "\x1b["
	scan := func(format string, extra ...string) string {
		var out bytes.Buffer
		args := append([]string{"cfgaudit", "--claude-version", "2.1.312", "-config", os.DevNull, "-format", format}, extra...)
		var errOut bytes.Buffer
		if code := run(append(args, dir), strings.NewReader(""), &out, &errOut); code != 1 {
			t.Fatalf("%s %v: exit code %d, want 1:\n%s", format, extra, code, errOut.String())
		}
		return out.String()
	}
	for _, format := range []string{"text", "table"} {
		t.Setenv("FORCE_COLOR", "")
		t.Setenv("CLICOLOR_FORCE", "")
		t.Setenv("NO_COLOR", "")
		plain := scan(format) // not a terminal: colour off by default
		noColor := scan(format, "-no-color")
		t.Setenv("FORCE_COLOR", "1")
		colored := scan(format)
		t.Setenv("NO_COLOR", "1")
		envOff := scan(format) // NO_COLOR wins over FORCE_COLOR
		for name, out := range map[string]string{"non-terminal": plain, "-no-color": noColor, "NO_COLOR": envOff} {
			if strings.Contains(out, esc) {
				t.Errorf("%s, %s: colour off but output has an ANSI escape:\n%q", format, name, out)
			}
		}
		if !strings.Contains(colored, esc) {
			t.Errorf("%s: FORCE_COLOR=1 but no ANSI escape:\n%q", format, colored)
		}
		for name, out := range map[string]string{"colour off": plain, "colour on": colored} {
			for _, word := range []string{"error", "warn", "info"} {
				if !strings.Contains(out, word) {
					t.Errorf("%s, %s: severity word %q missing:\n%s", format, name, word, out)
				}
			}
		}
	}
}
