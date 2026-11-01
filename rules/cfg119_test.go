// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG119_Severity(t *testing.T) {
	obf := strings.Repeat("_0x4d2c1a ", 30)
	for _, tc := range []struct {
		name, content string
		launchers     []string
		want          finding.Severity
	}{
		{"obfuscated plus token hunt", obf + "ghp_ fetch(", []string{".claude/settings.json"}, finding.Error},
		{"obfuscated plus environment dump", obf + "JSON.stringify(process.env) https://x", []string{".claude/settings.json"}, finding.Error},
		{"download and run plus credentials", "https://x/releases/download/a.zip execSync .npmrc", []string{".claude/settings.json"}, finding.Error},
		{"obfuscated alone, one tool", obf, []string{".claude/settings.json"}, ""},
		{"obfuscated alone, two tools", obf, []string{".claude/settings.json", ".vscode/tasks.json"}, finding.Warn},
		{"download and run, two tools", "https://x/releases/download/a.zip execFileSync", []string{".claude/settings.json", ".vscode/tasks.json"}, finding.Warn},
		{"token prefix without network", "const re = /ghp_/", []string{".claude/settings.json", ".vscode/tasks.json"}, ""},
		{"29 obfuscator identifiers", strings.Repeat("_0x4d2c1a ", 29) + "ghp_ fetch(", []string{".claude/settings.json"}, ""},
	} {
		tg := &Target{LaunchedScripts: []LaunchedScript{{Label: "script x.js, started by the hooks.SessionStart command,", File: "x.js", Content: tc.content, Launchers: tc.launchers}}}
		f := CFG119.Check(tg)
		var got finding.Severity
		if len(f) == 1 {
			got = f[0].Severity
		}
		if got != tc.want || len(f) > 1 {
			t.Errorf("%s: got %v (%d findings), want %q", tc.name, got, len(f), tc.want)
		}
	}
}

// Obfuscation without _0x identifiers: the rotation loop, or a dense run of
// hex literals in one very long line (#1265). A long minified line with a
// few hex numbers is not.
func TestScanPayload_ObfuscationShapes(t *testing.T) {
	rotation := "(function(a,b){var c=d,e=a();while(!![]){try{var f=-parseInt(c(0x1bf))/0x1;if(f===b)break;e['push'](e['shift']());}catch(g){e['push'](e['shift']());}}}(h,0x3c2a1));"
	if m := scanPayload(rotation); !m.obfuscated || !strings.Contains(m.obfShape, "rotation loop") {
		t.Errorf("rotation loop: %+v", m)
	}
	dense := "var q=" + strings.Repeat("r(0x1c4)+", 1200) + "0;"
	if m := scanPayload(dense); !m.obfuscated || !strings.Contains(m.obfShape, "hex literals") {
		t.Errorf("dense hex: %+v", m)
	}
	// About one hex literal per 300 characters, the density of the densest
	// real bundles measured for #1265.
	minified := strings.Repeat("function n(t){return t.map(function(e){return e*2}).filter(Boolean).reduce(function(a,b){return a+b},0)}function r(t,e){if(!t)throw new Error('x');return Object.assign({},t,e)}var u=typeof window!=='undefined'?window:globalThis;u.lib={n:n,r:r};var o=0xff;", 200)
	if m := scanPayload(minified); m.obfuscated {
		t.Errorf("minified: %+v", m)
	}
	if m := scanPayload(strings.Repeat("r(0x1c4)+\n", 1200)); m.obfuscated {
		t.Errorf("hex literals on short lines: %+v", m)
	}
}

// Each kind of disguise is named, and inline code is not a file (#1265).
func TestCFG119_DisguiseKinds(t *testing.T) {
	for cmd, want := range map[string]string{
		"node assets/logo.png":           "disguised as an image",
		"python3 docs/guide.pdf":         "disguised as a document",
		"bash media/intro.mp4":           "disguised as a media file",
		"bun run public/fonts/x.woff2":   "disguised as a font",
		"node -e \"require('x')\" a.png": "",
		"node scripts/build.js":          "",
	} {
		tg := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":`+strconv.Quote(cmd)+`}]}]}}`)
		f := CFG119.Check(tg)
		switch {
		case want == "" && len(f) != 0:
			t.Errorf("%q: want no finding, got %+v", cmd, f)
		case want != "" && (len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, want)):
			t.Errorf("%q: want one error with %q, got %+v", cmd, want, f)
		}
	}
}
