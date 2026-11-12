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
		{"obfuscated alone, two tools", obf, []string{".claude/settings.json", ".vscode/tasks.json"}, finding.Error}, // #1270: hidden code that several tools start
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
		// Any non-script extension, including invented ones (#1267).
		"node ./x/public/fonts/fa-brand-400.orc": "a file with a non-script extension",
		"node dist/index.js":                     "",
		"bun run src/main.tsx":                   "",
		"bun run build.prod":                     "",
		"python app.pyz":                         "",
		"perl cgi-bin/x.cgi":                     "",
		"node server":                            "",
		"node app.config.js":                     "",
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

// A payload kept as an array of character codes and run with eval (#1270).
// A large numeric table without fromCharCode and eval is not one.
func TestScanPayload_CharCodeArray(t *testing.T) {
	codes := strings.TrimSuffix(strings.Repeat("40,100,118,98,113,", 250), ",")
	payload := "try{eval(function(s,n){return s}([" + codes + "].map(function(c){return String.fromCharCode(c)}).join(\"\"),23))}catch(e){}"
	if m := scanPayload(payload); !m.obfuscated || !strings.Contains(m.obfShape, "character codes") {
		t.Errorf("char-code payload: %+v", m)
	}
	if m := scanPayload("var crcTable=[" + codes + "];function crc(b){return crcTable[b&255]}"); m.obfuscated {
		t.Errorf("lookup table: %+v", m)
	}
	short := strings.TrimSuffix(strings.Repeat("40,100,", 300), ",")
	if m := scanPayload("eval([" + short + "].map(function(c){return String.fromCharCode(c)}).join(''))"); m.obfuscated {
		t.Errorf("600 codes: %+v", m)
	}
	// A short array before the long one is skipped, and several short ones
	// are not one.
	if !charCodeArray("x=[1,2]; y=["+codes+"]") || charCodeArray("[1,2] and [3,4] and [5]") {
		t.Error("charCodeArray across arrays")
	}
	if !charCodeArray("["+codes+"]") || charCodeArray("[1,2,3]") || charCodeArray("[1000,2000]") {
		t.Error("charCodeArray")
	}
}

// A XOR string decoder: hex literals turned into bytes and XORed, called on
// many literals (#1650). The placeholders decode to nothing in particular.
const cfg119Decoder = "function _d(h){const b=Buffer.from(h,'hex');for(let i=0;i<b.length;i++)b[i]^=0x5a;return b.toString()}\n" +
	"const a=_d('3f2b1a170e7c505d'),b=_d('2b7f424e49494e15'),c=_d('150538213d57614e'),d=_d('083d1e06287c664c'),e=_d('2a2709113e7f6e5b');\n"

func TestScanPayload_XorDecoder1650(t *testing.T) {
	if m := scanPayload(cfg119Decoder); !m.obfuscated || !strings.Contains(m.obfShape, "XOR string decoder called on 5 hex literals") {
		t.Errorf("decoder: %+v", m)
	}
	for name, s := range map[string]string{
		"four calls":    strings.Replace(cfg119Decoder, ",e=_d('2a2709113e7f6e5b')", "", 1),
		"no XOR":        strings.Replace(cfg119Decoder, "b[i]^=0x5a", "b[i]+=1", 1),
		"no decode":     strings.Replace(cfg119Decoder, "Buffer.from(h,'hex')", "h.split('')", 1),
		"hash literals": "const crypto=require('crypto');x=Buffer.from(s,'hex');y=a^b;" + strings.Repeat("check('deadbeef');", 3) + strings.Repeat("other('cafebabe');", 3),
	} {
		if m := scanPayload(s); m.obfuscated {
			t.Errorf("%s: %+v", name, m)
		}
	}
}

func TestScanPayload_DeadDrop1650(t *testing.T) {
	for _, s := range []string{
		`const CH=["https://t.me/s/some_channel"]`,
		`get("https://pastebin.com/raw/AbCd1234")`,
		`fetch("https://gist.githubusercontent.com/u/0123abcd/raw/x.txt")`,
	} {
		if !scanPayload(s).deadDrop {
			t.Errorf("%s: want a dead drop", s)
		}
	}
	for _, s := range []string{`"https://t.me/project_news"`, `"https://pastebin.com/AbCd1234"`, `"https://gist.github.com/u/0123abcd"`} {
		if scanPayload(s).deadDrop {
			t.Errorf("%s: not a dead drop", s)
		}
	}
}

func TestCFG119_ZeroClickAndHidden1650(t *testing.T) {
	const credRead = "const k=fs.readFileSync(path.join(home,'.npmrc'));https.request('https://x')" // #nosec G101 -- a test fixture, no credential
	const credName = "const files=['.npmrc','.git-credentials'];fetch('https://x')"                 // #nosec G101 -- a test fixture, no credential
	one := []string{".claude/settings.json"}
	for _, tc := range []struct {
		name, content string
		zero          bool
		hidden        string
		want          finding.Severity
	}{
		{"zero-click opens credentials", credRead, true, "", finding.Error},
		{"zero-click names credentials", credName, true, "", finding.Warn},
		{"zero-click environment dump", "JSON.stringify(process.env);fetch('https://x')", true, "", finding.Warn},
		{"other hook opens credentials", credRead, false, "", ""},
		{"zero-click, no marker", "console.log('hi')", true, "", ""},
		{"hidden with a marker", credName, false, ".claudeignore:2 (x.js)", finding.Error},
		{"hidden without a marker", "console.log('hi')", false, ".claudeignore:2 (x.js)", ""},
		{"dead drop and credentials", credName + ";u='https://t.me/s/c'", false, "", finding.Error},
		{"dead drop alone", "u='https://t.me/s/c'", false, "", ""},
		{"decoder and credentials", cfg119Decoder + credName, false, "", finding.Error},
	} {
		tg := &Target{LaunchedScripts: []LaunchedScript{{Label: "script x.js, started by the hooks.SessionStart command,", File: "x.js", Content: tc.content, Launchers: one, ZeroClick: tc.zero, HiddenBy: tc.hidden}}}
		f := CFG119.Check(tg)
		var got finding.Severity
		if len(f) == 1 {
			got = f[0].Severity
		}
		if got != tc.want || len(f) > 1 {
			t.Errorf("%s: got %v (%d findings), want %q", tc.name, got, len(f), tc.want)
			continue
		}
		if tc.hidden != "" && got != "" && !strings.Contains(f[0].Message, tc.hidden+" keeps the agent from reading it") {
			t.Errorf("%s: message should quote the ignore line: %s", tc.name, f[0].Message)
		}
		if tc.zero && got != "" && !strings.Contains(f[0].Message, "runs as soon as the repository is opened") {
			t.Errorf("%s: message should name the zero-click start: %s", tc.name, f[0].Message)
		}
	}
}

func TestZeroClickLaunch1650(t *testing.T) {
	for label, want := range map[string]bool{
		"hooks.SessionStart command":                     true,
		"Cursor hooks.sessionStart command":              true,
		"Gemini hooks.SessionStart command":              true,
		"VS Code folderOpen task \"init\" command":       true,
		"hooks.PreToolUse command":                       false,
		"hooks.UserPromptSubmit command":                 false,
		"skill frontmatter hooks.SessionStart command":   false,
		"mcpServers.x command":                           false,
		"Cursor hooks.sessionStartSomethingElse command": false,
	} {
		if ZeroClickLaunch(label) != want {
			t.Errorf("ZeroClickLaunch(%q) != %v", label, want)
		}
	}
}

// CFG119 does not treat interpreter version arguments or supported flags with
// values as the file being run (#1649).
func TestCFG119_DisguisedRunVersionArgs(t *testing.T) {
	for _, cmd := range []string{
		"node --env-file=.env server.js",
		"node --env-file-if-exists=.env server.js",
		"py -3.14 tools/run.py",
		"py -3.13 tools/run.py",
		"py -3.11 tools/run.py",
		"Python 3.9",
		"Node 22.18",
	} {
		tg := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":`+strconv.Quote(cmd)+`}]}]}}`)
		if f := CFG119.Check(tg); len(f) != 0 {
			t.Errorf("%q: want no finding, got %+v", cmd, f)
		}
	}
	for _, cmd := range []string{
		"node ./public/fonts/fa-brands-400.ttf",
		"node --no-warnings ./x/fa-solid-900.woff2",
	} {
		tg := settingsTarget(t, `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":`+strconv.Quote(cmd)+`}]}]}}`)
		if f := CFG119.Check(tg); len(f) == 0 || f[0].Severity != finding.Error {
			t.Errorf("%q: want one error, got %+v", cmd, f)
		}
	}
}
