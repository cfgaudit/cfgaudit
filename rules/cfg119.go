// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg119 struct{}

// CFG119 reports a repository script that an auto-run hook, task or MCP launch
// starts and that carries the markers of a malicious payload in combination
// (#1218): obfuscation, a download that is then run, a hunt for credentials
// or a dump of the environment. The pre-release corpus run for v1.20.0 found
// such an implant, started by a Claude Code SessionStart hook and a VS Code
// folder-open task at once, that the other rules reported only as a generic
// task and hook.
var CFG119 = &cfg119{}

func init() { All = append(All, CFG119) }

func (r *cfg119) ID() string { return "CFG119" }

// payloadCredFiles are the files that hold developer credentials.
const payloadCredFiles = `\.npmrc\b|\.aws/credentials|\.docker/config\.json|\.git-credentials|\.ssh/id_|\.config/gh/hosts` // #nosec G101 -- file names, no credential

var (
	// payloadObfIdentRe matches the hex identifiers an obfuscator gives
	// every variable (_0x4d2cd2). A hand-written or minified file has few.
	payloadObfIdentRe = regexp.MustCompile(`\b_0x[0-9a-f]{4,}\b`)
	// payloadRotationRe matches the loop an obfuscator emits to rotate its
	// string array into place before the code runs. It is there whatever the
	// identifiers are called (#1265); none of 886 minified bundles and large
	// node_modules files measured for #1265 contains it.
	payloadRotationRe = regexp.MustCompile(`while\s*\(\s*!!\s*\[\s*\]\s*\)\s*\{\s*try\s*\{`)
	// payloadCharCodeArrayRe, payloadFromCharCodeRe and payloadEvalRe find a
	// payload kept as an array of character codes that is turned into text and
	// run (#1270): `eval(...([40,100,118,...].map(c => String.fromCharCode(c))
	// ...))`. The array alone is not enough: 34 of 886 measured bundles carry
	// a large numeric table, none with fromCharCode and eval or Function.
	payloadFromCharCodeRe = regexp.MustCompile(`\bfromCharCode\b`)
	payloadEvalRe         = regexp.MustCompile(`\beval\s*\(|\bFunction\s*\(`)
	// payloadHexLitRe matches the hex literals an obfuscator uses as string
	// indices (f(0x1bf)).
	payloadHexLitRe = regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`)
	// payloadDownloadRe matches a download of a release asset, an archive or a
	// binary, or a runtime installer script.
	payloadDownloadRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `]*(?:/releases/download/|\.zip\b|\.tar\.gz\b|\.tgz\b|\.exe\b|\.bin\b|/install\.sh\b|bun\.sh/install|deno\.land/install)`)
	// payloadRunRe matches code that starts a process or makes a file executable.
	payloadRunRe = regexp.MustCompile(`\b(?:execFileSync|execSync|spawnSync|spawn|execFile|subprocess|os\.system|Start-Process|chmodSync|chmod)\b|\|\s*(?:ba|z)?sh\b`)
	// payloadTokenRe matches the prefixes of access tokens a stealer looks for.
	payloadTokenRe = regexp.MustCompile(`\b(?:ghp_|ghs_|gho_|ghu_|github_pat_|npm_[A-Za-z0-9]|AKIA[0-9A-Z]|xox[abprs]-)`)
	// payloadCredFileRe matches a name of such a file.
	payloadCredFileRe = regexp.MustCompile(payloadCredFiles)
	// payloadCredReadRe matches a line that opens a credential file. A skill's
	// scripts need it because payloadCredFileRe alone is mostly a name in a
	// list: on 13,559 corpus scripts, 2 of the 27 findings on such a name came
	// from a file that opens it (#1409).
	// The call and the name have to be close, within 200 characters, and a
	// name whose dot is escaped (`\.npmrc`) is a regular expression, as in a
	// redaction pattern list, not a file the line opens (#1680).
	payloadCredReadRe = regexp.MustCompile(`(?:\bopen\(|\breadFile(?:Sync)?\(|\.read_(?:text|bytes)\()[^\n]{0,200}[^\\\n](?:` + payloadCredFiles + `)|(?:^|[^\\])(?:` + payloadCredFiles + `)[^\n]{0,200}(?:\bopen\(|\breadFile(?:Sync)?\(|\.read_(?:text|bytes)\()`)
	// payloadEnvDumpRe matches code that reads the whole environment at once.
	payloadEnvDumpRe = regexp.MustCompile(`JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.items\(\)`)
	payloadEnvReadRe = regexp.MustCompile(`\bprocess\.env\b`)
	// payloadNetworkRe matches code that sends data out.
	payloadNetworkRe = regexp.MustCompile(`https?://|\bfetch\(|https?\.request\(|XMLHttpRequest|\bcurl\b|requests\.post|urllib\.request`)
	// payloadDecodeRe, payloadXorRe and payloadEncodedCallRe find a string
	// decoder (#1650): a function that turns a hex or base64 literal into
	// bytes and XORs them, called on many such literals, so that no path,
	// host or command shows in the file. The implant that prompted #1650 hid
	// its file names and commands behind ten lines of this shape, which none
	// of the obfuscator markers above sees.
	payloadDecodeRe = regexp.MustCompile(`Buffer\.from\([^)]*,\s*['"](?:hex|base64)['"]|\batob\(|bytes\.fromhex\(|\bb64decode\(|\bunhexlify\(`)
	payloadXorRe    = regexp.MustCompile(`[\w\]]\s*\^=|[\w\])]\s*\^\s*(?:0x[0-9a-fA-F]+|\d+|[A-Za-z_$][\w$]*\s*[\[(])`)
	// payloadEncodedCallRe matches a call with one hex literal of at least
	// eight digits (group 1 is the function).
	payloadEncodedCallRe = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\(\s*['"](?:[0-9a-fA-F]{2}){4,}['"]\s*\)`)
	// payloadDeadDropRe matches a public page that a payload reads its server
	// address from (#1650): a Telegram channel preview, a raw paste or a raw
	// gist. The address can then change without a commit.
	payloadDeadDropRe = regexp.MustCompile(`https?://(?:t\.me/s/|telegra\.ph/|pastebin\.com/raw/|paste\.ee/r/|rentry\.(?:co|org)/[\w-]+/raw|gist\.githubusercontent\.com/[^\s"'` + "`" + `]+/raw)`)
)

// payloadMaxCredReadLine is the longest line read for a credential file
// opened on it. A minified bundle is one line for the whole library, so a
// read call and a credential name anywhere in it meet on "the same line"
// (#1680: four of four sampled warnings were bundles and a pattern list).
const payloadMaxCredReadLine = 2048

// opensCredentialFile reports a line, of at most payloadMaxCredReadLine
// characters, that opens a credential file.
func opensCredentialFile(content string) bool {
	for line := range strings.SplitSeq(content, "\n") {
		if len(line) <= payloadMaxCredReadLine && payloadCredReadRe.MatchString(line) {
			return true
		}
	}
	return false
}

// payloadMinEncodedCalls is how many calls of one function on a hex literal
// make a string decoder (#1650).
const payloadMinEncodedCalls = 5

// xorDecoderCalls returns how often the most used function is called on a hex
// literal, when the file also decodes hex or base64 and XORs bytes.
func xorDecoderCalls(content string) int {
	if !payloadDecodeRe.MatchString(content) || !payloadXorRe.MatchString(content) {
		return 0
	}
	calls := map[string]int{}
	most := 0
	for _, m := range payloadEncodedCallRe.FindAllStringSubmatch(content, -1) {
		calls[m[1]]++
		most = max(most, calls[m[1]])
	}
	return most
}

// disguisedRunRe matches an interpreter started on a file with an extension.
// Groups: interpreter, flags, "run", path, extension. disguisedRuns keeps
// the ones whose extension is not a script's.
var disguisedRunRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(])(node|nodejs|bun|deno|python[0-9.]*|py|ruby|perl|php|bash|sh|zsh|dash|pwsh|powershell)(?:\.exe)?((?:\s+--?[A-Za-z][\w-]*)*)(\s+run)?\s+["']?([^\s"';&|<>]*?[^\s"';&|<>/]\.([A-Za-z0-9]{1,10}))["']?(?:[\s;&|)]|$)`)

// scriptExts are the extensions an interpreter runs for a legitimate reason.
// An interpreter started on anything else (a font, an image, a document, or
// an invented extension such as .orc) is a payload in disguise (#1265,
// #1267): the campaign that prompted this varies the extension from sample
// to sample, so a list of suspicious extensions would always lag behind.
var scriptExts = map[string]bool{
	"js": true, "mjs": true, "cjs": true, "ts": true, "mts": true, "cts": true, "jsx": true, "tsx": true,
	"py": true, "pyw": true, "pyz": true, "rb": true, "pl": true, "pm": true, "cgi": true,
	"php": true, "phar": true, "inc": true, "sh": true, "bash": true, "zsh": true, "ksh": true, "fish": true,
	"ps1": true, "psm1": true, "lua": true,
}

// disguiseKind names what a disguised payload pretends to be, with its article.
func disguiseKind(ext string) string {
	switch strings.ToLower(ext) {
	case "ttf", "otf", "woff", "woff2", "eot":
		return "a font"
	case "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico":
		return "an image"
	case "mp3", "mp4", "wav", "mov", "avi":
		return "a media file"
	case "pdf", "txt", "doc", "docx", "xls", "xlsx", "md", "csv":
		return "a document"
	}
	return "a file with a non-script extension"
}

// disguisedRuns reports each auto-run command of t that starts an
// interpreter on a non-script file. An obfuscated file that cfgaudit could
// read is named as such.
func disguisedRuns(t *Target) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, lc := range LaunchCommands(t) {
		for _, m := range disguisedRunRe.FindAllStringSubmatch(lc.Command, -1) {
			if scriptExts[strings.ToLower(m[5])] {
				continue
			}
			if m[3] != "" && !strings.Contains(m[4], "/") {
				continue // `bun run build.prod` names a package.json script
			}
			flags := strings.Fields(m[2])
			if slices.ContainsFunc(flags, func(f string) bool { return f == "-e" || f == "-c" || f == "-m" || f == "--eval" }) {
				continue // inline code or a module, not the file
			}
			path := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(m[4])), "./")
			if seen[lc.File+"\x00"+path] {
				continue
			}
			seen[lc.File+"\x00"+path] = true
			msg := lc.Label + " starts " + m[1] + " on " + path + ", a file whose extension (." + strings.ToLower(m[5]) + ") is not a script: a payload disguised as " + disguiseKind(m[5])
			for _, s := range t.LaunchedScripts {
				if f := filepath.ToSlash(s.File); f == path || strings.HasSuffix(f, "/"+path) {
					if sm := scanPayload(s.Content); sm.obfuscated {
						msg += "; the file is obfuscated (" + sm.obfShape + ")"
					}
				}
			}
			msg += ". No interpreter runs " + disguiseKind(m[5]) + " for a legitimate reason; do not open the repository with an agent or editor until you have read the file, and if nobody in the project added it, treat the repository as compromised"
			out = append(out, finding.Finding{RuleID: "CFG119", Severity: finding.Error, File: lc.File, Message: msg})
		}
	}
	return out
}

// payloadMarkers are what CFG119 found in one script.
type payloadMarkers struct {
	obfuscated, fetchRun, credentials, credRead, envDump, deadDrop bool
	idents, envReads                                               int
	// obfShape names the obfuscation that was found, for the message.
	obfShape string
}

// The hex-literal density, per 1,000 characters, above which a file with a
// very long line counts as obfuscated (#1265). Minified bundles stay below
// it: of 886 measured, the densest with a line of 5,000 characters or more
// had under 5; the obfuscated payload that prompted #1265 had 8.8.
const (
	payloadHexDensity = 5
	payloadLongLine   = 5000
	payloadMinHexLits = 100
)

// charCodeArray reports whether s holds an array literal of at least 1,000
// numbers of up to three digits, the shape of text kept as character codes
// (#1270).
func charCodeArray(s string) bool {
	const minCodes = 1000
	for i := strings.IndexByte(s, '['); i >= 0; {
		codes, digits, j := 0, 0, i+1
	scan:
		for ; j < len(s); j++ {
			switch c := s[j]; {
			case c >= '0' && c <= '9':
				digits++
				if digits > 3 {
					break scan
				}
			case c == ',':
				if digits > 0 {
					codes++
				}
				digits = 0
			case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			default:
				break scan
			}
		}
		if codes+1 >= minCodes {
			return true
		}
		next := strings.IndexByte(s[j:], '[')
		if next < 0 {
			return false
		}
		i = j + next
	}
	return false
}

func longestLine(s string) int {
	n := 0
	for line := range strings.SplitSeq(s, "\n") {
		n = max(n, len(line))
	}
	return n
}

func scanPayload(content string) payloadMarkers {
	var m payloadMarkers
	m.idents = len(payloadObfIdentRe.FindAllStringIndex(content, -1))
	hexLits := len(payloadHexLitRe.FindAllStringIndex(content, -1))
	switch {
	case m.idents >= 30:
		m.obfuscated, m.obfShape = true, strconv.Itoa(m.idents)+" _0x identifiers"
	case payloadRotationRe.MatchString(content):
		m.obfuscated, m.obfShape = true, "an obfuscator's string-array rotation loop"
	case payloadFromCharCodeRe.MatchString(content) && payloadEvalRe.MatchString(content) && charCodeArray(content):
		m.obfuscated, m.obfShape = true, "code kept as an array of character codes and run with eval"
	case hexLits >= payloadMinHexLits && hexLits*1000 >= payloadHexDensity*len(content) && longestLine(content) >= payloadLongLine:
		m.obfuscated, m.obfShape = true, strconv.Itoa(hexLits)+" hex literals in a line of "+strconv.Itoa(longestLine(content))+" characters"
	default:
		if n := xorDecoderCalls(content); n >= payloadMinEncodedCalls {
			m.obfuscated, m.obfShape = true, "a XOR string decoder called on "+strconv.Itoa(n)+" hex literals"
		}
	}
	m.deadDrop = payloadDeadDropRe.MatchString(content)
	m.fetchRun = payloadDownloadRe.MatchString(content) && payloadRunRe.MatchString(content)
	network := payloadNetworkRe.MatchString(content)
	m.credentials = network && (payloadTokenRe.MatchString(content) || payloadCredFileRe.MatchString(content))
	m.credRead = network && opensCredentialFile(content)
	m.envReads = len(payloadEnvReadRe.FindAllStringIndex(content, -1))
	m.envDump = network && (payloadEnvDumpRe.MatchString(content) || m.envReads >= 50)
	return m
}

func (m payloadMarkers) describe() string {
	var parts []string
	if m.obfuscated {
		parts = append(parts, "it is obfuscated ("+m.obfShape+")")
	}
	if m.fetchRun {
		parts = append(parts, "it downloads a release asset, archive, binary or runtime and runs code")
	}
	switch {
	case m.credRead:
		parts = append(parts, "it opens credential files and talks to the network")
	case m.credentials:
		parts = append(parts, "it looks for access tokens or credential files and talks to the network")
	}
	if m.envDump {
		parts = append(parts, "it reads the whole environment and talks to the network")
	}
	if m.deadDrop {
		parts = append(parts, "it reads its server address from a public channel or paste (a dead drop), so the address can change without a commit")
	}
	return strings.Join(parts, "; ")
}

// toolsOf counts the different tools among the launcher files: the config
// directory, or the file name for a root-level file (.mcp.json).
func toolsOf(launchers []string) int {
	seen := map[string]bool{}
	for _, l := range launchers {
		d := filepath.ToSlash(filepath.Dir(l))
		if d == "." {
			d = filepath.Base(l)
		}
		seen[strings.SplitN(d, "/", 2)[0]] = true
	}
	return len(seen)
}

// Check reports at error a script with obfuscation and any other marker, an
// obfuscated script that several tools start, one with a download-and-run
// step or a dead drop and a credential hunt, one that a session start or
// folder open launches and that opens credential files and talks to the
// network, and one with any marker that an agent ignore file hides; at warn
// a script with one other marker that several tools start, since starting
// the same script from a VS Code task and an agent hook is rare in a
// legitimate repository and the usual way an implant makes sure it runs, or
// that a session start or folder open launches.
func (r *cfg119) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	findings := disguisedRuns(t)
	for _, s := range t.LaunchedScripts {
		m := scanPayload(s.Content)
		other := m.fetchRun || m.credentials || m.envDump || m.deadDrop
		if s.Skill != "" {
			// One marker is not enough here: a skill's scripts name tokens,
			// credential files and release URLs for good reasons, which gave
			// 180 findings on 13,559 corpus scripts, nearly all benign (#1409).
			// A shell script has the line rules instead.
			if !s.isShell() && (m.obfuscated || (m.fetchRun && m.credentials) || m.credRead) {
				findings = append(findings, finding.Finding{RuleID: "CFG119", Severity: finding.Warn, File: s.File,
					Message: s.Label + " carries the markers of a malicious payload: " + m.describe() + ". Read it before the agent runs it"})
			}
			continue
		}
		tools := toolsOf(s.Launchers)
		hidden := s.HiddenBy != "" && (m.obfuscated || other)
		var sev finding.Severity
		switch {
		case m.obfuscated && other, (m.fetchRun || m.deadDrop) && (m.credentials || m.envDump):
			sev = finding.Error
		case m.obfuscated && tools >= 2:
			// Hidden code that several tools start: a payload whose strings
			// are all encoded shows no other marker (#1270).
			sev = finding.Error
		case s.ZeroClick && m.credRead, hidden:
			// A script that runs when the repository is opened and reads
			// the user's credentials, or that the repository hides from the
			// agent asked to review it (#1650).
			sev = finding.Error
		case (m.obfuscated || other) && tools >= 2, s.ZeroClick && (m.credentials || m.envDump):
			sev = finding.Warn
		default:
			continue
		}
		msg := s.Label + " carries the markers of a malicious payload: " + m.describe()
		if s.Partial {
			msg += " (the file is " + strconv.FormatInt(s.Size>>20, 10) + " MB, over the read limit, so only its first and last 64 KB were read)"
		}
		if tools >= 2 {
			msg += "; it is started from " + strconv.Itoa(tools) + " tools' configuration (" + strings.Join(s.Launchers, ", ") + ")"
		}
		if s.ZeroClick {
			msg += "; it runs as soon as the repository is opened or a session starts"
		}
		if hidden {
			msg += "; " + s.HiddenBy + " keeps the agent from reading it or its launcher, so an agent asked to review the repository does not see it"
		}
		msg += ". A committed script that runs when the repository is opened must not hide what it does; read it before you open the repository with an agent or editor, and if nobody in the project added it, treat the repository as compromised"
		findings = append(findings, finding.Finding{RuleID: "CFG119", Severity: sev, File: s.File, Message: msg})
	}
	return findings
}
