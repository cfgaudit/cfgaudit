// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg141 struct{}

// CFG141 reports a command that runs on its own (a hook, an MCP launch, a
// folder-open task, a `!` block, a status line) and decodes an encoded
// literal that is written into it: base64, base32 or hex (#1643). A reviewer
// sees only the encoded string while the agent runs what it decodes to.
// cfgaudit decodes the literal itself and never runs it.
var CFG141 = &cfg141{}

func init() { All = append(All, CFG141) }

func (r *cfg141) ID() string { return "CFG141" }

// Literal lengths from which a payload that is decoded but not run is
// reported. Shorter ones are constants such as a base64 user:password or a
// test string; the same floor as glsec's GL011 for CI scripts.
const (
	payloadMinEncoded = 60
	payloadMinHex     = 80
	payloadPreviewLen = 100
)

// embeddedPayload is one decoded literal in a command.
type embeddedPayload struct {
	form    string // how it is decoded: "base64 -d", "Buffer.from(…, 'base64')"
	enc     string // base64, base32 or hex
	literal string
	decoded []byte
	// run says how the decoded text is executed, "" when it is not.
	run string
}

// Check reports each auto-run command that decodes an embedded literal: at
// error when the decoded text is run or is dangerous on its own, at warn when
// it is only decoded and the literal is long enough to hide something.
func (r *cfg141) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	cmds := LaunchCommands(t)
	for i, lc := range cmds {
		if strings.HasSuffix(strings.ToLower(lc.File), ".md") && partECovers(lc.Command) {
			continue // a `!` block in a Markdown file: CFG036 Part E reports it
		}
		next := ""
		if i+1 < len(cmds) && cmds[i+1].File == lc.File && cmds[i+1].Label == lc.Label {
			next = cmds[i+1].Command
		}
		for _, p := range findPayloads(lc.Command, next) {
			sev, why := judgePayload(p)
			if sev == "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID: "CFG141", Severity: sev, File: lc.File,
				Message: lc.Label + " decodes an embedded " + p.enc + " payload (" + p.form + ", " + strconv.Itoa(len(p.literal)) + " characters)" + why +
					"; it decodes to " + payloadPreview(p.decoded) + ". Nobody reviewing the file can see what it does: write the command out, or commit the decoded file in readable form" + userScopeNote(t),
			})
		}
	}
	return findings
}

// judgePayload grades a decoded literal and says why.
func judgePayload(p embeddedPayload) (finding.Severity, string) {
	text := string(p.decoded)
	if p.run != "" {
		return finding.Error, " and " + p.run
	}
	if why := dangerousDecoded(text); why != "" {
		return finding.Error, ", and the decoded text " + why
	}
	min := payloadMinEncoded
	if p.enc == "hex" {
		min = payloadMinHex
	}
	if len(p.literal) < min {
		return "", ""
	}
	return finding.Warn, ""
}

// minerMarkersRe matches a crypto-miner configuration or command line.
var minerMarkersRe = regexp.MustCompile(`(?i)stratum\+(?:tcp|ssl|tls)://|"pools"\s*:\s*\[|donate-level|"algo"\s*:\s*"rx/0"|\bxmrig\b|\bcpuminer\b|(?:supportxmr|minexmr|moneroocean|nanopool|hashvault|c3pool|herominers|2miners|unmineable)\.(?:com|org|net|stream|pro)`)

// nestedBase64Re matches a run of base64 that a second layer could hide in.
var nestedBase64Re = regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`)

// dangerousDecoded says what makes the decoded text dangerous without being
// run here: a miner configuration, a reverse shell (CFG008), a download that
// is run (CFG014), a read of a credential path (CFG036 Part A), or a second
// encoded layer. "" when none.
func dangerousDecoded(text string) string {
	if minerMarkersRe.MatchString(text) {
		return "is a crypto-miner configuration or command"
	}
	if label, ok := matchReverseShell(text); ok {
		return "is a reverse shell (" + label + ")"
	}
	command := maskPrintedText(text)
	for _, p := range downloadExecPatterns {
		if p.re.MatchString(command) && (p.re != curlPipeInterpreterRe || pipesProgramToStdin(command)) {
			return "downloads and runs remote code (" + p.label + ")"
		}
	}
	if downloadThenRuns(command) {
		return "downloads a file and runs it"
	}
	if cmdSubstSensitiveRe.MatchString("$( " + text + ")") {
		return "reads a credential or key file"
	}
	for _, m := range nestedBase64Re.FindAllString(text, -1) {
		if _, ok := decodeLiteral(m, "base64"); ok {
			return "holds another encoded layer"
		}
	}
	return ""
}

// payloadPreview is the first line of the decoded text, at most
// payloadPreviewLen characters, quoted, or a note for binary data.
func payloadPreview(b []byte) string {
	if !utf8.Valid(b) {
		return strconv.Itoa(len(b)) + " bytes of binary data"
	}
	s := strings.TrimSpace(string(b))
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' {
			return strconv.Itoa(len(b)) + " bytes of binary data"
		}
	}
	if utf8.RuneCountInString(s) > payloadPreviewLen {
		s = string([]rune(s)[:payloadPreviewLen]) + "…"
	}
	return strconv.Quote(s)
}

// decodeLiteral decodes s in the named encoding; it must decode cleanly.
func decodeLiteral(s, enc string) ([]byte, bool) {
	switch enc {
	case "hex":
		s = strings.Join(strings.Fields(s), "")
		b, err := hex.DecodeString(s)
		return b, err == nil && len(b) > 0
	case "base32":
		b, err := base32.StdEncoding.DecodeString(strings.ToUpper(s))
		if err != nil {
			b, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s))
		}
		return b, err == nil && len(b) > 0
	default:
		for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := e.DecodeString(s); err == nil && len(b) > 0 {
				return b, true
			}
		}
		return nil, false
	}
}

// encodedLiteralRe gives the alphabet each encoding allows in a literal.
var encodedLiteralRe = map[string]*regexp.Regexp{
	"base64": regexp.MustCompile(`^[A-Za-z0-9+/_-]{4,}={0,2}$`),
	"base32": regexp.MustCompile(`^[A-Za-z2-7]{8,}={0,6}$`),
	"hex":    regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}\s?){4,}$`),
}

// literalPayload decodes w when it is a literal of the encoding, not a
// variable, a path or a substitution.
func literalPayload(w, enc string) ([]byte, bool) {
	if !encodedLiteralRe[enc].MatchString(w) {
		return nil, false
	}
	return decodeLiteral(w, enc)
}

// findPayloads returns the decoded literals of a command: shell pipelines
// (echo/printf or a here-string into a decoder) and inline interpreter code
// (Buffer.from, atob, b64decode, decode_base64, Base64.decode64). next is the
// following command of the same hook, task or block, which may run a file the
// command writes.
func findPayloads(command, next string) []embeddedPayload {
	out := shellPayloads(command, next, "")
	return append(out, inlinePayloads(command)...)
}

// statementSplit splits a command at ;, &&, || and newlines outside quotes
// and outside $( ).
func statementSplit(s string) []string {
	var out []string
	var quote byte
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\' && i+1 < len(s):
			i++
		case quote == '"' && c == '"':
			quote = 0
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			depth++
			i++
		case c == ')' && depth > 0:
			depth--
		case quote == 0 && depth == 0 && (c == ';' || c == '\n'):
			out = append(out, s[start:i])
			start = i + 1
		case quote == 0 && depth == 0 && (c == '&' || c == '|') && i+1 < len(s) && s[i+1] == c:
			out = append(out, s[start:i])
			start = i + 2
			i++
		}
	}
	return append(out, s[start:])
}

// pipeSplit splits a statement at single | outside quotes and $( ).
func pipeSplit(s string) []string {
	var out []string
	var quote byte
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\' && i+1 < len(s):
			i++
		case quote == '"' && c == '"':
			quote = 0
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			depth++
			i++
		case c == ')' && depth > 0:
			depth--
		case quote != '\'' && depth == 0 && c == '|':
			if quote == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// substitutions returns the $( ) spans of s, outermost first, with the text
// before each.
func substitutions(s string) (spans [][2]int) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
			continue
		case c == '\\':
			i++
			continue
		case c == '"':
			if quote == '"' {
				quote = 0
			} else {
				quote = '"'
			}
			continue
		case c == '\'' && quote == 0:
			quote = '\''
			continue
		}
		if c == '$' && i+1 < len(s) && s[i+1] == '(' {
			depth := 1
			for j := i + 2; j < len(s); j++ {
				switch s[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
				if depth == 0 {
					spans = append(spans, [2]int{i, j + 1})
					i = j
					break
				}
			}
		}
	}
	return spans
}

// payloadInterpreters run decoded text piped into them as code, unless they
// get their program another way (see takesOwnProgram).
var payloadInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"python": true, "python2": true, "python3": true, "ruby": true, "perl": true, "node": true,
	"pwsh": true, "powershell": true, "source": true, ".": true, "eval": true, "php": true,
}

// commandRunners are the wrappers that run the program after them.
var commandRunners = map[string]bool{"sudo": true, "doas": true, "env": true, "exec": true, "nohup": true, "command": true}

// segmentProgram returns the program a pipeline segment runs and its
// arguments, past wrappers and NAME=value assignments.
func segmentProgram(seg string) (string, []string) {
	words := shellWords(seg)
	for len(words) > 0 {
		w := words[0]
		switch {
		case strings.Contains(w, "=") && !strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "="):
			words = words[1:]
		case commandRunners[executableName(w)]:
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
		default:
			return executableName(w), words[1:]
		}
	}
	return "", nil
}

// takesOwnProgram reports an interpreter that gets its program from a flag or
// a script file, so text piped into it is data: `| python3 -c "import json"`,
// `| node script.js`, `| bash -c '…'`. `| sh -s`, `| python3 -` and `| bash`
// read the program from the pipe.
func takesOwnProgram(name string, args []string) bool {
	if name == "eval" || name == "source" || name == "." {
		return false
	}
	for _, a := range args {
		switch {
		case a == "-" || a == "--":
			return false
		case strings.HasPrefix(a, ">") || strings.HasPrefix(a, "<") || strings.HasPrefix(a, "2>"):
			continue
		case strings.HasPrefix(a, "--"):
			if a == "--eval" || a == "--print" || a == "--command" || strings.HasPrefix(a, "--eval=") {
				return true
			}
		case strings.HasPrefix(a, "-"):
			f := a[1:]
			switch {
			case strings.Contains(f, "s") && (name == "sh" || name == "bash" || name == "zsh" || name == "dash" || name == "ksh" || name == "ash"):
				return false
			case strings.ContainsAny(f, "cemEp"):
				return true
			}
		default:
			return true // a script file
		}
	}
	return false
}

// decoderSegment reports a pipeline segment that decodes its input and the
// encoding: base64/base32 -d, basenc --base64/--base32 -d, openssl base64 -d
// or openssl enc -base64 -d, xxd -r -p.
func decoderSegment(name string, args []string) (form, enc string, ok bool) {
	has := func(pred func(string) bool) bool {
		for _, a := range args {
			if pred(a) {
				return true
			}
		}
		return false
	}
	decodeFlag := func(a string) bool {
		return a == "-d" || a == "--decode" || a == "-D" || (len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], "dD"))
	}
	switch name {
	case "base64", "base32":
		if has(decodeFlag) {
			return name + " -d", name, true
		}
	case "basenc":
		if has(decodeFlag) {
			if has(func(a string) bool { return a == "--base32" }) {
				return "basenc --base32 -d", "base32", true
			}
			if has(func(a string) bool { return a == "--base64" || a == "--base64url" }) {
				return "basenc --base64 -d", "base64", true
			}
		}
	case "openssl":
		if has(func(a string) bool { return a == "base64" || a == "-base64" || a == "-a" }) && has(func(a string) bool { return a == "-d" }) {
			return "openssl base64 -d", "base64", true
		}
	case "xxd":
		if has(func(a string) bool {
			return len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a[1:], 'r')
		}) {
			return "xxd -r -p", "hex", true
		}
	}
	return "", "", false
}

// printedLiteral returns the literal an echo or printf segment prints.
func printedLiteral(seg, enc string) ([]byte, string, bool) {
	name, args := segmentProgram(seg)
	if name != "echo" && name != "printf" {
		return nil, "", false
	}
	for i, a := range args {
		if strings.HasPrefix(a, "-") || strings.Contains(a, "%") {
			continue // -n, -e, a printf format
		}
		if enc == "hex" {
			// xxd -r -p ignores whitespace, so the hex can span several words.
			joined := strings.Join(args[i:], "")
			b, ok := literalPayload(joined, enc)
			return b, joined, ok
		}
		b, ok := literalPayload(a, enc)
		return b, a, ok
	}
	return nil, "", false
}

// hereStringLiteralOf returns the literal of `decoder <<< 'literal'`.
func hereStringLiteralOf(seg, enc string) ([]byte, string, bool) {
	_, rest, ok := strings.Cut(seg, "<<<")
	if !ok {
		return nil, "", false
	}
	words := shellWords(rest)
	if len(words) == 0 {
		return nil, "", false
	}
	b, ok := literalPayload(words[0], enc)
	return b, words[0], ok
}

// payloadRedirectRe matches an output redirection to a file.
var payloadRedirectRe = regexp.MustCompile(`(?:^|[^0-9&<])>{1,2}\s*["']?([^\s"';&|<>]+)`)

// devNullOnlyRe matches a segment whose standard output goes to /dev/null.
var devNullOnlyRe = regexp.MustCompile(`(?:^|[^0-9&<])>{1,2}\s*/dev/null\b`)

// segmentRedirect returns the file a segment writes its output to, "" for
// none, /dev/null or a standard stream.
func segmentRedirect(seg string) string {
	for _, m := range payloadRedirectRe.FindAllStringSubmatch(seg, -1) {
		if target := m[1]; target != "/dev/null" && !strings.HasPrefix(target, "/dev/std") && !strings.HasPrefix(target, "&") {
			return target
		}
	}
	return ""
}

// substitutionRunsRe matches the text before a $( ) whose output is run:
// eval "$(…)", sh -c "$(…)", python3 -c "$(…)", node -e "$(…)".
var substitutionRunsRe = regexp.MustCompile(`(?:\beval|\b(?:ba|z|da|k)?sh\s+-\w*c\w*|\bpython[0-9.]*\s+-c|\bnode\s+(?:-e|--eval)|\bperl\s+-e|\bruby\s+-e)\s+["']?$`)

// shellPayloads finds echo/printf/here-string literals fed to a decoder in
// the shell part of command. ctx is the text before the $( ) command is in,
// "" at the top level.
func shellPayloads(command, next, ctx string) []embeddedPayload {
	var out []embeddedPayload
	// Inner $( ) first; their text is blanked for the outer pass.
	outer := []byte(command)
	for _, sp := range substitutions(command) {
		inner := command[sp[0]+2 : sp[1]-1]
		out = append(out, shellPayloads(inner, "", command[:sp[0]])...)
		for k := sp[0]; k < sp[1]; k++ {
			outer[k] = ' '
		}
	}
	statements := statementSplit(string(outer))
	for si, st := range statements {
		segs := pipeSplit(st)
		for k, seg := range segs {
			name, args := segmentProgram(seg)
			form, enc, ok := decoderSegment(name, args)
			if !ok {
				continue
			}
			decoded, literal, found := hereStringLiteralOf(seg, enc)
			if !found && k > 0 {
				decoded, literal, found = printedLiteral(segs[k-1], enc)
			}
			if !found {
				continue
			}
			if k+1 == len(segs) && devNullOnlyRe.MatchString(seg) {
				continue // decoded into /dev/null: nothing reads it
			}
			p := embeddedPayload{form: form, enc: enc, literal: literal, decoded: decoded}
			switch {
			case k+1 < len(segs):
				n, a := segmentProgram(segs[k+1])
				if payloadInterpreters[n] && !takesOwnProgram(n, a) {
					p.run = "pipes the decoded text into " + n
				}
			case segmentRedirect(seg) != "":
				target := segmentRedirect(seg)
				rest := strings.Join(statements[si+1:], "\n") + "\n" + next
				if runsFile(rest, target) {
					p.run = "writes it to " + target + ", which the command then runs"
				}
			case ctx != "" && substitutionRunsRe.MatchString(ctx):
				p.run = "passes the decoded text to " + strings.Fields(substitutionRunsRe.FindString(ctx))[0] + " as code"
			}
			out = append(out, p)
		}
	}
	return out
}

// runsFile reports whether text runs path as a program or script: sh f, bash
// f, python f, node f, source f, . f, or ./f and f itself as the command.
func runsFile(text, path string) bool {
	want := normPath(strings.Trim(path, `"'`))
	for _, st := range statementSplit(text) {
		for _, seg := range pipeSplit(st) {
			name, args := segmentProgram(seg)
			words := shellWords(seg)
			if len(words) > 0 && normPath(words[0]) == want && (strings.Contains(words[0], "/")) {
				return true
			}
			switch name {
			case "sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python2", "python3", "node", "ruby", "perl", "php", "source", ".", "pwsh", "powershell":
				for _, a := range args {
					if strings.HasPrefix(a, "-") {
						if runsCommandFlag(a) {
							break
						}
						continue
					}
					if normPath(a) == want {
						return true
					}
					break
				}
			}
		}
	}
	return false
}

// runsCommandFlag reports an interpreter flag that takes inline code, after
// which the next word is that code, not a file.
func runsCommandFlag(a string) bool {
	return a == "--eval" || a == "--command" || (len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], "ce"))
}

// Inline decode calls in interpreter code. Group 1 is the quoted literal.
var inlineDecodeForms = []struct {
	re   *regexp.Regexp
	form string
	enc  string
}{
	{regexp.MustCompile(`Buffer\.from\(\s*\\?["']([A-Za-z0-9+/=_-]+)\\?["']\s*,\s*\\?["'](?:base64|base64url)\\?["']`), "Buffer.from(…, 'base64')", "base64"},
	{regexp.MustCompile(`Buffer\.from\(\s*\\?["']([0-9A-Fa-f]+)\\?["']\s*,\s*\\?["']hex\\?["']`), "Buffer.from(…, 'hex')", "hex"},
	{regexp.MustCompile(`\batob\(\s*\\?["']([A-Za-z0-9+/=]+)\\?["']\s*\)`), "atob(…)", "base64"},
	{regexp.MustCompile(`\b(?:urlsafe_|standard_)?b64decode\(\s*b?\\?["']([A-Za-z0-9+/=_-]+)\\?["']`), "b64decode(…)", "base64"},
	{regexp.MustCompile(`\bb32decode\(\s*b?\\?["']([A-Za-z2-7=]+)\\?["']`), "b32decode(…)", "base32"},
	{regexp.MustCompile(`\bcodecs\.decode\(\s*b?\\?["']([A-Za-z0-9+/=]+)\\?["']\s*,\s*\\?["']base64\\?["']`), "codecs.decode(…, 'base64')", "base64"},
	{regexp.MustCompile(`\bdecode_base64\(\s*\\?["']([A-Za-z0-9+/=]+)\\?["']`), "decode_base64(…)", "base64"},
	{regexp.MustCompile(`\bBase64\.(?:strict_|urlsafe_)?decode64\(\s*\\?["']([A-Za-z0-9+/=_-]+)\\?["']`), "Base64.decode64(…)", "base64"},
}

// inlineRunsRe matches the code just before a decode call that runs its
// result: eval(…), exec(…), Function(…), compile(…), vm.runInThisContext(…),
// child_process calls, os.system(…), subprocess calls, Perl's eval.
var inlineRunsRe = regexp.MustCompile(`(?:\beval|\bexec|\bexecSync|\bspawnSync|\bnew\s+Function|\bFunction|\bcompile|\bvm\.runIn\w+|\bos\.system|\bsubprocess\.\w+|\bsystem)\s*\(\s*[\w.$()\[\]'"]{0,60}$|\beval\s+$`)

// inlineDecodeVarRe matches a decode call on a variable rather than a
// literal: Buffer.from(f, 'base64'), atob(s), b64decode(data).
var inlineDecodeVarRe = regexp.MustCompile(`Buffer\.from\(\s*[A-Za-z_$][\w$.]*\s*,\s*\\?["'](?:base64|base64url)\\?["']|\batob\(\s*[A-Za-z_$][\w$.]*\s*\)|\b(?:urlsafe_|standard_)?b64decode\(\s*[A-Za-z_][\w.]*\s*[,)]|\bdecode_base64\(\s*\$\w+|\bBase64\.(?:strict_|urlsafe_)?decode64\(\s*[A-Za-z_@][\w.]*\s*\)`)

// quotedBase64Re matches a quoted base64 literal of payloadMinEncoded
// characters or more.
var quotedBase64Re = regexp.MustCompile(`\\?["']([A-Za-z0-9+/]{60,}={0,2})\\?["']`)

// inlinePayloads finds decode calls in inline interpreter code. A literal
// first stored in a variable and decoded from there counts when it is long
// (#1643): a corpus hook printed {"decision":"allow", "additionalContext":
// "..."} this way, an approval and an instruction nobody could read.
func inlinePayloads(command string) []embeddedPayload {
	var out []embeddedPayload
	if m := inlineDecodeVarRe.FindString(command); m != "" {
		form := strings.SplitN(m, "(", 2)[0] + "(variable)"
		for _, q := range quotedBase64Re.FindAllStringSubmatch(command, -1) {
			if b, ok := decodeLiteral(q[1], "base64"); ok {
				out = append(out, embeddedPayload{form: form, enc: "base64", literal: q[1], decoded: b})
			}
		}
	}
	for _, f := range inlineDecodeForms {
		for _, m := range f.re.FindAllStringSubmatchIndex(command, -1) {
			lit := command[m[2]:m[3]]
			b, ok := decodeLiteral(lit, f.enc)
			if !ok || len(lit) < 4 {
				continue
			}
			p := embeddedPayload{form: f.form, enc: f.enc, literal: lit, decoded: b}
			before := command[max(0, m[0]-80):m[0]]
			if i := strings.LastIndexAny(before, ";\n"); i >= 0 {
				before = before[i+1:]
			}
			if inlineRunsRe.MatchString(before) {
				p.run = "passes the decoded text to " + strings.TrimSpace(strings.SplitN(inlineRunsRe.FindString(before), "(", 2)[0]) + " as code"
			}
			out = append(out, p)
		}
	}
	return out
}

// partECovers reports a command CFG036 Part E reports in an instruction file:
// a literal decoded into a shell (#906, #1644), or into a file it runs.
func partECovers(cmd string) bool {
	if loc := decodeShellRe.FindStringSubmatchIndex(cmd); loc != nil && decodeLiteralOK(cmd, loc) {
		return true
	}
	if loc := decodeEvalRe.FindStringSubmatchIndex(cmd); loc != nil && decodeLiteralOK(cmd, loc) {
		return true
	}
	col, _, _ := decodeToFileRun(cmd, "", true)
	return col >= 0
}

// decodeLiteralOK applies Part E's literal check to a decode match.
func decodeLiteralOK(cmd string, loc []int) bool {
	lit := cmd[loc[2]:loc[3]]
	if decodedKind(cmd[loc[0]:loc[1]]) == "base32" {
		return base32Literal(lit)
	}
	return base64Literal(lit)
}
