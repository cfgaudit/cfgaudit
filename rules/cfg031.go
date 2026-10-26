// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg031 struct{}

var CFG031 = &cfg031{}

func init() { All = append(All, CFG031) }

func (r *cfg031) ID() string { return "CFG031" }

// sensitivePathRe matches references to credential / secret files that legitimate
// project documentation has no reason to point Claude at — a hallmark of an
// exfiltration payload. The dotfile fragments match any home form (~/, $HOME,
// /home/<u>/, /Users/<u>/) since the fragment itself is distinctive.
//
// Agent *config* files (.cursor/mcp.json, .claude/settings.json, …) are
// deliberately NOT listed: setup docs and skills routinely reference them, so
// flagging the mention is a false positive (500-repo FP scan). A real secret
// inside such a config is caught at the value level by CFG007/CFG050, not here.
//
// The two catch-all extensions are not treated alike, because they do not carry
// the same risk of collision (#569).
//
// `.pem` is left open: nothing else uses that extension, and a census of 200
// committed instruction files mentioning it produced only real certificate and
// key files (fullchain.pem, dh4096.pem, .ssh/aws-key.pem), so requiring a path
// there would cost coverage and buy nothing.
//
// `.key` has to carry a path separator, because the extension collides with
// three unrelated things that are common in exactly these files. In the same
// census, 65 of the roughly 123 `.key` occurrences had no directory component,
// and about nine in ten of those were not files at all: field and method access
// in code samples (`item.key`, `headers.get(item.key)`, `vault.key()`), i18n
// translation keys (`t("full.key")`), a Gradle property name (`signing.key`),
// and Apple Keynote documents (`DECK.key`, `presentation.key`), which is also
// how the rule reached `error`, since one Keynote line ends "then Read them".
// Requiring the separator keeps every real path in the census
// (`/etc/openclaw/secrets/tenant-1.key`, `.claude/azure.key`,
// `node/data/keys/pub.key`, `~/.ssh/id_rsa.key`).
//
// The price is stated rather than hidden: a credential file named without any
// directory, such as `age.key` or `example.com.key`, is no longer reported. Seven
// occurrences in the census were of that kind. Keeping them was tried and
// rejected, because a path-less `.key` with an action verb on the line is not a
// cleaner signal either: of the four such lines in the census, three were the
// Keynote and Gradle false positives.
//
// `.npmrc` counts only in the home directory, or as an `_authToken` line: a
// project `.npmrc` holds registry settings and is named in prose all the time
// ("`.npmrc` is used only for auth and registry settings", "plain fetch does
// not read `.npmrc`"), while the token lives in `~/.npmrc` or is injected in
// CI (#854).
var sensitivePathRe = mustFiltered(`(?i)(` +
	`\.ssh/(?:id_rsa|id_ed25519|id_dsa|id_ecdsa|known_hosts|config)\b` +
	`|\.aws/(?:credentials|config)\b` +
	`|\.config/gcloud/` +
	`|\.gnupg/` +
	`|\.netrc\b` +
	`|(?:~|\$HOME|\$\{HOME\}|/home/[\w.\-]+|/Users/[\w.\-]+|/root)/\.npmrc\b|:_authToken\b` +
	`|\.docker/config\.json` +
	`|\.kube/config\b` +
	`|/etc/(?:passwd|shadow|sudoers)\b` +
	`|credentials\.json\b` +
	`|[\w.\-/]+\.pem\b` +
	`|(?:[\w.\-]*/)+[\w.\-]*\.key\b` +
	`)`)

// pathActionRe matches a read/transmit verb that turns a sensitive-file reference
// from a documentation *mention* into an instruction to access or exfiltrate it.
// On the same line as the path → error; otherwise a bare mention is only a warn
// (a skill may legitimately name a credential path in prose).
var pathActionRe = regexp.MustCompile(`(?i)\b(read|cat|open|less|head|tail|view|print|echo|dump|copy|cp|scp|move|mv|send|upload|post|put|curl|wget|fetch|exfiltrat\w*|leak|transmit|mail|base64|gpg|tar|zip|attach|load|source|contents of|paste)\b`)

// readOnlyRe matches "read-only" / "read only" / "readonly", where "read"
// describes a mount or a permission, not an action.
var readOnlyRe = regexp.MustCompile(`(?i)\bread[- ]?only\b`)

// assignmentCommentRe matches a KEY= line whose comment documents the value
// ("SMTP_DKIM_PRIVATE_KEY_PATH=   # PEM private key, e.g. keys/dkim.pem").
var assignmentCommentRe = regexp.MustCompile(`^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=[^#]*#`)

// actionScope returns the part of line whose verbs can act on the path at loc:
// the clause around it, bounded by sentence punctuation and table cell
// separators (#854). A verb elsewhere on the line, such as "read the whole
// change" in a list that also names `scripts/` and a key file, or "fails" in an
// error message quoted in a troubleshooting table, says nothing about the path.
// A path inside the comment of a KEY= line documents the value; it has no
// scope.
func actionScope(line string, loc []int) string {
	if m := assignmentCommentRe.FindStringIndex(line); m != nil && loc[0] >= m[1]-1 {
		return ""
	}
	start := clauseStart(line, loc[0])
	if i := strings.LastIndexByte(line[:loc[0]], '|'); i+1 > start {
		start = i + 1
	}
	end := len(line)
	for i := loc[1]; i < len(line); i++ {
		c := line[i]
		if c == '|' || ((c == '.' || c == ';' || c == '!' || c == '?') && i+1 < len(line) && (line[i+1] == ' ' || line[i+1] == '\t')) {
			end = i
			break
		}
	}
	scope := line[start:end]
	// A verb in another code span is a command of its own: "GitHub via
	// `~/.ssh/config`) rather than `github.com`, `gh stack link`/`view`" (#869).
	scope = inlineCodeSpanRe.ReplaceAllStringFunc(scope, func(span string) string {
		if sensitivePathRe.MatchString(span) {
			return span
		}
		return strings.Repeat(" ", len(span))
	})
	scope = fieldNameRe.ReplaceAllStringFunc(scope, func(f string) string { return strings.Repeat(" ", len(f)) })
	return readOnlyRe.ReplaceAllString(scope, "")
}

// fieldNameRe matches a dotted field name of a rule or query language,
// three or more lowercase segments: open.file.path, exec.file.name. Its first
// segment is not a verb, so "open.file.path in [\"/etc/shadow\"]" in a
// detection rule does not read the file (#945).
var fieldNameRe = regexp.MustCompile(`\b[a-z_]+(?:\.[a-z_]+){2,}\b`)

// homeToolPathRe matches a path under a dot-directory of the home directory,
// capturing the directory name ("gooseworks" in
// "$HOME/.gooseworks/credentials.json", "config/mentra" in
// "~/.config/mentra/private-key.pem").
var homeToolPathRe = regexp.MustCompile(`(?:~|\$HOME|\$\{HOME\}|/home/[\w.\-]+|/Users/[\w.\-]+|/root)/\.((?:config/)?[\w][\w\-]*)/(?:[\w.\-]+/)*[\w.\-]+`)

// sharedSecretStores are the home dot-directories that hold credentials for
// more than the tool that wrote them: SSH and GPG keys, cloud and cluster
// credentials, and Claude Code's own login.
var sharedSecretStores = map[string]bool{
	"ssh": true, "gnupg": true, "aws": true, "azure": true, "config/gcloud": true,
	"docker": true, "kube": true, "claude": true,
}

// toolOwnPath reports whether text is a path to a file in a single tool's own
// home directory ("~/.gooseworks/credentials.json", "~/.cyrus/github-app.pem").
// A skill that sets up or calls a tool reads that tool's key from where the
// tool keeps it; seventy-two skills of one package did exactly that, three
// lines each (#866). Such a file is reported as a mention, not as
// exfiltration: the key reaches the tool it belongs to.
func toolOwnPath(text string) bool {
	m := homeToolPathRe.FindStringSubmatch(text)
	return m != nil && m[0] == text && !sharedSecretStores[strings.ToLower(m[1])]
}

// pathToken widens the match at loc to the whole path it is part of, so a
// generic file name ("credentials.json") is seen with its directory.
func pathToken(line string, loc []int) string {
	start := loc[0]
	for start > 0 && strings.IndexByte(pathChars, line[start-1]) >= 0 {
		start--
	}
	return line[start:loc[1]]
}

const pathChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-/~${}"

// publicCertRe matches a CA certificate, which is public by design:
// "~/.portless/ca.pem", "cyrus-egress-ca.pem", "cacert.pem" (#869).
var publicCertRe = regexp.MustCompile(`(?i)(?:^|[/_.\-])(?:ca|cacert|ca-cert\w*|ca-bundle|ca-certificates?)\.(?:pem|crt)$`)

// placeholderPathRe matches a placeholder for a path the reader fills in:
// "/path/to/cert.pem", "path-to-cert.pem" (#869).
var placeholderPathRe = regexp.MustCompile(`(?i)(?:^|/)path[/\-]to[/\-]|^<[^>]*>$|^your[\-_]`)

// notASecretFile reports a match that names no secret file: a path inside a
// URL ("https://gvisor.dev/archive.key" is a public signing key), a CA
// certificate and a placeholder (#869).
func notASecretFile(line string, loc []int, full string) bool {
	start := loc[1] - len(full)
	if strings.HasPrefix(full, "//") && start > 0 && line[start-1] == ':' &&
		!strings.HasSuffix(strings.ToLower(line[:start-1]), "file") {
		return true // a web URL; file:///etc/passwd is still a local file
	}
	if strings.Contains(full, "../") && baseURLPathRe.MatchString(full) {
		return true
	}
	return publicCertRe.MatchString(full) || placeholderPathRe.MatchString(full)
}

// baseURLPathRe matches a path that starts with a base URL placeholder:
// "{BASE_URL}/api/assets/download/../../../etc/passwd" is a path traversal
// probe sent to a web server, not a local file (#887).
var baseURLPathRe = regexp.MustCompile(`^(?:\{\{?\s*[A-Za-z_]\w*\s*\}?\}|\$\{?[A-Za-z_]\w*\}?)/`)

// blockedAfterRe matches a clause that says the read is refused: "Attempts to
// read `/proc/self/environ`, `~/.docker/config.json` ... will be denied".
var blockedAfterRe = regexp.MustCompile(`(?i)\b(?:is|are|will\s+be|get|gets|be)\s+(?:blocked|denied|forbidden|rejected|refused|not\s+allowed)\b`)

// writeOrTestBeforeRe matches what makes the path a write target or an
// existence test rather than a read: "> key.pem", "test -f x.pem", "[ -f x ]".
var writeOrTestBeforeRe = regexp.MustCompile(`(?:>>?\s*['"]?|\b(?:test|\[)\s+-[efsrdL]\s+['"]?)$`)

// copyCommandRe matches a cp, mv, install or ln command up to the path, with
// at least one argument before it: "sudo cp -i /etc/kubernetes/admin.conf ".
var copyCommandRe = regexp.MustCompile(`(?:^|[;&|(` + "`" + `]\s*|^\s*(?:[-*+]|\d+\.)\s+)(?:sudo\s+(?:-\S+\s+)*)?(?:cp|mv|install|ln)\s+(?:\S+\s+)+['"]?$`)

// copyToRe matches prose that names the path as where a file goes: "Copy the
// user's PEM to `instance/secrets/app.pem`".
var copyToRe = regexp.MustCompile(`(?i)\b(?:copy|move|write|save|place|put|store)\b[^.;|]*\bto\s+[` + "`" + `'"]?$`)

// listCommandRe matches a command that checks a path without printing its
// content: "ls \"/etc/sudoers.d/...\"", "stat x.pem".
var listCommandRe = regexp.MustCompile(`\b(?:ls|stat)(?:\s+-\w+)*\s+['"]?$`)

// copyDestination reports whether the path between start and end is written
// or only checked, not read (#887): the last argument of cp, mv, install or ln
// ("sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config"), the target of
// "copy ... to", and a path given to ls or stat.
func copyDestination(line string, start, end int) bool {
	before := line[:start]
	if copyToRe.MatchString(before) || listCommandRe.MatchString(before) {
		return true
	}
	if !copyCommandRe.MatchString(before) {
		return false
	}
	rest := line[end:]
	if i := strings.IndexAny(rest, ";&|`)"); i >= 0 {
		rest = rest[:i]
	}
	return strings.Trim(rest, " \t'\"") == ""
}

// quietGrepBeforeRe matches a grep that reports only whether the file holds a
// match, not what it holds: -q, -c, -l and their long forms, up to the path
// ("grep -q 'ANTHROPIC' \"$HOME/.claude/.credentials.json\"", #952).
var quietGrepBeforeRe = regexp.MustCompile(`\bgrep\s+(?:-\S+\s+)*?(?:-[A-Za-z]*[qcl][A-Za-z]*|--quiet|--silent|--count|--files-with-matches)\s+(?:\S+\s+)*['"]?$`)

// errorTextAfterRe matches the error a program prints about the path, so the
// verb before it is the failed call quoted from a log: "open /data/tls.key:
// permission denied" in a troubleshooting table (#952).
var errorTextAfterRe = regexp.MustCompile(`(?i)^:\s*(?:permission\s+denied|no\s+such\s+file(?:\s+or\s+directory)?|is\s+a\s+directory|not\s+a\s+directory|operation\s+not\s+permitted|read-only\s+file\s+system)\b`)

// npmrcWriteRe matches a line that writes an .npmrc file, where an
// ":_authToken" is the line being written: echo "//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}" > .npmrc.
var npmrcWriteRe = regexp.MustCompile(`>\s*\S*\.npmrc[\w.\-]*`)

// blockListHeadRe matches the head of a list of things refused or detected:
// "**106 patterns covering:**", "Never:", "Blocked paths:".
var blockListHeadRe = regexp.MustCompile(`(?i)\b(?:patterns?|detect\w*|block\w*|den(?:y|ied|ies)|forbid\w*|prohibit\w*|red\s+flags?|dangerous)\b`)

// notARead reports whether a verb near the path does not read it (#869): a
// negation before the path in its clause or a refusing list above it, a
// refusal after it, a write or an existence test of the path (a quiet grep
// among them), an error message quoted about the path, and an
// ":_authToken" line written to an .npmrc.
func notARead(lines []string, i int, loc []int, full string) bool {
	line := lines[i]
	start := loc[1] - len(full)
	if prohibitionRe.MatchString(line[clauseStart(line, start):start]) {
		return true
	}
	// "etc." inside the list does not end the sentence.
	if blockedAfterRe.MatchString(clauseRest(strings.ReplaceAll(line[loc[1]:], "etc.", "etc"))) {
		return true
	}
	if writeOrTestBeforeRe.MatchString(line[:start]) || copyDestination(line, start, loc[1]) ||
		quietGrepBeforeRe.MatchString(line[:start]) || errorTextAfterRe.MatchString(line[loc[1]:]) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(line[loc[0]:loc[1]]), ":_authtoken") && npmrcWriteRe.MatchString(line[loc[1]:]) {
		return true
	}
	g := governingLine(lines, i)
	return introducesList(g) && (prohibitionRe.MatchString(g) || blockListHeadRe.MatchString(g))
}

func (r *cfg031) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		toolOwnSeen := map[string]bool{}
		lines := strings.Split(src.Content, "\n")
		for i, line := range lines {
			loc := sensitivePathRe.FindStringIndex(line)
			// A public key is meant to be shared: look past "id_ed25519.pub"
			// to a private key later on the line (#952).
			for loc != nil && strings.HasPrefix(line[loc[1]:], ".pub") {
				next := sensitivePathRe.FindStringIndex(line[loc[1]:])
				if next == nil {
					loc = nil
					break
				}
				loc = []int{loc[1] + next[0], loc[1] + next[1]}
			}
			if loc == nil {
				continue
			}
			lineNo := i + 1
			path := strings.TrimSpace(line[loc[0]:loc[1]])
			full := pathToken(line, loc)
			if notASecretFile(line, loc, full) {
				continue
			}
			if toolOwnPath(full) {
				// "~/.x/f" and "$HOME/.x/f" are one file.
				key := full[strings.Index(full, "/.")+1:]
				if toolOwnSeen[key] {
					continue
				}
				toolOwnSeen[key] = true
				findings = append(findings, finding.Finding{
					RuleID:   "CFG031",
					Severity: finding.Warn,
					File:     src.File,
					Line:     lineNo,
					Col:      loc[0] + 1,
					Message: src.Name + " line " + strconv.Itoa(lineNo) + " names \"" + full +
						"\", a credential file in one tool's own home directory — normal for a skill that calls that tool; confirm the key is used only with it",
				})
				continue
			}
			sev := finding.Warn
			msg := src.Name + " line " + strconv.Itoa(lineNo) + " mentions the sensitive file \"" + path +
				"\" — a trusted instruction file naming a credential/secret file is suspicious; confirm this is documentation, not an instruction to access it"
			if pathActionRe.MatchString(actionScope(line, loc)) && !notARead(lines, i, loc, full) {
				sev = finding.Error
				msg = src.Name + " line " + strconv.Itoa(lineNo) + " instructs reading or sending the sensitive file \"" + path +
					"\" — a hallmark of an exfiltration payload. Remove it"
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG031",
				Severity: sev,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message:  msg,
			})
		}
	}
	return findings
}
