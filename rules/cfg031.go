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
var sensitivePathRe = regexp.MustCompile(`(?i)(` +
	`\.ssh/(?:id_rsa|id_ed25519|id_dsa|id_ecdsa|known_hosts|config)\b` +
	`|\.aws/(?:credentials|config)\b` +
	`|\.config/gcloud/` +
	`|\.gnupg/` +
	`|\.netrc\b` +
	`|\.npmrc\b` +
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

func (r *cfg031) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		for i, line := range strings.Split(src.Content, "\n") {
			loc := sensitivePathRe.FindStringIndex(line)
			if loc == nil {
				continue
			}
			lineNo := i + 1
			path := strings.TrimSpace(line[loc[0]:loc[1]])
			sev := finding.Warn
			msg := src.Name + " line " + strconv.Itoa(lineNo) + " mentions the sensitive file \"" + path +
				"\" — a trusted instruction file naming a credential/secret file is suspicious; confirm this is documentation, not an instruction to access it"
			if pathActionRe.MatchString(line) {
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
