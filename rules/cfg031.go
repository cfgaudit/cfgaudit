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
// /home/<u>/, /Users/<u>/) since the fragment itself is distinctive; the
// ambiguous .claude/settings.json is anchored to a home prefix so a project-local
// reference is not flagged.
var sensitivePathRe = regexp.MustCompile(`(?i)(` +
	`\.ssh/(?:id_rsa|id_ed25519|id_dsa|id_ecdsa|known_hosts|config)\b` +
	`|\.aws/(?:credentials|config)\b` +
	`|(?:~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+)/\.claude/settings(?:\.local)?\.json` +
	`|\.cursor/mcp\.json` +
	`|\.config/gcloud/` +
	`|\.gnupg/` +
	`|\.netrc\b` +
	`|\.npmrc\b` +
	`|\.docker/config\.json` +
	`|\.kube/config\b` +
	`|/etc/(?:passwd|shadow|sudoers)\b` +
	`|credentials\.json\b` +
	`|[\w.\-/]+\.pem\b` +
	`|[\w.\-/]+\.key\b` +
	`)`)

// pathActionRe matches a read/transmit verb that turns a sensitive-file reference
// from a documentation *mention* into an instruction to access or exfiltrate it.
// On the same line as the path → error; otherwise a bare mention is only a warn
// (a skill may legitimately name a credential path in prose).
var pathActionRe = regexp.MustCompile(`(?i)\b(read|cat|open|less|head|tail|view|print|echo|dump|copy|cp|scp|move|mv|send|upload|post|put|curl|wget|fetch|exfiltrat\w*|leak|transmit|mail|base64|gpg|tar|zip|attach|load|source|contents of|paste)\b`)

func (r *cfg031) Check(t *Target) []finding.Finding {
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	var findings []finding.Finding
	for i, line := range strings.Split(t.InstructionContent, "\n") {
		loc := sensitivePathRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		lineNo := i + 1
		path := strings.TrimSpace(line[loc[0]:loc[1]])
		sev := finding.Warn
		msg := t.instructionName() + " line " + strconv.Itoa(lineNo) + " mentions the sensitive file \"" + path +
			"\" — a trusted instruction file naming a credential/secret file is suspicious; confirm this is documentation, not an instruction to access it"
		if pathActionRe.MatchString(line) {
			sev = finding.Error
			msg = t.instructionName() + " line " + strconv.Itoa(lineNo) + " instructs reading or sending the sensitive file \"" + path +
				"\" — a hallmark of an exfiltration payload. Remove it"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG031",
			Severity: sev,
			File:     t.InstructionFile,
			Line:     lineNo,
			Col:      loc[0] + 1,
			Message:  msg,
		})
	}
	return findings
}
