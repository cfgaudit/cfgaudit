// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// checkCursorIDEPolicy reports what .cursor/permissions.json grants against the
// neutral forbid-allow. The file has allowlists only, so policy.deny goes to
// CFG118. Cursor turns each terminalAllowlist entry into Shell(entry) and each
// mcpAllowlist entry into Mcp(entry), the tokens Cursor CLI reads (#1518).
func checkCursorIDEPolicy(t *Target, sp policySpelling) []finding.Finding {
	p := t.CursorPermissions
	if p == nil {
		return nil
	}
	var findings []finding.Finding
	check := func(category, key, token string, list, entries []string) {
		for _, v := range entries {
			for _, e := range list {
				if cursorOverlaps(category, token+"("+e+")", v) {
					findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: finding.Error, File: t.CursorPermissionsFile,
						Message: "policy forbid-allow." + category + " \"" + v + "\": " + key + " grants it via \"" + e + "\", so " + sp.name + " runs it without asking"})
					break
				}
			}
		}
	}
	check("commands", "terminalAllowlist", "Shell", p.TerminalAllowlist, t.PolicyForbid.Commands)
	check("mcp-tools", "mcpAllowlist", "Mcp", p.MCPAllowlist, t.PolicyForbid.MCPTools)
	return findings
}

// vscodeRegexKeyRe is a /regex/ key of chat.tools.terminal.autoApprove.
var vscodeRegexKeyRe = regexp.MustCompile(`^/(.*)/([a-z]*)$`)

// vscodeMatches reports whether a key of chat.tools.terminal.autoApprove applies
// to the command v, and whether that could be decided. A plain key is a word
// prefix in either direction, since an allow for "git push --force" grants part
// of "git push". A /regex/ is tried on the command with and without arguments;
// one Go cannot compile is undecidable.
func vscodeMatches(key, v string) (matches, decided bool) {
	m := vscodeRegexKeyRe.FindStringSubmatch(strings.TrimSpace(key))
	if m == nil {
		return hasCmdPrefix(v, key) || hasCmdPrefix(key, v), true
	}
	src := m[1]
	if strings.Contains(m[2], "i") {
		src = "(?i)" + src
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return false, false
	}
	return re.MatchString(v) || re.MatchString(v+" origin main"), true
}

// checkVSCodePolicy reports what chat.tools.terminal.autoApprove grants against
// the neutral forbid-allow. A false entry that covers the command keeps the
// prompt, so a true entry under it grants nothing.
func checkVSCodePolicy(t *Target, sp policySpelling) []finding.Finding {
	if t.VSCodeSettings == nil {
		return nil
	}
	entries, ok := t.VSCodeSettings.ObjectField(terminalAutoApproveKey)
	if !ok {
		return nil
	}
	var findings []finding.Finding
	add := func(severity finding.Severity, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG025", Severity: severity, File: t.VSCodeSettingsFile, Message: msg})
	}
	for _, v := range t.PolicyForbid.Commands {
		keys := sortedRawKeys(entries)
		kept := false
		for _, k := range keys {
			if !terminalEntryApproves(entries[k]) {
				if m, _ := vscodeMatches(k, v); m && hasCmdPrefix(v, strings.TrimSpace(k)) {
					kept = true
				}
			}
		}
		if kept {
			continue
		}
		for _, k := range keys {
			if !terminalEntryApproves(entries[k]) {
				continue
			}
			m, decided := vscodeMatches(k, v)
			switch {
			case !decided:
				add(finding.Warn, "policy forbid-allow.commands \""+v+"\": "+terminalAutoApproveKey+" has the pattern \""+k+"\", which cfgaudit cannot read, so it may grant the command")
			case m:
				add(finding.Error, "policy forbid-allow.commands \""+v+"\": "+terminalAutoApproveKey+" grants it via \""+k+"\", so "+sp.name+" runs it without asking")
			}
		}
	}
	return findings
}
