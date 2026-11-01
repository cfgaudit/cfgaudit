// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"slices"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg015 struct{}

var CFG015 = &cfg015{}

func init() { All = append(All, CFG015) }

func (r *cfg015) ID() string { return "CFG015" }

// `$(...)` — only the inside is captured; nested parens are not modelled
// because hooks rarely use them and the rule only needs presence + content.
var cmdSubstDollarRe = regexp.MustCompile(`\$\(([^()]*)\)`)

// Backtick substitution: `…`.
var cmdSubstBacktickRe = regexp.MustCompile("`([^`]*)`")

// Network commands that escalate the finding severity when they appear
// inside a substitution.
var hookNetworkCmdRe = regexp.MustCompile(`\b(?:curl|wget|nc|ncat|ssh|scp|rsync|ftp|telnet|nslookup|dig|host)\b`)

// benignSubstRe matches a substitution whose command is fixed, local, and takes
// no input: a query for the repository root. The rule is about output that is
// spliced into a shell line, and this output is a path the shell already had
// access to, produced by a command with no argument an attacker could reach.
//
// This exists because of what the newly scanned hook surfaces actually contain.
// A false-positive run over 432 real repositories (2026-08-04, pre-v1.11.0)
// found CFG015 firing on 19 of the 59 with a .codex/hooks.json, and 43 of those
// 46 findings were the identical expression: `$(git rev-parse --show-toplevel)`.
// Claude Code hooks never showed this because Claude provides
// $CLAUDE_PROJECT_DIR; Codex has no equivalent, so its hooks ask git.
//
// Deliberately narrow. Only `git rev-parse` with the flags that print a path,
// and only when nothing else rides along in the same substitution: any pipe,
// redirect, semicolon or command separator makes it a compound expression again
// and it is flagged as before.
var benignSubstRe = regexp.MustCompile(`^\s*git\s+rev-parse\s+--(?:show-toplevel|git-dir|git-common-dir|absolute-git-dir)\s*$`)

// isBenignSubstitution reports whether a substituted command is one of the fixed
// path queries above. The input carries its delimiters, as extractHookSubstitutions
// returns them, so they are stripped before matching.
func isBenignSubstitution(s string) bool {
	inner := strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(inner, "$(") && strings.HasSuffix(inner, ")"):
		inner = inner[2 : len(inner)-1]
	case strings.HasPrefix(inner, "`") && strings.HasSuffix(inner, "`") && len(inner) >= 2:
		inner = inner[1 : len(inner)-1]
	default:
		return false
	}
	return benignSubstRe.MatchString(inner)
}

// stdinReaderRe matches a substituted command that only reads the hook's own
// stdin, the event JSON Claude Code pipes in: jq with options and one filter
// and no file argument, or a bare cat, optionally with stderr sent to
// /dev/null. That is how the docs of this rule tell
// a hook to get its input (#792).
var stdinReaderRe = regexp.MustCompile(`^\s*(?:jq(?:\s+-[A-Za-z-]+)*\s+(?:'[^']*'|"[^"]*"|\.[A-Za-z0-9_.\[\]]*)|cat)(?:\s+2>\s*/dev/null)?\s*$`)

// assignedFromStdin reports whether the substitution s appears in cmd only as
// the whole value of a variable assignment (NAME=$(...), local NAME=$(...))
// and its command only reads stdin. The output is stored, not spliced into a
// command line; where the variable is used is CFG009's question.
func assignedFromStdin(cmd, s string) bool {
	if !strings.HasPrefix(s, "$(") || !stdinReaderRe.MatchString(s[2:len(s)-1]) {
		return false
	}
	found := false
	for i := 0; ; {
		j := strings.Index(cmd[i:], s)
		if j < 0 {
			return found
		}
		j += i
		if !assignedBeforeRe.MatchString(cmd[:j]) {
			return false
		}
		end := j + len(s)
		if end < len(cmd) && !strings.ContainsRune(" \t;&|)\n", rune(cmd[end])) {
			return false // more text glued to the value
		}
		found = true
		i = end
	}
}

var assignedBeforeRe = regexp.MustCompile(`(?:^|[\s;&|(])[A-Za-z_][A-Za-z0-9_]*=$`)

func (r *cfg015) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSites(t) {
		substs := extractHookSubstitutions(site.Command)
		substs = slices.DeleteFunc(substs, isBenignSubstitution)
		substs = slices.DeleteFunc(substs, func(s string) bool { return assignedFromStdin(site.Command, s) })
		if len(substs) == 0 {
			continue
		}
		// Option C of #1201: a substitution that reads nothing an attacker can
		// write (hook input, $ARGUMENTS, repository text, the network) is info.
		sev := finding.Info
		taint := commandTaint(site.Command, nil)
		for _, s := range substs {
			if hookNetworkCmdRe.MatchString(s) {
				sev = finding.Error
				break
			}
			if substReadsInput(s, taint) {
				sev = finding.Warn
			}
		}
		msg := site.Label + " contains shell substitution(s) " + strings.Join(quotedList(substs), ", ") +
			" — the output of each substituted command is spliced into the shell line at runtime; if any input is attacker-controlled this becomes a command-injection sink"
		switch sev {
		case finding.Error:
			msg += " (network call inside the substitution increases severity)"
		case finding.Info:
			msg += " (none of them reads hook input, $ARGUMENTS, repository text or the network)"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG015",
			Severity: sev,
			File:     site.File,
			Message:  msg + userScopeNote(t),
		})
	}
	return findings
}

// substInputRe matches a substituted command that reads text an attacker can
// write: the hook's stdin (jq, cat, read, Python's or Node's stdin), the
// skill's $ARGUMENTS, a repository file through cat, or git output that holds
// commit messages, branch or tag names and file contents (#1201). `ls`, `date`,
// `command -v`, `dirname` and a `tail` over their output do not.
var substInputRe = regexp.MustCompile(`\bjq\b|tool_input|\bcat\b|\bread\b|/dev/stdin|sys\.stdin|json\.load|readFileSync\(\s*0|ReadToEnd|\$\{?(?:ARGUMENTS\b|input\b|[0-9@*])|\bgit\s+(?:\S+\s+)*?(?:log|show|branch|describe|for-each-ref|rev-list|shortlog|diff|status|config|name-rev|symbolic-ref|blame|grep|ls-files|cat-file|tag)\b|--abbrev-ref`)

// substReadsInput reports whether substitution s reads attacker-writable text,
// directly or through a variable that holds hook input.
func substReadsInput(s string, taint shellTaint) bool {
	if substInputRe.MatchString(s) {
		return true
	}
	for _, u := range shellVarUses(s) {
		if taint.untrusted(u.name, nil) {
			return true
		}
	}
	return false
}

func extractHookSubstitutions(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, m := range cmdSubstDollarRe.FindAllStringSubmatch(cmd, -1) {
		add("$(" + m[1] + ")")
	}
	for _, m := range cmdSubstBacktickRe.FindAllStringSubmatch(cmd, -1) {
		add("`" + m[1] + "`")
	}
	return out
}

func quotedList(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = `"` + s + `"`
	}
	return out
}
