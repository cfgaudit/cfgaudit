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

func (r *cfg015) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSites(t) {
		substs := extractHookSubstitutions(site.Command)
		substs = slices.DeleteFunc(substs, isBenignSubstitution)
		if len(substs) == 0 {
			continue
		}
		sev := finding.Warn
		for _, s := range substs {
			if hookNetworkCmdRe.MatchString(s) {
				sev = finding.Error
				break
			}
		}
		msg := site.Label + " contains shell substitution(s) " + strings.Join(quotedList(substs), ", ") +
			" — the output of each substituted command is spliced into the shell line at runtime; if any input is attacker-controlled this becomes a command-injection sink"
		if sev == finding.Error {
			msg += " (network call inside the substitution increases severity)"
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
