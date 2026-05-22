package rules

import (
	"regexp"
	"sort"
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

func (r *cfg015) Check(t *Target) []finding.Finding {
	if t.Settings == nil || len(t.Settings.Hooks) == 0 {
		return nil
	}

	events := make([]string, 0, len(t.Settings.Hooks))
	for e := range t.Settings.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var findings []finding.Finding
	for _, event := range events {
		for _, group := range t.Settings.Hooks[event] {
			for _, h := range group.Hooks {
				if h.Command == "" {
					continue
				}
				substs := extractHookSubstitutions(h.Command)
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
				msg := "hooks." + event + " command contains shell substitution(s) " + strings.Join(quotedList(substs), ", ") +
					" — the output of each substituted command is spliced into the shell line at runtime; if any input is attacker-controlled this becomes a command-injection sink"
				if sev == finding.Error {
					msg += " (network call inside the substitution increases severity)"
				}
				findings = append(findings, finding.Finding{
					RuleID:   "CFG015",
					Severity: sev,
					File:     t.SettingsFile,
					Message:  msg + userScopeNote(t),
				})
			}
		}
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
