package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg104 struct{}

// CFG104 reports a committed Devin permission allow rule that removes the
// confirmation prompt for a whole tool family or for a privileged binary.
var CFG104 = &cfg104{}

func init() { All = append(All, CFG104) }

func (r *cfg104) ID() string { return "CFG104" }

// devinRuleRe splits a Devin permission rule into its kind and its argument:
// Read(glob), Write(glob), Exec(prefix) and Fetch(pattern) are the four
// documented kinds.
var devinRuleRe = regexp.MustCompile(`^\s*(Read|Write|Exec|Fetch)\(\s*([^)]*)\s*\)\s*$`)

// devinWildcardRe matches an argument that constrains nothing: "*", "**", "/**"
// and the home-rooted spellings of the same.
var devinWildcardRe = regexp.MustCompile(`^(?:\*{1,2}|/\*{1,2}|~/\*{1,2}|\*{1,2}/\*{1,2})$`)

// devinPrivilegedBinaries are the commands whose bare prefix auto-approves an
// action a reviewer would want to see. Deliberately short: each one is either a
// privilege change or an irreversible write, and each was found in real
// committed files during the measurement on #538.
//
// Interpreters (bash, python3, node) and network binaries (curl, ssh) are NOT
// here, and that is a decision rather than an oversight. They auto-approve
// arbitrary code just as effectively, but 15 of 51 sampled files carry one, so
// reporting them would report how people ordinarily drive the tool. See the rule
// doc; the numbers are there rather than in a comment that will drift.
var devinPrivilegedBinaries = map[string]string{
	"sudo":   "runs commands as another user, so every later restriction is negotiable",
	"rm":     "deletes files with no confirmation and no undo",
	"chmod":  "changes file permissions, including making something executable",
	"chown":  "changes file ownership",
	"docker": "reaches the container daemon, which is a root-equivalent interface on most setups",
}

// Check reports the narrow set of Devin allow rules that are weakening.
//
// Devin's default when no rule matches is a prompt ("you're prompted for
// approval"), so a committed allow converts "everyone is asked" into "nobody is
// asked". It does not override a contributor's own deny: the permission lists
// merge across levels and deny is evaluated first over the merged set, which is
// why this is warn rather than error and why the message says "who has not
// denied it themselves" instead of claiming the repository wins outright.
//
// Argument-constrained rules (Exec(git status), Exec(npm run)) are never
// reported. Deny and ask rules are the narrowing direction and are not read.
func (r *cfg104) Check(t *Target) []finding.Finding {
	if t == nil || t.Devin == nil || t.Devin.Permissions == nil {
		return nil
	}
	var wildcards, privileged []string
	for _, rule := range t.Devin.Permissions.Allow {
		m := devinRuleRe.FindStringSubmatch(rule)
		if m == nil {
			continue
		}
		kind, arg := m[1], strings.TrimSpace(m[2])
		if devinWildcardRe.MatchString(arg) {
			wildcards = append(wildcards, strings.TrimSpace(rule))
			continue
		}
		if kind != "Exec" {
			continue
		}
		if _, ok := devinPrivilegedBinaries[strings.ToLower(arg)]; ok {
			privileged = append(privileged, strings.TrimSpace(rule))
		}
	}
	sort.Strings(wildcards)
	sort.Strings(privileged)

	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG104",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.DevinFile,
			Message:  msg + devinPermissionNote,
		})
	}
	if len(wildcards) > 0 {
		add("permissions.allow grants " + strings.Join(wildcards, ", ") +
			" — the pattern constrains nothing, so every path (or every command) in that category is auto-approved")
	}
	for _, rule := range privileged {
		arg := strings.ToLower(devinRuleRe.FindStringSubmatch(rule)[2])
		add("permissions.allow grants " + rule + " — Devin matches a prefix as a whole word, so this auto-approves the binary with any arguments, and " +
			devinPrivilegedBinaries[arg])
	}
	return findings
}

// devinPermissionNote states what a committed allow does and, just as
// importantly, what it does not do.
const devinPermissionNote = ". Devin prompts for approval when no rule matches, so a committed rule removes that prompt for every teammate who has not written their own deny; it does not override one that has, because the lists merge across levels and deny is evaluated first."
