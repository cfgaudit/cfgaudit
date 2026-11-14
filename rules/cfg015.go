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
// and it is flagged as before. The exceptions are the guards hooks write
// around it (#1200): `git -C` on the project or plugin directory Claude Code
// sets, stderr sent to /dev/null, and a `|| true` or `|| pwd` fallback.
var benignSubstRe = regexp.MustCompile(`^\s*git\s+(?:-C\s+(?:"\$\{?CLAUDE_(?:PROJECT_DIR|PLUGIN_ROOT)\}?"|\$\{?CLAUDE_(?:PROJECT_DIR|PLUGIN_ROOT)\}?)\s+)?rev-parse\s+--(?:show-toplevel|git-dir|git-common-dir|absolute-git-dir)` + substFallback + `$`)

// substFallback is the guard a hook adds so a failing query does not abort
// it: stderr to /dev/null, then `|| true` or `|| pwd` (#1200).
const substFallback = `(?:\s+2>\s*/dev/null)?(?:\s*\|\|\s*(?:true|pwd))?\s*`

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

// storedOnly reports whether the substitution s appears in cmd only where its
// output is never run: as the whole value of a variable assignment
// (NAME=$(...), local NAME="$(...)"), as a quoted operand of a test
// ([ "$(...)" = main ], [[ -n "$(...)" ]]), or as the quoted subject of a case
// (#792, #1675). An assignment value is not split into words or run, a test
// only compares it, and how a stored variable is used later is CFG009's
// question. A substitution that reaches the network or runs code itself is
// still reported, and so is the same substitution used as an argument
// elsewhere in the command.
func storedOnly(cmd, s string) bool {
	if hookNetworkCmdRe.MatchString(s) || substRunsCodeRe.MatchString(s) {
		return false
	}
	found := false
	for i := 0; ; {
		j := strings.Index(cmd[i:], s)
		if j < 0 {
			return found
		}
		j += i
		end := j + len(s)
		before := cmd[:j]
		quoted := strings.HasSuffix(before, `"`) && end < len(cmd) && cmd[end] == '"'
		if quoted {
			end++
		}
		after := cmd[end:]
		switch {
		case assignedBeforeRe.MatchString(before):
			if strings.HasSuffix(before, `"`) && !quoted {
				return false // the quoted value goes on
			}
			if after != "" && !strings.ContainsRune(" \t;&|)\n", rune(after[0])) {
				return false // more text glued to the value
			}
		case !quoted:
			return false
		case testLeftOperandRe.MatchString(before) && testAfterLeftRe.MatchString(after),
			testRightOperandRe.MatchString(before) && testCloseRe.MatchString(after),
			caseSubjectRe.MatchString(before) && caseInRe.MatchString(after):
		default:
			return false
		}
		found = true
		i = end
	}
}

// The value may be double-quoted: input="$(cat)" (#1200). A single quote may
// open the script of a bash -c: bash -c 'CMD=$(jq -r .x); …' (#1675); outside
// one, a single-quoted substitution is never extracted.
var assignedBeforeRe = regexp.MustCompile(`(?:^|[\s;&|('])[A-Za-z_][A-Za-z0-9_]*="?$`)

// substRunsCodeRe matches a substitution that runs code it is given rather
// than a fixed command: eval, a shell with -c, source, or text piped into a
// shell or an interpreter.
var substRunsCodeRe = regexp.MustCompile(`\beval\b|\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-\w*c\b|\bsource\b|(?:^|[\s;&|(])\.\s|\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|php)\b`)

// testStart is a test in command position: [, [[ or test at the start of the
// line, after a separator or a keyword. `npm test "$(...)"` is no test.
const testStart = `(?:^|[;&|(!{]|\b(?:if|then|elif|else|while|until|do))\s*(?:\[\[?|test)`

// The quoted substitution opens a test: [ "$(...)", [[ ! -n "$(...)", test -z "$(...)".
var testLeftOperandRe = regexp.MustCompile(testStart + `\s+(?:!\s+)?(?:-[nz]\s+)?"$`)

// What may follow the first operand of a test: a comparison, the closing
// bracket, or the end of a test command.
var testAfterLeftRe = regexp.MustCompile(`^\s*(?:\]\]?(?:$|[\s;&|)])|(?:==?|!=|-eq|-ne|-lt|-le|-gt|-ge)\s|$|[;&|)])`)

// The quoted substitution is the second operand of a comparison inside a test.
var testRightOperandRe = regexp.MustCompile(testStart + `\s+[^;&|]*?\s(?:==?|!=|-eq|-ne|-lt|-le|-gt|-ge)\s+"$`)

// The test closes after its second operand.
var testCloseRe = regexp.MustCompile(`^\s*(?:\]\]?)?(?:$|[\s;&|)])`)

var (
	caseSubjectRe = regexp.MustCompile(`(?:^|[\s;&|(])case\s+"$`)
	caseInRe      = regexp.MustCompile(`^\s+in(?:$|\s)`)
)

func (r *cfg015) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSites(t) {
		substs := extractHookSubstitutions(site.Command)
		substs = slices.DeleteFunc(substs, isBenignSubstitution)
		substs = slices.DeleteFunc(substs, func(s string) bool { return storedOnly(site.Command, s) })
		if len(substs) == 0 {
			continue
		}
		// Option C of #1201: a substitution that reads nothing an attacker can
		// write (hook input, $ARGUMENTS, repository text, the network) is info.
		sev := finding.Info
		taint := commandTaint(site.Command, nil, !strings.Contains(site.Label, "`!{...}`"))
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

// Single quotes are literal to the shell, unless the command explicitly
// passes them to another shell for evaluation (for example sh -c).
var reparsedShellCommand = regexp.MustCompile("(^|[;&| ]+)(bash|sh|zsh)[ \t]+-c[ \t]+|(^|[;&| ]+)eval[ \t]+")

func shellSingleQuotedAt(cmd string, offset int) bool {
	if reparsedShellCommand.MatchString(cmd[:offset]) {
		return false
	}
	var single, double, escaped bool
	for _, char := range cmd[:offset] {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && !single {
			escaped = true
			continue
		}
		if char == '\'' && !double {
			single = !single
		}
		if char == '"' && !single {
			double = !double
		}
	}
	return single
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
	for _, m := range cmdSubstDollarRe.FindAllStringIndex(cmd, -1) {
		if !shellSingleQuotedAt(cmd, m[0]) {
			add(cmd[m[0]:m[1]])
		}
	}
	for _, m := range cmdSubstBacktickRe.FindAllStringIndex(cmd, -1) {
		if !shellSingleQuotedAt(cmd, m[0]) {
			add(cmd[m[0]:m[1]])
		}
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
