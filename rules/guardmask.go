// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// grepCommands match their quoted argument as a pattern, unless a pattern-file
// flag (-f) makes the argument a file they read instead (grep -qf KEYFILE).
var grepCommands = map[string]bool{
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true,
}

// guardHelperCommands take a quoted argument as the name of something they
// block, deny or assert on, not as a command they run (#1888). A committed
// guard hook has to name the keys and commands it refuses in order to match
// them, so that naming is detect/deny data. The list is message/match helpers
// beyond the echo/grep family: deny/block verbs and the assertion helpers a
// guard's own test harness uses. None of these runs its argument as a shell
// command, so blanking the argument cannot hide an executed payload; a command
// that does run its argument (bash -c, eval, ssh ...) is deliberately absent.
var guardHelperCommands = map[string]bool{
	"deny": true, "denied": true, "block": true, "blocked": true, "reject": true,
	"refuse": true, "refused": true, "forbid": true, "forbidden": true, "disallow": true,
	"disallowed": true, "guard": true, "veto": true, "abort": true, "bail": true,
	"assert": true, "refute": true, "expect": true, "require": true, "want": true,
	"should": true, "match": true, "matches": true, "matched": true, "contains": true,
	"has": true, "includes": true, "hit": true, "found": true, "check": true,
	"run_case": true, "testcase": true, "test_case": true, "expect_deny": true,
	"is_blocked": true, "should_block": true, "should_deny": true,
}

// denylistAssignRe is the left-hand side of a scalar assignment sitting right
// before a quoted value: BLOCKED='...' or DENY+="...". The value is masked only
// when it is an alternation list (holds a `|`), which is a pattern, never a
// command the shell runs.
var denylistAssignRe = regexp.MustCompile(`(?:^|[\s;&|(])[A-Za-z_][A-Za-z0-9_]*\+?=$`)

// testOperatorRe is a bash [[ ]] comparison operator whose right-hand side is a
// pattern the guard compares against, not a command: =~, ==, !=.
var testOperatorRe = regexp.MustCompile(`(?:=~|==|!=)`)

// maskGuardPatterns blanks a token where it appears as detect/deny data inside
// a guard or block hook, rather than as the command the hook runs (#1888). The
// deny-data positions are a grep/rg pattern, a case pattern arm, a [[ ]]
// comparison pattern, a quoted argument to a message or guard helper, and the
// alternation value of a denylist assignment. Masked bytes become spaces so
// offsets and the rest of the command keep their meaning, and an executed
// token (shred -u ~/.bash_history, cat ~/.ssh/id_rsa) stays visible. A command
// substitution inside double quotes is kept, since the shell runs what is in
// it. Shared by CFG037 and CFG077.
func maskGuardPatterns(cmd string) string {
	masked := []byte(cmd)

	// grep/rg quoted pattern arguments.
	for _, match := range grepPatternRe.FindAllStringSubmatchIndex(cmd, -1) {
		if len(match) < 6 || match[4] < 0 || grepUsesPatternFile(cmd[match[2]:match[3]]) {
			continue
		}
		if containsExecutableSubstitution(cmd[match[4]:match[5]]) {
			continue
		}
		blankSpan(masked, match[4], match[5])
	}

	// [[ ... (=~|==|!=) pattern ]] comparison right-hand side.
	maskTestGuardPatterns(masked, cmd)

	// case pattern arms.
	for _, body := range caseBodyRe.FindAllStringSubmatchIndex(cmd, -1) {
		if len(body) < 4 || body[2] < 0 {
			continue
		}
		for _, m := range casePatternRe.FindAllStringSubmatchIndex(cmd[body[2]:body[3]], -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			from, to := body[2]+m[2], body[2]+m[3]
			if containsExecutableSubstitution(cmd[from:to]) {
				continue
			}
			blankSpan(masked, from, to)
		}
	}

	// Quoted arguments to a message or guard helper, and denylist alternation
	// assignments.
	maskGuardQuotes(masked, cmd)
	return string(masked)
}

// maskGuardQuotes blanks the content of a quoted string that a message or
// guard helper matches or reports, or that holds a denylist alternation on the
// right of an assignment. A $(...) or backtick substitution inside double
// quotes is kept. The scan resets at an unquoted command separator so each
// segment is judged by its own leading command word.
func maskGuardQuotes(masked []byte, cmd string) {
	segStart := 0
	for i := 0; i < len(cmd); i++ {
		switch c := cmd[i]; c {
		case '|', ';', '&', '\n', '(', ')', '`':
			segStart = i + 1
		case '\\':
			i++
		case '\'', '"':
			end := closingQuote(cmd, i)
			if end < 0 {
				return
			}
			seg := cmd[segStart:i]
			body := cmd[i+1 : end]
			if guardMasksQuotes(seg) || denylistAlternation(seg, body, c) {
				blankQuotedSpan(masked, cmd, i+1, end, c == '"')
			}
			i = end
		}
	}
}

// guardMasksQuotes reports whether the quoted strings after seg, the start of a
// command, are what a message or guard helper matches or reports: a guard
// hook's list of the names it refuses is data, not a command.
func guardMasksQuotes(seg string) bool {
	if strings.Contains(seg, "[[") && testOperatorRe.MatchString(seg) {
		return true
	}
	for _, f := range strings.Fields(seg) {
		if arrayLiteralRe.MatchString(f) {
			return true
		}
		f = strings.TrimLeft(f, "({!")
		switch {
		case f == "" || f == "if" || f == "then" || f == "else" || f == "elif" ||
			f == "do" || f == "while" || f == "until" || f == "sudo" || f == "command" || f == "builtin":
			continue
		case strings.Contains(f, "=") && !strings.HasPrefix(f, "-"):
			continue
		}
		lf := strings.ToLower(f)
		if grepCommands[lf] {
			// grep KEYFILE with -f reads the file, so it is not deny data.
			return !grepUsesPatternFile(seg)
		}
		return messageCommands[lf] || guardHelperCommands[lf]
	}
	return false
}

// denylistAlternation reports whether the quoted value body is an alternation
// denylist on the right of an assignment (CLOBBER='rm|shred|unlink'): seg ends
// in NAME=, the value holds a `|`, and nothing in it runs.
func denylistAlternation(seg, body string, quote byte) bool {
	if !denylistAssignRe.MatchString(seg) || !strings.Contains(body, "|") {
		return false
	}
	if quote == '"' && containsExecutableSubstitution(`"`+body+`"`) {
		return false
	}
	return true
}

// blankSpan replaces masked[from:to] with spaces, keeping newlines.
func blankSpan(masked []byte, from, to int) {
	for i := from; i < to && i < len(masked); i++ {
		if masked[i] != '\n' {
			masked[i] = ' '
		}
	}
}

// blankQuotedSpan blanks masked[from:to], reading structure from the original
// cmd so an earlier mask pass cannot change what counts as a substitution. A
// $(...) or backtick inside a double-quoted string is kept, since it runs.
func blankQuotedSpan(masked []byte, cmd string, from, to int, double bool) {
	depth := 0
	tick := false
	for j := from; j < to && j < len(masked); j++ {
		switch {
		case double && !tick && cmd[j] == '$' && j+1 < to && cmd[j+1] == '(':
			depth++
			j++ // keep the "$(" and skip it
			continue
		case double && depth > 0 && cmd[j] == ')':
			depth--
			continue
		case double && depth == 0 && cmd[j] == '`':
			tick = !tick
			continue
		}
		if depth == 0 && !tick && cmd[j] != '\n' {
			masked[j] = ' '
		}
	}
}
