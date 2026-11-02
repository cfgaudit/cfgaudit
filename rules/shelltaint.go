// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// Taint tracking inside one hook command for CFG009 (#1199). A variable the
// command assigns itself is untrusted only when its value reads the hook's
// stdin, the skill's $ARGUMENTS, a positional parameter or another untrusted
// variable. A variable the command never assigns comes from the environment
// and stays untrusted, unless it is in safeShellVars. This is a file-level
// approximation: assignments are found anywhere in the command, functions and
// other files are not followed, and one untrusted assignment taints the name.

// assignStartRe finds NAME= at the start of a word, also after local, export,
// readonly, declare and typeset with their options.
var assignStartRe = regexp.MustCompile("(?:^|[\\s;&|(`])(?:(?:local|export|readonly|declare|typeset)(?:\\s+-[A-Za-z]+)*\\s+)?([A-Za-z_][A-Za-z0-9_]*)\\+?=")

// forLoopRe finds `for NAME in LIST` and captures the list up to the next ; or
// newline.
var forLoopRe = regexp.MustCompile(`\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b([^;\n]*)`)

// readNamesRe finds read, mapfile and readarray with their arguments; every
// name they set holds stdin.
var readNamesRe = regexp.MustCompile(`\b(?:read|mapfile|readarray)\b([^;&|\n)]*)`)

// stdinValueRe matches a value that reads the hook's input: a program that
// reads stdin by default, Python's or Node's stdin, $ARGUMENTS, or a
// positional parameter. `cat FILE` matches too, which errs on the side of
// reporting.
var stdinValueRe = regexp.MustCompile(`(?i)\b(?:jq|cat|read|head|tail|tee|xargs)\b|json\.load|sys\.stdin|/dev/stdin|\bstdin\b|readFileSync\(\s*0|ReadToEnd|\[Console\]::In|\$input\b|Read-Host|\$\{?(?:ARGUMENTS\b|[0-9@*])`)

// readOptsWithArg are the read options that take a value.
var readOptsWithArg = map[string]bool{"-p": true, "-d": true, "-t": true, "-n": true, "-N": true, "-u": true, "-i": true}

// shellTaint maps every name the command assigns to whether it is untrusted.
type shellTaint map[string]bool

// untrusted reports whether a reference to name may carry hook input: an
// untrusted local, or a name the command does not assign at all. outer holds
// the assignments of the enclosing command for a nested `sh -c` body.
func (st shellTaint) untrusted(name string, outer shellTaint) bool {
	if safeShellVars[name] {
		return false
	}
	if tainted, ok := st[name]; ok {
		return tainted
	}
	if outer != nil {
		if tainted, ok := outer[name]; ok {
			return tainted
		}
	}
	return true
}

// commandTaint collects the assignments in cmd and resolves which of them are
// untrusted.
func commandTaint(cmd string, outer shellTaint) shellTaint {
	values := map[string][]string{}
	add := func(name, value string) { values[name] = append(values[name], value) }
	for _, m := range assignStartRe.FindAllStringSubmatchIndex(cmd, -1) {
		add(cmd[m[2]:m[3]], assignedValue(cmd, m[1]))
	}
	for _, m := range forLoopRe.FindAllStringSubmatch(cmd, -1) {
		add(m[1], m[2])
	}
	for _, m := range readNamesRe.FindAllStringSubmatch(cmd, -1) {
		fields := strings.Fields(m[1])
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			if strings.HasPrefix(f, "-") {
				if readOptsWithArg[f] || f == "-a" {
					if f == "-a" && i+1 < len(fields) {
						add(fields[i+1], "/dev/stdin")
					}
					i++
				}
				continue
			}
			if assignmentNameRe.MatchString(f) {
				add(f, "/dev/stdin")
			}
		}
	}
	st := shellTaint{}
	for name := range values {
		st[name] = false
	}
	// Propagate until nothing changes: a value that references an untrusted
	// name is untrusted.
	for changed := true; changed; {
		changed = false
		for name, vs := range values {
			if st[name] {
				continue
			}
			for _, v := range vs {
				if valueUntrusted(v, st, outer) {
					st[name], changed = true, true
					break
				}
			}
		}
	}
	return st
}

var assignmentNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func valueUntrusted(v string, st, outer shellTaint) bool {
	if stdinValueRe.MatchString(v) {
		return true
	}
	for _, m := range hookVarRe.FindAllStringSubmatch(v, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if st.untrusted(name, outer) {
			return true
		}
	}
	return false
}

// assignedValue returns the word that starts at cmd[i]: up to the first
// unquoted blank, ; & | or newline, or an unmatched ), following quotes,
// backticks and $( ) nesting.
func assignedValue(cmd string, i int) string {
	depth := 0
	var inSingle, inDouble, inBack bool
	start := i
	for ; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case c == '\\':
			i++
		case inBack:
			if c == '`' {
				inBack = false
			}
		case c == '`':
			inBack = true
		case c == '(' && i > 0 && cmd[i-1] == '$', c == '(' && depth > 0:
			depth++
		case c == ')' && depth > 0:
			depth--
		case inDouble:
			if c == '"' {
				inDouble = false
			}
		case c == '"':
			inDouble = true
		case c == '\'':
			inSingle = true
		case depth == 0 && strings.IndexByte(" \t\n;&|)", c) >= 0:
			return cmd[start:i]
		}
	}
	return cmd[start:]
}

// singleQuotedShRe finds `sh -c '...'` (and bash, dash, ksh, zsh) whose body is
// one single-quoted word. The outer shell expands nothing in it, so the body
// is checked as a script of its own (#1199). The character after the closing
// quote has to end the word, or the body continues in other quoting.
var xargsRe = regexp.MustCompile(`\bxargs\b`)

var singleQuotedShRe = regexp.MustCompile(`\b((?:ba|da|k|z)?sh\s+(?:-[a-z]*\s+)*-[a-z]*c)\s+'([^']*)'($|[\s;&|)])`)

// splitSingleQuotedSh returns cmd with each single-quoted `sh -c` body
// replaced by an empty command, and the bodies. Under xargs the body receives
// the piped words as positional parameters, which this check does not follow,
// so that form keeps the whole command as one re-parse.
func splitSingleQuotedSh(cmd string) (string, []string) {
	if xargsRe.MatchString(cmd) {
		return cmd, nil
	}
	var bodies []string
	outer := singleQuotedShRe.ReplaceAllStringFunc(cmd, func(m string) string {
		sm := singleQuotedShRe.FindStringSubmatch(m)
		bodies = append(bodies, sm[2])
		return "true" + sm[3]
	})
	return outer, bodies
}
