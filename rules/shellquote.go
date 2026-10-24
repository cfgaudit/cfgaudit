// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// shellVarUse is one $NAME or ${NAME} reference in a hook command, with the
// quoting the shell sees it in (#792).
type shellVarUse struct {
	name string
	// safe is true for a reference the shell expands as one argument and never
	// parses again: inside double quotes that hold nothing but the reference
	// and path characters ("$f", "${f}.bak"), not in command position.
	safe bool
	// literal is true inside single quotes, where the shell does not expand it.
	literal bool
}

// shellReparseRe matches a command that hands text to a shell or another
// interpreter to parse again, which undoes any quoting around a variable.
var shellReparseRe = regexp.MustCompile(`\beval\b|\b(?:ba|da|k|z)?sh\s+(?:-[a-z]*\s+)*-[a-z]*c\b|\bxargs\b[^|;&]*\b(?:ba|da|k|z)?sh\b|\bsource\b|(?:^|[;&|(]\s*|\s)\.\s`)

// quotedVarWordRe is the content of a double-quoted string that is a single
// variable reference, optionally with path characters around it.
var quotedVarWordRe = regexp.MustCompile(`^[A-Za-z0-9_./:@+=-]*\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)[A-Za-z0-9_./:@+=-]*$`)

// shellVarUses returns every variable reference in cmd with its quoting. It
// follows single and double quotes, backslash escapes and command position
// (start of the line, after ; & | ( or a newline, and after leading NAME=value
// assignments). It is not a shell parser: nested $(...) inside double quotes
// is treated as quoted text.
func shellVarUses(cmd string) []shellVarUse {
	var (
		out      []shellVarUse
		cmdPos   = true // the current word is a command name
		word     strings.Builder
		dqStart  = -1 // index of the content after an opening ", or -1
		dqUses   []int
		inSingle bool
	)
	endWord := func() {
		w := word.String()
		if w != "" {
			// NAME=value before a command keeps the next word in command position.
			cmdPos = assignmentRe.MatchString(w)
		}
		word.Reset()
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case inSingle:
			switch c {
			case '\'':
				inSingle = false
			case '$':
				if name, n := varRefAt(cmd, i); n > 0 {
					out = append(out, shellVarUse{name: name, literal: true})
					i += n - 1
				}
			}
			word.WriteByte(c)
		case dqStart >= 0:
			switch c {
			case '\\':
				i++
			case '"':
				safe := !cmdPos && quotedVarWordRe.MatchString(cmd[dqStart:i]) && len(dqUses) == 1
				for _, k := range dqUses {
					out[k].safe = safe
				}
				dqStart, dqUses = -1, nil
			case '$':
				if name, n := varRefAt(cmd, i); n > 0 {
					dqUses = append(dqUses, len(out))
					out = append(out, shellVarUse{name: name})
					i += n - 1
				}
			}
			word.WriteByte(c)
		default:
			switch c {
			case '\\':
				i++
				word.WriteByte('x')
			case '\'':
				inSingle = true
				word.WriteByte(c)
			case '"':
				dqStart = i + 1
				word.WriteByte(c)
			case ' ', '\t':
				endWord()
			case ';', '&', '|', '(', '\n':
				word.Reset()
				cmdPos = true
			case '$':
				if name, n := varRefAt(cmd, i); n > 0 {
					out = append(out, shellVarUse{name: name})
					i += n - 1
				}
				word.WriteByte(c)
			default:
				word.WriteByte(c)
			}
		}
	}
	// An unclosed double quote leaves its references unsafe (safe is false).
	return out
}

var assignmentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// varRefAt returns the name of the $NAME or ${NAME} reference at cmd[i] and
// its length, or 0 when there is none ($(, $1, $@ and the like).
func varRefAt(cmd string, i int) (string, int) {
	m := hookVarRe.FindStringSubmatchIndex(cmd[i:])
	if m == nil || m[0] != 0 {
		return "", 0
	}
	if m[2] >= 0 {
		return cmd[i+m[2] : i+m[3]], m[1]
	}
	return cmd[i+m[4] : i+m[5]], m[1]
}
