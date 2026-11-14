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
	// printed is true for an argument of echo, or of printf after its format:
	// the shell splits and globs the value but does not run it (#1558).
	printed bool
	// assignTo names the variable whose assignment this reference is the
	// value of (NAME=$x, NAME="$x"). The shell neither splits nor globs it
	// there, so it matters only where NAME itself is used unsafely (#1674).
	assignTo string
}

// printSafeRe matches what makes a printed value reach a parser or a program
// after all: process substitution, a pipe into a shell, an interpreter or
// xargs, which hands the words to a program as arguments, and a write to a
// file that is read back as code or settings. Claude Code sources
// $CLAUDE_ENV_FILE before later Bash commands, and GitHub Actions reads
// $GITHUB_ENV, $GITHUB_PATH and $GITHUB_OUTPUT as NAME=value lines.
var printSafeRe = regexp.MustCompile(`[<>]\(|\|\s*(?:sudo\s+)?(?:(?:ba|da|k|z)?sh|python[0-9.]*|node|perl|ruby|php|pwsh|powershell|bun|deno|source|eval|xargs)\b|>\s*"?\$\{?(?:CLAUDE_ENV_FILE|GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)\b`)

// printSafe reports whether a printed reference in cmd stays text.
func printSafe(cmd string) bool {
	return !printSafeRe.MatchString(cmd)
}

// shellReparseRe matches a command that hands text to a shell or another
// interpreter to parse again, which undoes any quoting around a variable. The
// dot builtin counts only in command position: jq's `.` program is an
// argument (#1674).
var shellReparseRe = regexp.MustCompile(`\beval\b|\b(?:ba|da|k|z)?sh\s+(?:-[a-z]*\s+)*-[a-z]*c\b|\bxargs\b[^|;&]*\b(?:ba|da|k|z)?sh\b|\bsource\b|(?:^|[;&|(]\s*|\b(?:then|do|else)\s+)\.\s`)

// reparses reports whether cmd hands text to be parsed again, judged on its
// unquoted words only: "source" in a quoted message or a jq program is text,
// not the source builtin (#1674).
func reparses(cmd string) bool {
	return shellReparseRe.MatchString(unquotedText(cmd))
}

// unquotedText is cmd with the content of every single- and double-quoted
// string, and every backslash-escaped character, replaced by "Q". The quotes
// stay, so "bash -c "$CMD"" still reads as a shell given a script.
func unquotedText(cmd string) string {
	var b strings.Builder
	var inSingle, inDouble bool
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
				b.WriteByte(c)
			} else {
				b.WriteByte('Q')
			}
		case inDouble:
			switch c {
			case '\\':
				i++
				b.WriteByte('Q')
			case '"':
				inDouble = false
				b.WriteByte(c)
			case '$':
				// "$(...)" runs a command of its own, quoting and all.
				if end := substEnd(cmd, i); end > 0 {
					b.WriteString("$(" + unquotedText(cmd[i+2:end]) + ")")
					i = end
					continue
				}
				b.WriteByte('Q')
			default:
				b.WriteByte('Q')
			}
		case c == '\\':
			i++
			b.WriteByte('Q')
		case c == '\'':
			inSingle = true
			b.WriteByte(c)
		case c == '"':
			inDouble = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// quotedVarWordRe is the content of a double-quoted string that is a single
// variable reference, optionally with path characters around it.
var quotedVarWordRe = regexp.MustCompile(`^[A-Za-z0-9_./:@+=-]*\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)[A-Za-z0-9_./:@+=-]*$`)

// plainParamExpRe matches ${NAME:-word}, ${NAME:+word}, ${NAME-word} and
// ${NAME:?word} whose word holds only path characters and other references
// (#1674). Quoted, such an expansion is one argument, like "${NAME}".
var plainParamExpRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-+?]|-)(?:[A-Za-z0-9_./:@+=-]|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)*\}`)

// quotedOneWord reports whether the content of a double-quoted string is one
// reference with path characters around it, counting a plain parameter
// expansion with a default or alternative word as the reference it is.
func quotedOneWord(content string) bool {
	return quotedVarWordRe.MatchString(plainParamExpRe.ReplaceAllString(content, "$${$1}"))
}

// shellVarUses returns every variable reference in cmd with its quoting. It
// follows single and double quotes, backslash escapes and command position
// (start of the line, after ; & | ( or a newline, and after leading NAME=value
// assignments), and it reads a $(...) inside double quotes as a command of its
// own, so "$(dirname "$f")" holds a quoted $f (#1376). It is not a shell parser:
// backticks inside double quotes are treated as quoted text.
func shellVarUses(cmd string) []shellVarUse {
	var (
		out      []shellVarUse
		cmdPos   = true // the current word is a command name
		cmdName  string // the command name of the current simple command
		argIdx   int    // words after the command name so far
		printfV  bool   // printf -v, which assigns instead of printing
		redir    bool   // the next word is a redirection target
		subst    int    // depth of unquoted $( ) around the current word
		inBack   bool   // inside unquoted backticks
		word     strings.Builder
		dqStart  = -1 // index of the content after an opening ", or -1
		dqUses   []int
		inSingle bool
	)
	endWord := func() {
		w := word.String()
		if w != "" {
			if cmdPos && !assignmentRe.MatchString(w) {
				cmdName, argIdx, printfV = w, 0, false
			} else if !cmdPos {
				argIdx++
				printfV = printfV || (cmdName == "printf" && w == "-v")
			}
			redir = strings.Trim(w, "0123456789&") == ">" || strings.Trim(w, "0123456789&") == ">>" || w == "<"
			// NAME=value before a command keeps the next word in command
			// position, and so does a reserved word: in `then p="$x"` the
			// assignment is the command (#1674).
			cmdPos = assignmentRe.MatchString(w) || (cmdPos && shellReservedWords[w])
		}
		word.Reset()
	}
	// A redirection target is a path the shell opens, not printed text.
	printing := func() bool {
		// Output of a substitution becomes words of another command (#1558).
		if cmdPos || redir || subst > 0 || inBack || strings.ContainsAny(word.String(), "<>") {
			return false
		}
		return cmdName == "echo" || (cmdName == "printf" && argIdx > 0 && !printfV)
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
				safe := !cmdPos && quotedOneWord(cmd[dqStart:i])
				assign := ""
				if cmdPos {
					assign = assignedName(word.String())
				}
				for _, k := range dqUses {
					out[k].safe = safe
					out[k].assignTo = assign
				}
				dqStart, dqUses = -1, nil
			case '$':
				if end := substEnd(cmd, i); end > 0 {
					inner := shellVarUses(cmd[i+2 : end])
					for k := range inner {
						inner[k].printed = false
					}
					out = append(out, inner...)
					i = end
					continue
				}
				if name, n := varRefAt(cmd, i); n > 0 {
					dqUses = append(dqUses, len(out))
					out = append(out, shellVarUse{name: name, printed: printing()})
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
			case '`':
				inBack = !inBack
				word.Reset()
				cmdPos, cmdName, redir = true, "", false
			case ')':
				if subst > 0 {
					subst--
				}
				word.WriteByte(c)
			case ';', '&', '|', '(', '\n':
				if c == '(' && i > 0 && cmd[i-1] == '$' {
					subst++
				}
				word.Reset()
				cmdPos, cmdName, redir = true, "", false
			case '$':
				if name, n := varRefAt(cmd, i); n > 0 {
					assign := ""
					if cmdPos {
						assign = assignedName(word.String())
					}
					out = append(out, shellVarUse{name: name, printed: printing(), assignTo: assign})
					i += n - 1
				}
				word.WriteByte(c)
			default:
				word.WriteByte(c)
			}
		}
	}
	// An unclosed double quote leaves its references unsafe (safe is false),
	// and they do not count as printed: the shell rejects the command.
	for _, k := range dqUses {
		out[k].printed = false
	}
	return out
}

// substEnd returns the index of the ")" that closes the command substitution
// starting with "$(" at cmd[i], or 0 when there is none or it is arithmetic.
func substEnd(cmd string, i int) int {
	if !strings.HasPrefix(cmd[i:], "$(") || strings.HasPrefix(cmd[i:], "$((") {
		return 0
	}
	depth := 1
	var inSingle, inDouble bool
	for j := i + 2; j < len(cmd); j++ {
		c := cmd[j]
		switch {
		case inSingle:
			inSingle = c != '\''
		case c == '\\':
			j++
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if end := substEnd(cmd, j); end > 0 {
				j = end
			}
		case c == '"':
			inDouble = true
		case c == '\'':
			inSingle = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return 0
}

var assignmentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// assignedName returns NAME when word starts an assignment NAME=..., or "".
func assignedName(word string) string {
	if m := assignmentRe.FindString(word); m != "" {
		return strings.TrimSuffix(m, "=")
	}
	return ""
}

// shellReservedWords are the words after which the next word starts a command.
var shellReservedWords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true, "time": true,
}

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
