// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
)

// CodexRule is one prefix_rule of a Codex .rules file. Pattern is a list of
// token positions, each with its alternatives. Decision is allow, prompt or
// forbidden, allow by default.
type CodexRule struct {
	Pattern  [][]string
	Decision string
}

// starlarkScanner walks the literal part of a .rules file. The files are
// Starlark, so a rule built from variables or a loop has no literal pattern and
// is skipped.
type starlarkScanner struct {
	s string
	i int
}

func (p *starlarkScanner) space() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		case '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

// str reads a quoted string at the cursor.
func (p *starlarkScanner) str() (string, bool) {
	if p.i >= len(p.s) || (p.s[p.i] != '"' && p.s[p.i] != '\'') {
		return "", false
	}
	quote := p.s[p.i]
	var b strings.Builder
	for p.i++; p.i < len(p.s); p.i++ {
		c := p.s[p.i]
		switch {
		case c == quote:
			p.i++
			return b.String(), true
		case c == '\\' && p.i+1 < len(p.s):
			p.i++
			b.WriteByte(p.s[p.i])
		default:
			b.WriteByte(c)
		}
	}
	return "", false
}

// strList reads a list of strings, with the cursor on its opening bracket.
func (p *starlarkScanner) strList() ([]string, bool) {
	var out []string
	p.i++
	for {
		p.space()
		if p.i >= len(p.s) {
			return nil, false
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, true
		}
		s, ok := p.str()
		if !ok {
			return nil, false
		}
		out = append(out, s)
		p.space()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
		}
	}
}

// pattern reads a pattern list: each element a string, or a list of
// alternatives.
func (p *starlarkScanner) pattern() ([][]string, bool) {
	if p.i >= len(p.s) || p.s[p.i] != '[' {
		return nil, false
	}
	p.i++
	var out [][]string
	for {
		p.space()
		if p.i >= len(p.s) {
			return nil, false
		}
		switch p.s[p.i] {
		case ']':
			p.i++
			return out, len(out) > 0
		case ',':
			p.i++
		case '[':
			alts, ok := p.strList()
			if !ok {
				return nil, false
			}
			out = append(out, alts)
		default:
			s, ok := p.str()
			if !ok {
				return nil, false
			}
			out = append(out, []string{s})
		}
	}
}

// skipValue moves past one argument value, balancing brackets and strings.
func (p *starlarkScanner) skipValue() {
	depth := 0
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == '"' || c == '\'':
			if _, ok := p.str(); !ok {
				return
			}
			continue
		case c == '#':
			p.space()
			continue
		case c == '[' || c == '(' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ')':
			if depth == 0 {
				return
			}
			depth--
		case c == ',' && depth == 0:
			return
		}
		p.i++
	}
}

// rule reads the arguments after prefix_rule(.
func (p *starlarkScanner) rule() (CodexRule, bool) {
	r := CodexRule{Decision: "allow"}
	for {
		p.space()
		if p.i >= len(p.s) {
			return r, false
		}
		if p.s[p.i] == ')' {
			p.i++
			return r, len(r.Pattern) > 0
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		start := p.i
		for p.i < len(p.s) && (p.s[p.i] == '_' || p.s[p.i] >= 'a' && p.s[p.i] <= 'z') {
			p.i++
		}
		name := p.s[start:p.i]
		p.space()
		if name == "" || p.i >= len(p.s) || p.s[p.i] != '=' {
			return r, false
		}
		p.i++
		p.space()
		switch name {
		case "pattern":
			pattern, ok := p.pattern()
			if !ok {
				return r, false
			}
			r.Pattern = pattern
		case "decision":
			d, ok := p.str()
			if !ok {
				return r, false
			}
			r.Decision = d
		default:
			p.skipValue()
		}
	}
}

// ParseCodexRules returns the prefix rules of a .rules file whose pattern is
// written literally.
func ParseCodexRules(content string) []CodexRule {
	var out []CodexRule
	p := &starlarkScanner{s: content}
	for {
		p.space()
		if p.i >= len(p.s) {
			return out
		}
		if strings.HasPrefix(p.s[p.i:], "prefix_rule(") {
			p.i += len("prefix_rule(")
			if r, ok := p.rule(); ok {
				out = append(out, r)
			}
			continue
		}
		if p.s[p.i] == '"' || p.s[p.i] == '\'' {
			if _, ok := p.str(); !ok {
				return out
			}
			continue
		}
		p.i++
	}
}

// MatchesPrefix reports whether the rule's pattern is a token prefix of command.
func (r CodexRule) MatchesPrefix(command []string) bool {
	if len(r.Pattern) > len(command) {
		return false
	}
	for i, alts := range r.Pattern {
		found := false
		for _, a := range alts {
			found = found || a == command[i]
		}
		if !found {
			return false
		}
	}
	return true
}

// Under reports whether the rule names a command that starts with prefix, as a
// rule for git push --force does under git push.
func (r CodexRule) Under(prefix []string) bool {
	if len(r.Pattern) < len(prefix) {
		return false
	}
	for i, tok := range prefix {
		found := false
		for _, a := range r.Pattern[i] {
			found = found || a == tok
		}
		if !found {
			return false
		}
	}
	return true
}
