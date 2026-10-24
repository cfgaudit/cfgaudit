// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"regexp"
	"strings"
)

// Claude Code expands `@path` imports in CLAUDE.md, CLAUDE.local.md, AGENTS.md
// and .claude/rules files, loading the imported file into the same context
// (#794). The pattern and the two path checks are the ones in the 2.1.310
// binary, where they sit next to each other:
//
//	/(?:^|\s)@((?:[^\s\\]|\\ )+)/g
//	/^[#%^&*()]+/
//	/^[a-zA-Z0-9._-]/
var (
	claudeImportRe      = regexp.MustCompile(`(?:^|\s)@((?:[^\s\\]|\\ )+)`)
	claudeImportJunkRe  = regexp.MustCompile(`^[#%^&*()]+`)
	claudeImportStartRe = regexp.MustCompile(`^[a-zA-Z0-9._-]`)

	mdFenceOpenRe = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
	mdHTMLBlockRe = regexp.MustCompile(`^ {0,3}</?[A-Za-z][A-Za-z0-9-]*(\s|/?>|$)`)
	mdListItemRe  = regexp.MustCompile(`^\s*([-*+]|\d+[.)])(\s|$)`)
)

// InstructionImports returns the paths a Claude Code instruction file imports,
// in file order and without duplicates. A path is returned as written, with a
// `#fragment` cut off and `\ ` turned into a space; resolving it is left to the
// caller.
//
// Measured with 2.1.310 against a capture endpoint: an import is read in plain
// text, list items, headings, block quotes and table cells, and at the start of
// a line or after a tab. It is not read inside a code span (single or double
// backticks), a fenced (``` or ~~~) or indented code block, an HTML comment
// (inline or block) or an HTML block, nor when something other than whitespace
// precedes the `@` (`user@host`, `(@x.md)`, `[l](@x.md)`), nor when the path is
// quoted (`@"x.md"`) or starts with `#`. Trailing punctuation stays part of the
// path, so `@x.md.` names a file "x.md." that is usually absent.
func InstructionImports(content string) []string {
	text := maskNonText(content)
	var out []string
	seen := map[string]bool{}
	for _, m := range claudeImportRe.FindAllStringSubmatch(text, -1) {
		p := m[1]
		if i := strings.IndexByte(p, '#'); i >= 0 {
			p = p[:i]
		}
		p = strings.ReplaceAll(p, `\ `, " ")
		if !validImportPath(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// validImportPath is Claude Code's check on an import path.
func validImportPath(p string) bool {
	switch {
	case p == "":
		return false
	case strings.HasPrefix(p, "./"), strings.HasPrefix(p, "~/"):
		return true
	case strings.HasPrefix(p, "/"):
		return p != "/"
	}
	return !strings.HasPrefix(p, "@") && !claudeImportJunkRe.MatchString(p) && claudeImportStartRe.MatchString(p)
}

// maskNonText replaces the Markdown that Claude Code does not search for
// imports (code blocks, code spans, HTML comments and HTML blocks) with NUL
// bytes, keeping line breaks. NUL is not whitespace, so text right after a
// masked span does not start an import, except after a code span (see
// maskCodeSpans).
func maskNonText(content string) string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var (
		fence    string // the opening run of the fenced block we are in
		html     bool   // inside an HTML block, until a blank line
		prevText bool   // the previous line was non-blank text
		listOpen bool   // a list item came after the last top-level paragraph
	)
	for i, line := range lines {
		blank := strings.TrimSpace(line) == ""
		switch {
		case fence != "":
			if closesFence(line, fence) {
				fence = ""
			}
			lines[i] = mask(line)
			continue
		case html:
			if blank {
				html = false
			} else {
				lines[i] = mask(line)
			}
			prevText = false
			continue
		}
		if m := mdFenceOpenRe.FindStringSubmatch(line); m != nil {
			fence = m[1]
			lines[i] = mask(line)
			prevText = false
			continue
		}
		if !prevText && mdHTMLBlockRe.MatchString(line) {
			html = true
			lines[i] = mask(line)
			continue
		}
		indented := strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t")
		if indented && !blank && !prevText && !listOpen {
			lines[i] = mask(line)
			continue
		}
		switch {
		case blank:
		case mdListItemRe.MatchString(line):
			listOpen = true
		case !indented:
			listOpen = false
		}
		prevText = !blank
	}
	return maskCodeSpans(maskHTMLComments(strings.Join(lines, "\n")))
}

// closesFence reports whether line closes a fenced block opened with open: the
// same character, at least as many of them, and nothing else on the line.
func closesFence(line, open string) bool {
	t := strings.TrimLeft(line, " ")
	if len(line)-len(t) > 3 {
		return false
	}
	run := strings.TrimLeft(t, open[:1])
	return len(t)-len(run) >= len(open) && strings.TrimSpace(run) == ""
}

// maskHTMLComments masks every <!-- ... --> span; an unclosed one runs to the
// end of the text.
func maskHTMLComments(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "<!--")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		rest := s[i:]
		end := strings.Index(rest[4:], "-->")
		if end < 0 {
			b.WriteString(mask(rest))
			return b.String()
		}
		b.WriteString(mask(rest[:4+end+3]))
		s = rest[4+end+3:]
	}
}

// maskCodeSpans masks inline code: a run of backticks up to the next run of the
// same length. A run with no partner is literal text and stays.
//
// Claude Code matches the import pattern per text token, so its `^` also
// matches right after a code span: `x`@a.md imports a.md on 2.1.310. A line
// break after the masked span reproduces that.
func maskCodeSpans(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '`' {
			b.WriteByte(s[i])
			i++
			continue
		}
		n := backtickRun(s, i)
		end := -1
		for j := i + n; j < len(s); {
			if s[j] != '`' {
				j++
				continue
			}
			m := backtickRun(s, j)
			if m == n {
				end = j + m
				break
			}
			j += m
		}
		if end < 0 {
			b.WriteString(s[i : i+n])
			i += n
			continue
		}
		b.WriteString(mask(s[i:end]))
		b.WriteByte('\n')
		i = end
	}
	return b.String()
}

func backtickRun(s string, i int) int {
	n := 0
	for i+n < len(s) && s[i+n] == '`' {
		n++
	}
	return n
}

// mask replaces every byte of s except line breaks with NUL.
func mask(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] != '\n' {
			b[i] = 0
		}
	}
	return string(b)
}
