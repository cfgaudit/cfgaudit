// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"reflect"
	"testing"
)

// The cases are the probe files from #794: each line was a CLAUDE.md that
// Claude Code 2.1.310 sent to a capture endpoint, and want is what it loaded.
func TestInstructionImports(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{"plain", "See @a.md for more.", []string{"a.md"}},
		{"line start", "@a.md", []string{"a.md"}},
		{"after tab", "tab\t@a.md", []string{"a.md"}},
		{"dot slash", "@./a.md", []string{"./a.md"}},
		{"home", "@~/notes.md", []string{"~/notes.md"}},
		{"absolute", "@/repo/a.md", []string{"/repo/a.md"}},
		{"root alone", "@/", nil},
		{"parent", "@../out.md", []string{"../out.md"}},
		{"fragment", "@frag.md#section", []string{"frag.md"}},
		{"only a fragment", "@#h.md", nil},
		{"escaped space", `@sp\ ace.md`, []string{"sp ace.md"}},
		{"glob characters", "@g*.md", []string{"g*.md"}},
		{"leading dash", "@-dash.md", []string{"-dash.md"}},
		{"trailing period kept", "@t.md.", []string{"t.md."}},
		{"trailing comma kept", "@u.md,", []string{"u.md,"}},
		{"quoted", `@"q.md"`, nil},
		{"scoped package", "@@scope/pkg", nil},
		{"email", "user@e.md", nil},
		{"parenthesis", "(@paren.md)", nil},
		{"link target", "[link](@lk.md)", nil},
		{"list item", "- item @li.md", []string{"li.md"}},
		{"heading", "# Heading @hd.md", []string{"hd.md"}},
		{"block quote", "> quote @bq.md", []string{"bq.md"}},
		{"table cell", "| t | @tb.md |\n|---|---|", []string{"tb.md"}},
		{"code span", "code `@c.md` here", nil},
		{"double backtick span", "``@dbl.md`` and ``x `@dbl2.md` y``", nil},
		{"unclosed backtick", "unclosed `@unc.md", nil},
		{"after code span", "`x` @after.md", []string{"after.md"}},
		{"right after code span", "`x`@tight.md", []string{"tight.md"}},
		{"fenced", "```\n@f.md\n```\n@after.md", []string{"after.md"}},
		{"tilde fence", "~~~\n@tilde.md\n~~~", nil},
		{"longer closing fence", "```\n@f.md\n`````\n@after.md", []string{"after.md"}},
		{"shorter run does not close", "````\n```\n@f.md\n````\n@after.md", []string{"after.md"}},
		{"unclosed fence", "```\n@f.md", nil},
		{"indented code", "text\n\n    @ind.md\n\n@after.md", []string{"after.md"}},
		{"indented list continuation", "- item\n\n    @cont.md", []string{"cont.md"}},
		{"lazy paragraph line", "text\n    @lazy.md", []string{"lazy.md"}},
		{"html comment inline", "inline <!-- @ic.md --> text @after.md", []string{"after.md"}},
		{"html comment block", "<!--\n@mlc.md\n-->\n\n@after.md", []string{"after.md"}},
		{"unclosed html comment", "<!-- @x.md\n@y.md", nil},
		{"html block", "\n<div>\n@dv.md\n</div>\n\n@after.md", []string{"after.md"}},
		{"autolink is not html", "<https://example.com>\n@after.md", []string{"after.md"}},
		{"duplicates", "@a.md and @a.md", []string{"a.md"}},
		{"crlf", "one @a.md\r\ntwo @b.md\r\n", []string{"a.md", "b.md"}},
		{"backslash ends path", `@a\b.md`, []string{"a"}},
		{"percent start", "@%x.md", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InstructionImports(tt.content); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InstructionImports(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}
