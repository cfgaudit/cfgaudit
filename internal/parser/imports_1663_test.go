// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"slices"
	"testing"
)

// #1663: a backtick is not paired with one in another table row or past a
// paragraph break, so a stray backtick in a table does not unmask a code span
// further down.
func TestInstructionImports_CodeSpansStayInTheirBlock1663(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{"stray backtick in a table row", "| a | `x |\n| b | y |\n\nSee `@~/notes.md` here.\n", nil},
		{"stray double backticks in table rows", "| a | ``x |\n| b | `y` |\n| c | z`` |\n\nSee `@~/notes.md`.\n", nil},
		{"stray backtick before a paragraph break", "Run `make\n\nthen read `@~/notes.md` too.\n", nil},
		{"a span may still wrap inside a paragraph", "Read `this\n@~/notes.md` and go.\n", nil},
		{"text after a stray table backtick is read", "| a | `x |\n\n@~/notes.md\n", []string{"~/notes.md"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InstructionImports(tt.content); !slices.Equal(got, tt.want) {
				t.Errorf("InstructionImports(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}
