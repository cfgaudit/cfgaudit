// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg137 struct{}

var CFG137 = &cfg137{}

func init() { All = append(All, CFG137) }

func (r *cfg137) ID() string { return "CFG137" }

// isSpaceSeparator reports whether r is a blank character for CFG137: a space,
// a tab, or a Unicode space separator (Zs), such as U+00A0 and U+3000. Runs
// are counted in runes, not bytes.
func isSpaceSeparator(r rune) bool {
	return r == ' ' || r == '\t' || unicode.Is(unicode.Zs, r)
}

// Check reports instruction text hidden behind a long run (150 or more) of
// blank characters (#1718): visible text, then 150+ spaces/tabs/Unicode space
// separators, then more visible text. Markdown tables and fenced code blocks
// are skipped, as are runs followed only by a table cell separator or a
// comment terminator.
func (r *cfg137) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, src := range t.instructionSources(r.ID()) {
		inFence := false
		for lineNo, line := range strings.Split(src.Content, "\n") {
			if isFenceDelimiter(line) {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			trimmed := strings.TrimSpace(line)
			// Skip Markdown table rows.
			if strings.HasPrefix(trimmed, "|") || strings.Count(line, "|") >= 2 {
				continue
			}
			runes := []rune(line)
			seenVisible := false
			i := 0
			reported := false
			for i < len(runes) {
				if isSpaceSeparator(runes[i]) {
					j := i
					for j < len(runes) && isSpaceSeparator(runes[j]) {
						j++
					}
					runLen := j - i
					hasVisibleAfter := false
					for k := j; k < len(runes); k++ {
						if !isSpaceSeparator(runes[k]) {
							hasVisibleAfter = true
							break
						}
					}
					if runLen >= 150 && seenVisible && hasVisibleAfter {
						after := strings.TrimSpace(string(runes[j:]))
						if after != "|" && after != "-->" && after != "*/" {
							quoteEnd := j + 60
							if quoteEnd > len(runes) {
								quoteEnd = len(runes)
							}
							quote := string(runes[j:quoteEnd])
							out = append(out, finding.Finding{
								RuleID:   "CFG137",
								Severity: finding.Warn,
								File:     src.File,
								Line:     lineNo + 1,
								Col:      j + 1,
								Message:  fmt.Sprintf("%s line %d hides text behind %d blank characters: %q", src.Name, lineNo+1, runLen, quote),
							})
							reported = true
							break
						}
					}
					i = j
				} else {
					seenVisible = true
					i++
				}
			}
			if reported {
				// one finding per line is enough
			}
		}
	}
	return out
}
