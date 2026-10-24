// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// literalFilter is a cheap necessary condition for a regular expression: every
// match contains at least one of its strings (compared without case). Most
// lines of an instruction file contain none of a content rule's trigger words,
// and checking for them with a byte search is far cheaper than running a
// case-insensitive regexp over the line, which is where the time went on large
// repositories (#831). A nil filter means none could be derived, and the
// regexp always runs.
type literalFilter []string

// requiredLiterals derives the literalFilter of re from its syntax tree.
func requiredLiterals(re *regexp.Regexp) literalFilter {
	prog, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	set := required(prog.Simplify())
	if len(set) == 0 {
		return nil
	}
	out := make(literalFilter, 0, len(set))
	for _, s := range set {
		if !isASCII(s) {
			// MayMatch folds only ASCII letters.
			return nil
		}
		out = append(out, strings.ToLower(s))
	}
	return out
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// required returns strings of which every match of re contains at least one,
// or nil when there is no such set: a branch that can match without any
// literal (a character class, an optional part, an empty match).
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture:
		return required(re.Sub[0])
	case syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Every part matches, so any part's set is necessary. Pick the one whose
		// shortest string is longest: it rules out the most lines.
		var best []string
		bestLen := 0
		for _, sub := range re.Sub {
			set := required(sub)
			if set == nil {
				continue
			}
			if l := shortest(set); l > bestLen {
				best, bestLen = set, l
			}
		}
		return best
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			set := required(sub)
			if set == nil {
				return nil
			}
			out = append(out, set...)
		}
		return out
	}
	return nil
}

func shortest(set []string) int {
	n := -1
	for _, s := range set {
		if n < 0 || len(s) < n {
			n = len(s)
		}
	}
	return n
}

// MayMatch reports whether s can contain a match. The literals are ASCII, and
// the bytes of a multi-byte UTF-8 character are never ASCII, so a byte search
// on the ASCII-lowered string is exact, except for the two characters that case-insensitive matching folds
// to an ASCII letter: U+017F (long s) and U+212A (Kelvin sign). A string with
// either always may match.
func (f literalFilter) MayMatch(s string) bool {
	if f == nil {
		return true
	}
	if !isASCII(s) && (strings.Contains(s, "\u017f") || strings.Contains(s, "\u212a")) {
		return true
	}
	lower := lowerASCII(s)
	for _, lit := range f {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}

// lowerASCII lower-cases the ASCII letters of s and leaves every other byte as
// it is, so the bytes of a multi-byte character stay intact. It returns s
// itself when there is nothing to change.
func lowerASCII(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// filteredRegexp is a regexp with its literalFilter, for the per-line content
// rules.
type filteredRegexp struct {
	*regexp.Regexp
	filter literalFilter
}

// filtered holds every filteredRegexp, for the test that checks the filters
// never reject a match.
var filtered []filteredRegexp

// mustFiltered is regexp.MustCompile with a literalFilter.
func mustFiltered(expr string) filteredRegexp {
	re := regexp.MustCompile(expr)
	f := filteredRegexp{Regexp: re, filter: requiredLiterals(re)}
	filtered = append(filtered, f)
	return f
}

func (r filteredRegexp) MatchString(s string) bool {
	return r.filter.MayMatch(s) && r.Regexp.MatchString(s)
}

func (r filteredRegexp) FindStringIndex(s string) []int {
	if !r.filter.MayMatch(s) {
		return nil
	}
	return r.Regexp.FindStringIndex(s)
}

func (r filteredRegexp) FindStringSubmatchIndex(s string) []int {
	if !r.filter.MayMatch(s) {
		return nil
	}
	return r.Regexp.FindStringSubmatchIndex(s)
}

func (r filteredRegexp) FindStringSubmatch(s string) []string {
	if !r.filter.MayMatch(s) {
		return nil
	}
	return r.Regexp.FindStringSubmatch(s)
}

func (r filteredRegexp) FindAllStringIndex(s string, n int) [][]int {
	if !r.filter.MayMatch(s) {
		return nil
	}
	return r.Regexp.FindAllStringIndex(s, n)
}

func (r filteredRegexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if !r.filter.MayMatch(s) {
		return nil
	}
	return r.Regexp.FindAllStringSubmatchIndex(s, n)
}

func (r filteredRegexp) FindString(s string) string {
	if !r.filter.MayMatch(s) {
		return ""
	}
	return r.Regexp.FindString(s)
}
