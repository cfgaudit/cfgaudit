// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
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
//
// The content rules call MayMatch once per line and filtered regexp, so it
// must not allocate (#1018): a line without an upper-case ASCII letter is
// searched as it is, and any other line is lowered into a pooled buffer.
func (f literalFilter) MayMatch(s string) bool {
	if f == nil {
		return true
	}
	if !isASCII(s) && (strings.Contains(s, "\u017f") || strings.Contains(s, "\u212a")) {
		return true
	}
	if !hasUpperASCII(s) {
		return f.containsAny(s)
	}
	bp := lowerBufs.Get().(*[]byte)
	b := appendLowerASCII((*bp)[:0], s)
	found := false
	for _, lit := range f {
		if bytes.Contains(b, []byte(lit)) {
			found = true
			break
		}
	}
	*bp = b
	lowerBufs.Put(bp)
	return found
}

func (f literalFilter) containsAny(s string) bool {
	for _, lit := range f {
		if strings.Contains(s, lit) {
			return true
		}
	}
	return false
}

// lowerBufs holds the buffers MayMatch lowers a line into. A pool rather than
// one buffer, because the rules run for several targets at once (#1017).
var lowerBufs = sync.Pool{New: func() any { b := make([]byte, 0, 256); return &b }}

func hasUpperASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// appendLowerASCII appends s to b with its ASCII letters lower-cased and every
// other byte as it is, so the bytes of a multi-byte character stay intact.
func appendLowerASCII(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return b
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
