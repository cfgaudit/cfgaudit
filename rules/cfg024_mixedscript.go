// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// latinConfusables maps the Cyrillic letters that look like a Latin letter to
// that letter, case for case (#1824). A key is a confusable; the set of keys is
// what tells a homoglyph apart from an ordinary non-Latin letter. The mapping
// is case-specific: uppercase Cyrillic В looks like Latin B, but lowercase в
// does not, so only the confusable case is listed.
//
// Greek is deliberately left out. On the corpus its mixed-Latin tokens were all
// legitimate scientific or math notation (a free-stream density `ρInf`, a
// T-cell receptor `TCRα`, a point `Aα`), where a Greek letter sits next to
// Latin on purpose; Cyrillic does not appear in that notation, so Latin with
// Cyrillic is a clean homoglyph signal and Latin with Greek is not.
var latinConfusables = map[rune]rune{
	// Cyrillic lowercase.
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
	'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w',
	// Cyrillic uppercase.
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
}

// Thresholds that keep short, incidental mixed tokens out: a homoglyph attack
// is a word, so it has several letters and at least two of them Latin.
const (
	mixedScriptMinLetters = 4
	mixedScriptMinLatin   = 2
)

// isWordRune reports whether r is part of a word: a letter or a combining mark.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.Is(unicode.Mn, r)
}

// mixedScriptWord reports the first word in runes that mixes Latin letters with
// Cyrillic letters that all look Latin, together with the Latin form it spells
// and its 1-based line and column. ok is false when there is none. It takes the
// caller's rune slice so it does not allocate a second copy, and only a word
// with a non-ASCII rune is examined, since an all-ASCII word cannot be mixed.
func mixedScriptWord(runes []rune) (word, latin string, line, col int, ok bool) {
	ln, cl := 1, 0
	wordStart, wordCol := -1, 0
	nonASCII := false
	check := func(end int) bool {
		if wordStart < 0 || !nonASCII {
			return false
		}
		w := runes[wordStart:end]
		if latinForm, is := homoglyphWord(w); is {
			word, latin, line, col, ok = string(w), latinForm, ln, wordCol, true
			return true
		}
		return false
	}
	for i, r := range runes {
		if r == '\n' {
			if check(i) {
				return
			}
			wordStart, nonASCII = -1, false
			ln++
			cl = 0
			continue
		}
		cl++
		if isWordRune(r) {
			if wordStart < 0 {
				wordStart, wordCol = i, cl
			}
			if r >= 0x80 {
				nonASCII = true
			}
			continue
		}
		if check(i) {
			return
		}
		wordStart, nonASCII = -1, false
	}
	check(len(runes))
	return
}

// homoglyphWord reports whether w mixes Latin with confusable Cyrillic letters
// so the whole word reads as Latin, and returns the Latin form. Every non-Latin
// letter has to be a Cyrillic confusable, or the word does not read as Latin and
// is ordinary non-English text (or scientific Greek), not a homoglyph. The
// classification does not allocate; the Latin form is built only for a word that
// is a homoglyph, which is rare.
func homoglyphWord(w []rune) (string, bool) {
	var latin, cyr, letters int
	for _, r := range w {
		// w holds only word runes (letters and combining marks); a mark does not
		// count as a letter and is kept in the Latin form.
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		letters++
		switch {
		case unicode.Is(unicode.Latin, r):
			latin++
		case unicode.Is(unicode.Cyrillic, r):
			if _, isConfusable := latinConfusables[r]; !isConfusable {
				return "", false // a non-confusable letter: ordinary Cyrillic text
			}
			cyr++
		default:
			return "", false // Greek or a third script: not a Cyrillic homoglyph
		}
	}
	if latin < mixedScriptMinLatin || cyr == 0 || letters < mixedScriptMinLetters {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(w))
	for _, r := range w {
		if sub, ok := latinConfusables[r]; ok {
			b.WriteRune(sub)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), true
}

// mixedScriptFinding returns the finding for the first homoglyph word in src,
// or nil. The word is visible, so it is reported at warn, with the Latin form
// it spells named so a reviewer sees what it reads as.
func (r *cfg024) mixedScriptFinding(src instructionSource, runes []rune) *finding.Finding {
	word, latin, line, col, ok := mixedScriptWord(runes)
	if !ok {
		return nil
	}
	return &finding.Finding{
		RuleID:   "CFG024",
		Severity: finding.Warn,
		File:     src.File,
		Line:     line,
		Col:      col,
		Message: src.Name + " line " + strconv.Itoa(line) + " contains the mixed-script word " + strconv.Quote(word) +
			", which reads as " + strconv.Quote(latin) + " but mixes Latin with Cyrillic look-alike letters so it matches no keyword a reviewer or a scanner greps for: a visible homoglyph, the sibling of the invisible smuggling above. Write the word in one script",
	}
}
