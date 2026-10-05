package rules

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg024 struct{}

var CFG024 = &cfg024{}

func init() { All = append(All, CFG024) }

func (r *cfg024) ID() string { return "CFG024" }

// bomRune is the byte-order mark / zero-width no-break space (U+FEFF). A single
// leading BOM is a benign encoding marker; anywhere else it hides content.
const bomRune rune = 0xFEFF

// zwjRune is the zero-width joiner (U+200D). It falls inside the zero-width
// range below, but it is also the codepoint that binds an emoji sequence
// together, so it needs its surrounding context before it can be judged.
const zwjRune rune = 0x200D

// The zero-width non-joiner and the two implicit directional marks, which
// ordinary writing in several scripts needs (#620).
const (
	zwnjRune rune = 0x200C
	lrmRune  rune = 0x200E
	rlmRune  rune = 0x200F
)

// joiningScripts are the scripts whose orthography uses ZWNJ / ZWJ inside a
// word: the Unicode Standard (chapter 23.2) describes them as required for
// Persian and Urdu spellings in Arabic script and for conjunct and half forms
// in the Indic scripts.
var joiningScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Syriac, unicode.Nko, unicode.Mongolian,
	unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada,
	unicode.Malayalam, unicode.Sinhala,
}

// joinerInScript reports whether the ZWNJ / ZWJ at runes[i] is part of writing
// in a joining script: the character before it (looking past combining marks,
// which Unicode assigns to the Inherited script, such as the Arabic kasra) or
// the character after it belongs to one of joiningScripts. One side is enough,
// because Persian attaches its suffixes to Latin loanwords with a ZWNJ
// ("merge" + ZWNJ + a Persian plural ending), and a word in Markdown emphasis
// can sit on the other side of a "**". A joiner between two Latin letters, the
// shape that splits a keyword invisibly, is still reported.
//
// In a corpus of 875 non-English instruction files, every ZWNJ / ZWJ CFG024
// reported before this exemption had one of these shapes.
func joinerInScript(runes []rune, i int) bool {
	inJoining := func(r rune) bool {
		for _, s := range joiningScripts {
			if unicode.Is(s, r) {
				return true
			}
		}
		return false
	}
	for j := i - 1; j >= 0; j-- {
		if unicode.Is(unicode.Mn, runes[j]) && !inJoining(runes[j]) {
			continue // an Inherited combining mark: judge the base it sits on
		}
		if inJoining(runes[j]) {
			return true
		}
		break
	}
	return i+1 < len(runes) && inJoining(runes[i+1])
}

// rtlScripts are the right-to-left scripts whose text uses LRM / RLM to fix the
// direction of neutral characters (UAX #9).
var rtlScripts = []*unicode.RangeTable{unicode.Hebrew, unicode.Arabic, unicode.Syriac, unicode.Thaana, unicode.Nko}

// lineHasRTL reports whether the line holding runes[i] contains a
// right-to-left letter. The marks rarely sit next to one: in the same corpus
// they stood before a digit, a backtick, a bracket or a space in Hebrew and
// Arabic lines, which is where a direction mark is needed.
func lineHasRTL(runes []rune, i int) bool {
	start, end := i, i
	for start > 0 && runes[start-1] != '\n' {
		start--
	}
	for end < len(runes) && runes[end] != '\n' {
		end++
	}
	for _, r := range runes[start:end] {
		for _, s := range rtlScripts {
			if unicode.Is(s, r) {
				return true
			}
		}
	}
	return false
}

// regionalIndicatorRunMin is how many consecutive regional indicator symbols
// count as smuggling. Each flag emoji is exactly two, so the run length is what
// separates spelling from decoration: 6 means three adjacent flags with nothing
// between them, which no ordinary prose produces. One or two flags in a sentence,
// or a locale table where flags are separated by text, never reach it.
const regionalIndicatorRunMin = 6

// isRegionalIndicator reports whether r is one of the 26 regional indicator
// symbols (U+1F1E6–U+1F1FF), which map onto A–Z.
func isRegionalIndicator(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }

// decodeRegionalIndicators renders the leading run of regional indicators as the
// ASCII letters they stand for, so the finding shows what the flags spell.
func decodeRegionalIndicators(runes []rune) string {
	var b strings.Builder
	for _, r := range runes {
		if !isRegionalIndicator(r) {
			break
		}
		b.WriteRune('A' + (r - 0x1F1E6))
	}
	return b.String()
}

// zwjJoinsEmoji reports whether the ZWJ at runes[i] sits between two emoji, i.e.
// it is building a composed glyph such as 👨‍💻 rather than hiding a break in text.
// Variation selector U+FE0F and the skin-tone modifiers commonly sit next to the
// joiner, so they count as emoji context too.
func zwjJoinsEmoji(runes []rune, i int) bool {
	if i == 0 || i+1 >= len(runes) {
		return false
	}
	return isEmojiContext(runes[i-1]) && isEmojiContext(runes[i+1])
}

// isEmojiContext reports whether r is a pictographic codepoint or one of the
// modifiers that attach to one. Deliberately range-based rather than exhaustive:
// the question is only "is this a rendering sequence", not "which emoji is it".
func isEmojiContext(r rune) bool {
	switch {
	case r >= 0x1F300 && r <= 0x1FAFF: // pictographs, emoticons, transport, supplemental
		return true
	case r >= 0x2600 && r <= 0x27BF: // misc symbols and dingbats
		return true
	case r >= 0x2B00 && r <= 0x2BFF: // arrows and geometric shapes used as emoji
		return true
	case r == 0xFE0F || r == 0xFE0E: // variation selectors
		return true
	case r >= 0x1F000 && r <= 0x1F2FF: // mahjong, dominoes, enclosed characters
		return true
	}
	return false
}

// Check scans a loaded CLAUDE.md for invisible Unicode control characters. Claude
// Code reads CLAUDE.md as trusted system context, so hidden codepoints — Tags
// block (ASCII smuggling), zero-width characters, BiDi controls (Trojan Source) —
// let an attacker embed instructions that are invisible in editors and review but
// processed by the model. Reports the first occurrence with its line/column.
func (r *cfg024) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	// One finding per source: the first hidden codepoint in each instruction
	// file / prompt-hook is enough to flag it for cleanup.
	for _, src := range t.instructionSources() {
		runes := []rune(src.Content)
		line, col := 1, 0
		riRun, riLine, riCol := 0, 0, 0
		for i, ch := range runes {
			if ch == '\n' {
				line++
				col = 0
				riRun = 0
				continue
			}
			col++

			// Regional indicators are *visible*, so they never reach
			// suspiciousUnicode — but a run of them spells ASCII in flag emoji.
			// Tracked as a run, because one or two are an ordinary country flag.
			if isRegionalIndicator(ch) {
				if riRun == 0 {
					riLine, riCol = line, col
				}
				riRun++
				if riRun == regionalIndicatorRunMin {
					findings = append(findings, finding.Finding{
						RuleID:   "CFG024",
						Severity: finding.Error,
						File:     src.File,
						Line:     riLine,
						Col:      riCol,
						Message: fmt.Sprintf("%s line %d encodes text as a run of flag emoji (regional indicator symbols) spelling %q — visible as a row of flags but decoded as letters by the model, so it hides instructions in plain sight. Remove it",
							src.Name, riLine, decodeRegionalIndicators(runes[i-regionalIndicatorRunMin+1:])),
					})
					break
				}
				continue
			}
			riRun = 0

			if ch == bomRune && i == 0 {
				continue // a single leading BOM is a benign encoding marker
			}
			// A zero-width joiner between two emoji is what builds 👨‍💻 and 👩‍👧‍👦;
			// that is rendering, not smuggling. Only ZWJ outside an emoji
			// sequence is a hiding vector.
			if ch == zwjRune && zwjJoinsEmoji(runes, i) {
				continue
			}
			// ZWNJ and ZWJ inside a word of a script that uses them for correct
			// spelling or conjunct forms (the Persian word for "half-space", spelled with a ZWNJ inside it, or a Bengali ra-phala formed with a ZWJ before the virama), and
			// LRM / RLM in a line of right-to-left text, are writing, not hiding
			// (#620). Neither can conceal text or reorder it the way the
			// embedding, override and isolate controls can.
			if (ch == zwnjRune || ch == zwjRune) && joinerInScript(runes, i) {
				continue
			}
			if (ch == lrmRune || ch == rlmRune) && lineHasRTL(runes, i) {
				continue
			}
			if name, ok := suspiciousUnicode(ch); ok {
				findings = append(findings, finding.Finding{
					RuleID:   "CFG024",
					Severity: finding.Error,
					File:     src.File,
					Line:     line,
					Col:      col,
					Message:  fmt.Sprintf("%s contains a hidden Unicode control character U+%04X (%s) — invisible in editors and review but read by the agent as instructions; a prompt-injection / ASCII-smuggling vector. Remove all non-printable characters", src.Name, ch, name),
				})
				break
			}
		}
	}
	return findings
}

// suspiciousUnicode reports whether r is an invisible/control codepoint used to
// smuggle hidden text, returning a short human-readable category.
func suspiciousUnicode(r rune) (string, bool) {
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		return "Tags block — ASCII smuggling", true
	case r >= 0x200B && r <= 0x200F:
		return "zero-width space / directional mark", true
	case r >= 0x202A && r <= 0x202E:
		return "BiDi control — Trojan Source", true
	case r == 0x2060 || r == bomRune:
		return "word joiner / zero-width no-break space", true
	case r >= 0xFFF9 && r <= 0xFFFB:
		return "interlinear annotation", true
	}
	return "", false
}
