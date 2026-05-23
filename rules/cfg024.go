package rules

import (
	"fmt"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg024 struct{}

var CFG024 = &cfg024{}

func init() { All = append(All, CFG024) }

func (r *cfg024) ID() string { return "CFG024" }

// bomRune is the byte-order mark / zero-width no-break space (U+FEFF). A single
// leading BOM is a benign encoding marker; anywhere else it hides content.
const bomRune rune = 0xFEFF

// Check scans a loaded CLAUDE.md for invisible Unicode control characters. Claude
// Code reads CLAUDE.md as trusted system context, so hidden codepoints — Tags
// block (ASCII smuggling), zero-width characters, BiDi controls (Trojan Source) —
// let an attacker embed instructions that are invisible in editors and review but
// processed by the model. Reports the first occurrence with its line/column.
func (r *cfg024) Check(t *Target) []finding.Finding {
	if t == nil || t.ClaudeMDContent == "" {
		return nil
	}
	line, col := 1, 0
	for i, ch := range t.ClaudeMDContent {
		if ch == '\n' {
			line++
			col = 0
			continue
		}
		col++
		if ch == bomRune && i == 0 {
			continue // a single leading BOM is a benign encoding marker
		}
		if name, ok := suspiciousUnicode(ch); ok {
			return []finding.Finding{{
				RuleID:   "CFG024",
				Severity: finding.Error,
				File:     t.ClaudeMDFile,
				Line:     line,
				Col:      col,
				Message:  fmt.Sprintf("CLAUDE.md contains a hidden Unicode control character U+%04X (%s) — invisible in editors and review but read by Claude as instructions; a prompt-injection / ASCII-smuggling vector. Remove all non-printable characters", ch, name),
			}}
		}
	}
	return nil
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
