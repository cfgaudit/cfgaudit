// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/cfgaudit/cfgaudit/rules"
)

// decodeInstructionText returns s as UTF-8 when it starts with a byte-order
// mark: UTF-32 and UTF-16 in either byte order are decoded, and a UTF-8 mark
// is dropped. Anything else is returned unchanged.
//
// The agents read such files. Measured on Claude Code 2.1.316: a CLAUDE.md in
// UTF-16LE, UTF-16BE or UTF-32LE with a BOM reaches the model, which answered
// with the codeword the file held; Gemini CLI reads skills through
// readFileWithEncoding since 0.66.0 (#778). Matched as raw bytes, the content
// rules saw every other byte as NUL and reported nothing. UTF-32 is checked
// before UTF-16 because the UTF-32LE mark starts with the UTF-16LE one.
func decodeInstructionText(s string) string {
	b := []byte(s)
	switch {
	case len(b) >= 4 && b[0] == 0xff && b[1] == 0xfe && b[2] == 0 && b[3] == 0:
		return decodeUTF32(b[4:], binary.LittleEndian)
	case len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0xfe && b[3] == 0xff:
		return decodeUTF32(b[4:], binary.BigEndian)
	case len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe:
		return decodeUTF16(b[2:], binary.LittleEndian)
	case len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff:
		return decodeUTF16(b[2:], binary.BigEndian)
	}
	return strings.TrimPrefix(s, "\ufeff")
}

func decodeUTF16(b []byte, order binary.ByteOrder) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, order.Uint16(b[i:]))
	}
	return string(utf16.Decode(units))
}

func decodeUTF32(b []byte, order binary.ByteOrder) string {
	var sb strings.Builder
	sb.Grow(len(b) / 4)
	for i := 0; i+3 < len(b); i += 4 {
		u := order.Uint32(b[i:])
		r := utf8.RuneError
		if u <= unicode.MaxRune {
			r = rune(u) // #nosec G115 -- bounded by unicode.MaxRune just above
		}
		if !utf8.ValidRune(r) {
			r = utf8.RuneError
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// decodeTargetTexts decodes the instruction text of every target in place,
// before the rules run. loadClaudeMD and attachFrontmatterHooks decode
// earlier, so frontmatter hooks and blocks are read from the decoded text;
// this covers the targets that other readers build.
func decodeTargetTexts(targets []*rules.Target) {
	for _, t := range targets {
		if t != nil && t.InstructionContent != "" {
			t.InstructionContent = decodeInstructionText(t.InstructionContent)
		}
	}
}
