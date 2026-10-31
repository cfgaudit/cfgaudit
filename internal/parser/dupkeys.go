// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// DuplicateKey is an object key that appears more than once in a JSON
// document, at any depth. Path is the key path ("hooks.SessionStart",
// "permissions.deny", "mcpServers.x.env.TOKEN", array elements as "[i]"),
// Line is an occurrence that does not take effect, and WinLine is the last
// occurrence, the one a last-wins decoder keeps (#1042).
type DuplicateKey struct {
	Path    string
	Line    int
	Col     int
	WinLine int
}

// commentKey reports whether key is a JSON comment by convention ("//",
// "//note", "_comment", "$comment"): files repeat it on purpose, and no
// setting depends on which copy wins.
func commentKey(key string) bool {
	return strings.HasPrefix(key, "//") || key == "_comment" || key == "$comment"
}

// duplicateKeys walks a strict JSON document and reports every key repeated
// within one object. Claude Code 2.1.312 keeps the last top-level occurrence
// and 2.1.314 the last nested one (a second "SessionStart" under "hooks"
// replaces the first), as JSON.parse does; json.Unmarshal into a map does the
// same, so the effective values cfgaudit checks are already the right ones.
// A document that is not valid JSON yields nil.
func duplicateKeys(data []byte) []DuplicateKey {
	w := &dupWalker{dec: json.NewDecoder(bytes.NewReader(data)), data: data}
	w.dec.UseNumber()
	if !w.value("") {
		return nil
	}
	sort.SliceStable(w.out, func(i, j int) bool { return w.out[i].Line < w.out[j].Line })
	return w.out
}

type dupWalker struct {
	dec  *json.Decoder
	data []byte
	out  []DuplicateKey
}

// pos is the 1-based line and column of the opening quote of the key that
// ends at byte offset end.
func (w *dupWalker) pos(end int64) (line, col int) {
	i := int(end) - 2 // end is at least 3 (`{""`), so i never goes below 0
	for i > 0 && (w.data[i] != '"' || w.data[i-1] == '\\') {
		i--
	}
	line = bytes.Count(w.data[:i], []byte{'\n'}) + 1
	return line, i - bytes.LastIndexByte(w.data[:i], '\n')
}

// value consumes one JSON value at path and reports whether it was valid.
func (w *dupWalker) value(path string) bool {
	tok, err := w.dec.Token()
	if err != nil {
		return false
	}
	switch tok {
	case json.Delim('{'):
		var order []string
		lines := map[string][][2]int{}
		for w.dec.More() {
			kt, err := w.dec.Token()
			if err != nil {
				return false
			}
			key, _ := kt.(string)
			if _, ok := lines[key]; !ok {
				order = append(order, key)
			}
			l, c := w.pos(w.dec.InputOffset())
			lines[key] = append(lines[key], [2]int{l, c})
			child := key
			if path != "" {
				child = path + "." + key
			}
			if !w.value(child) {
				return false
			}
		}
		for _, key := range order {
			ls := lines[key]
			if commentKey(key) {
				continue
			}
			child := key
			if path != "" {
				child = path + "." + key
			}
			for _, l := range ls[:len(ls)-1] {
				w.out = append(w.out, DuplicateKey{Path: child, Line: l[0], Col: l[1], WinLine: ls[len(ls)-1][0]})
			}
		}
		_, err := w.dec.Token() // the closing '}'
		return err == nil
	case json.Delim('['):
		for i := 0; w.dec.More(); i++ {
			if !w.value(path + "[" + strconv.Itoa(i) + "]") {
				return false
			}
		}
		_, err := w.dec.Token() // the closing ']'
		return err == nil
	}
	return true
}
