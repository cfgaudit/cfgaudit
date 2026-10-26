// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package keyline finds the line of the key a structured-config finding
// reports (#927). Rules name the key path at the start of their message
// ("permissions.allow contains \"Bash(*)\"", "mcpServers.docs connects to
// ..."); Locate looks that path up in the raw JSON or JSONC bytes and, when
// the message quotes a value, the entry holding it. A finding whose key cannot
// be located keeps no line rather than a guessed one.
package keyline

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// node is an object member, or a string element of an array.
type node struct {
	path      []string // object keys from the root; array indices are left out
	key       string   // the member's key, "" for an array element
	str       string   // the string value, if the value is a string
	isStr     bool
	line, col int // of the key, or of the array element
	end       int // nodes[i+1:end] lie inside this member's value
}

// Doc is a parsed JSON or JSONC document.
type Doc struct {
	nodes []node
}

// Parse reads JSON with the JSONC extensions Claude Code and the other agents
// accept: a leading BOM, // and /* */ comments and trailing commas. It returns
// nil if src is not such a document.
func Parse(src []byte) *Doc {
	d := &Doc{}
	p := &parser{src: bytes.TrimPrefix(src, []byte{0xEF, 0xBB, 0xBF}), line: 1, doc: d}
	p.skip()
	if !p.value(nil) {
		return nil
	}
	p.skip()
	if p.pos != len(p.src) {
		return nil
	}
	return d
}

type parser struct {
	src       []byte
	pos       int
	line      int
	lineStart int
	doc       *Doc
	depth     int
}

const maxDepth = 512

func (p *parser) col() int {
	return utf8.RuneCount(p.src[p.lineStart:p.pos]) + 1
}

func (p *parser) newline() {
	p.line++
	p.lineStart = p.pos + 1
}

// skip passes whitespace and comments.
func (p *parser) skip() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '\n':
			p.newline()
			p.pos++
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
		case c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '/':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '*':
			p.pos += 2
			for p.pos+1 < len(p.src) && (p.src[p.pos] != '*' || p.src[p.pos+1] != '/') {
				if p.src[p.pos] == '\n' {
					p.newline()
				}
				p.pos++
			}
			p.pos += 2
		default:
			return
		}
	}
}

// str reads a string literal at pos.
func (p *parser) str() (string, bool) {
	start := p.pos
	p.pos++
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\\':
			p.pos += 2
			continue
		case '"':
			p.pos++
			s, err := strconv.Unquote(string(p.src[start:p.pos]))
			if err != nil {
				// JSON escapes Go does not know, such as \/: keep the raw text.
				s = string(p.src[start+1 : p.pos-1])
			}
			return s, true
		case '\n':
			return "", false
		}
		p.pos++
	}
	return "", false
}

func (p *parser) value(path []string) bool {
	if p.pos >= len(p.src) {
		return false
	}
	switch p.src[p.pos] {
	case '{':
		return p.object(path)
	case '[':
		return p.array(path)
	case '"':
		_, ok := p.str()
		return ok
	default:
		start := p.pos
		for p.pos < len(p.src) && !strings.ContainsRune(" \t\r\n,]}/", rune(p.src[p.pos])) {
			p.pos++
		}
		return p.pos > start
	}
}

func (p *parser) nest() bool {
	p.depth++
	return p.depth <= maxDepth
}

func (p *parser) object(path []string) bool {
	if !p.nest() {
		return false
	}
	defer func() { p.depth-- }()
	p.pos++
	for {
		p.skip()
		if p.pos >= len(p.src) {
			return false
		}
		if p.src[p.pos] == '}' {
			p.pos++
			return true
		}
		if p.src[p.pos] != '"' {
			return false
		}
		line, col := p.line, p.col()
		key, ok := p.str()
		if !ok {
			return false
		}
		p.skip()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return false
		}
		p.pos++
		p.skip()
		child := append(append([]string(nil), path...), key)
		i := len(p.doc.nodes)
		p.doc.nodes = append(p.doc.nodes, node{path: child, key: key, line: line, col: col})
		if p.pos < len(p.src) && p.src[p.pos] == '"' {
			s, ok := p.str()
			if !ok {
				return false
			}
			p.doc.nodes[i].str, p.doc.nodes[i].isStr = s, true
		} else if !p.value(child) {
			return false
		}
		p.doc.nodes[i].end = len(p.doc.nodes)
		if !p.sep('}') {
			return false
		}
	}
}

func (p *parser) array(path []string) bool {
	if !p.nest() {
		return false
	}
	defer func() { p.depth-- }()
	p.pos++
	for {
		p.skip()
		if p.pos >= len(p.src) {
			return false
		}
		if p.src[p.pos] == ']' {
			p.pos++
			return true
		}
		if p.src[p.pos] == '"' {
			line, col := p.line, p.col()
			s, ok := p.str()
			if !ok {
				return false
			}
			n := len(p.doc.nodes)
			p.doc.nodes = append(p.doc.nodes, node{path: path, str: s, isStr: true, line: line, col: col, end: n + 1})
		} else if !p.value(path) {
			return false
		}
		if !p.sep(']') {
			return false
		}
	}
}

// sep passes the comma after a member or element, if any, and checks that the
// next token can follow.
func (p *parser) sep(closer byte) bool {
	p.skip()
	if p.pos >= len(p.src) {
		return false
	}
	switch p.src[p.pos] {
	case ',':
		p.pos++
		return true
	case closer:
		return true
	}
	return false
}

// quotedRe matches a Go-quoted string, as rules write values with %q.
var quotedRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// Locate returns the line and column of what msg reports, or 0, 0.
//
// The key path is the longest dotted path of a key in the document that msg
// starts with, preferring a path from the root. It may leave out leading keys
// ("defaultMode" for permissions.defaultMode) when only one key in the
// document matches. If msg quotes a value after the path, the result is the
// first string under that key equal to it, or else containing it; otherwise it
// is the key itself. A repeated key resolves to its last occurrence, the one
// JSON parsers keep.
//
// Rules name a server mcpServers.<name> whatever the file calls the block
// (opencode.json "mcp", VS Code "servers") and some put the agent first
// ("Gemini hooks.SessionStart"), so when msg names no key, Locate tries again
// without its first path segment and then without its first word.
func (d *Doc) Locate(msg string) (line, col int) {
	if d == nil {
		return 0, 0
	}
	if line, col = d.locate(msg); line > 0 {
		return line, col
	}
	if i := strings.IndexAny(msg, ". "); i > 0 && msg[i] == '.' {
		if line, col = d.locate(msg[i+1:]); line > 0 {
			return line, col
		}
	}
	if i := strings.IndexByte(msg, ' '); i > 0 {
		return d.locate(msg[i+1:])
	}
	return 0, 0
}

func (d *Doc) locate(msg string) (line, col int) {
	best, bestLen, rooted := []int(nil), 0, false
	for i, n := range d.nodes {
		if n.key == "" {
			continue
		}
		for s := 0; s < len(n.path); s++ {
			p := strings.Join(n.path[s:], ".")
			if len(p) < bestLen || !pathPrefix(msg, p) {
				continue
			}
			// A path from the root wins over the same text ending deeper
			// down: "hooks" is the top-level key, not hooks.PostToolUse.hooks.
			switch {
			case len(p) > bestLen || (s == 0 && !rooted):
				best, bestLen, rooted = nil, len(p), s == 0
			case s > 0 && rooted:
				continue
			}
			best = append(best, i)
			break
		}
	}
	if len(best) == 0 {
		return 0, 0
	}
	rest := msg[bestLen:]
	var want string
	if q := quotedRe.FindString(rest); len(q) > 2 {
		// Most rules quote with %q; some splice the raw value between quotes,
		// so a Windows path's backslashes are not Go escapes.
		var err error
		if want, err = strconv.Unquote(q); err != nil {
			want = q[1 : len(q)-1]
		}
	}
	if want != "" && len(best) > 1 {
		var holding []int
		for _, i := range best {
			if _, ok := d.find(i, want); ok {
				holding = append(holding, i)
			}
		}
		if len(holding) > 0 {
			best = holding
		}
	}
	// Keys that differ only in where the path starts are different keys.
	full := strings.Join(d.nodes[best[0]].path, "\x00")
	for _, i := range best[1:] {
		if strings.Join(d.nodes[i].path, "\x00") != full {
			return 0, 0
		}
	}
	i := best[len(best)-1]
	if want != "" {
		if j, ok := d.find(i, want); ok {
			return d.nodes[j].line, d.nodes[j].col
		}
	}
	return d.nodes[i].line, d.nodes[i].col
}

// find returns the first node from member i on whose key or string value is
// want, or else the first whose string value contains it.
func (d *Doc) find(i int, want string) (int, bool) {
	// A member wins over an array element with the same value: a VS Code
	// task's "label" over another task's "dependsOn" naming it.
	for j := i; j < d.nodes[i].end; j++ {
		if n := d.nodes[j]; n.key != "" && (n.key == want || (n.isStr && n.str == want)) {
			return j, true
		}
	}
	for j := i; j < d.nodes[i].end; j++ {
		if n := d.nodes[j]; n.isStr && n.str == want {
			return j, true
		}
	}
	for j := i; j < d.nodes[i].end; j++ {
		if n := d.nodes[j]; n.isStr && strings.Contains(n.str, want) {
			return j, true
		}
	}
	return 0, false
}

// pathPrefix reports whether msg starts with the key path p, followed by
// something that ends a path.
func pathPrefix(msg, p string) bool {
	if !strings.HasPrefix(msg, p) {
		return false
	}
	if len(msg) == len(p) {
		return true
	}
	return strings.IndexByte(" :.[=(,", msg[len(p)]) >= 0
}
