// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/version"
	"github.com/cfgaudit/cfgaudit/rules"
)

// The metamorphic test rewrites every rule doc trigger example and every
// invalid settings fixture in ways that do not change what the file means to
// the agent, and checks that the findings stay the same (#1066). A rule that
// matches on how a file is written instead of what it says fails here.
//
// Only rewrites the agents accept are valid. Comments and trailing commas are
// out: Claude Code drops a settings file that has them (#1040 to #1042). A BOM
// is only applied to Claude Code settings files, the one place it is measured
// to load.

// metaSource is one file to rewrite: where it goes in the project, the Claude
// Code version to gate rules on, and its content.
type metaSource struct {
	name    string
	path    string
	version string
	content string
}

func metaSources(t *testing.T) []metaSource {
	t.Helper()
	var out []metaSource
	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "rules", "CFG*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no rule docs found: %v", err)
	}
	for _, doc := range docs {
		b, err := os.ReadFile(doc) // #nosec G304 -- rule docs in this repository
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSuffix(filepath.Base(doc), ".md")
		for i, ex := range triggerExamples(string(b)) {
			out = append(out, metaSource{name: fmt.Sprintf("%s-%d", id, i+1), path: ex.path, version: ex.version, content: ex.content})
		}
	}
	fixtures, err := filepath.Glob(filepath.Join("..", "..", "testdata", "settings", "invalid", "*.json"))
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("no invalid fixtures found: %v", err)
	}
	for _, f := range fixtures {
		b, err := os.ReadFile(f) // #nosec G304 -- fixtures in this repository
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, metaSource{name: strings.TrimSuffix(filepath.Base(f), ".json"), path: ".claude/settings.json", content: string(b)})
	}
	return out
}

// metaScan scans a project holding one file and returns its findings as
// sorted "rule severity path" keys. Lines, columns and messages may change
// with the rewrite and are left out.
func metaScan(t *testing.T, src metaSource, content string) []string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, filepath.FromSlash(src.path)), content)
	var detected *version.Version
	if src.version != "" {
		v, err := version.Parse(src.version)
		if err != nil {
			t.Fatalf("version %q: %v", src.version, err)
		}
		detected = &v
	}
	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	pluginTargets, err := buildPluginTargets(dir, "", false)
	if err != nil {
		t.Fatalf("buildPluginTargets: %v", err)
	}
	targets = append(targets, dropDuplicateInstructions(targets, pluginTargets)...)
	var keys []string
	for _, tg := range targets {
		for _, f := range rules.Run(tg, detected, nil) {
			rel, err := filepath.Rel(dir, f.File)
			if err != nil {
				rel = f.File
			}
			keys = append(keys, fmt.Sprintf("%s %s %s", f.RuleID, f.Severity, filepath.ToSlash(rel)))
		}
	}
	slices.Sort(keys)
	return keys
}

type metaRewrite struct {
	name  string
	apply func(src metaSource) (string, bool) // false: does not apply to this file
}

func metaRewrites() []metaRewrite {
	jsonOnly := func(f func(*jsonNode) string) func(metaSource) (string, bool) {
		return func(src metaSource) (string, bool) {
			if !strings.HasSuffix(src.path, ".json") {
				return "", false
			}
			n, err := parseJSONNode(src.content)
			if err != nil {
				return "", false // JSONC or not JSON at all
			}
			return f(n), true
		}
	}
	return []metaRewrite{
		{"crlf", func(src metaSource) (string, bool) {
			return strings.ReplaceAll(strings.ReplaceAll(src.content, "\r\n", "\n"), "\n", "\r\n"), true
		}},
		{"bom", func(src metaSource) (string, bool) {
			if src.path != ".claude/settings.json" && src.path != ".claude/settings.local.json" {
				return "", false
			}
			return "\xef\xbb\xbf" + src.content, true
		}},
		{"minified", jsonOnly(func(n *jsonNode) string { return n.render("", "", false, false) })},
		{"tab-indented", jsonOnly(func(n *jsonNode) string { return n.render("", "\t", false, false) + "\n" })},
		{"keys-reversed", jsonOnly(func(n *jsonNode) string { return n.render("", "  ", true, false) + "\n" })},
		{"unicode-escaped", jsonOnly(func(n *jsonNode) string { return n.render("", "  ", false, true) + "\n" })},
	}
}

func TestMetamorphic_EquivalentFilesGiveSameFindings(t *testing.T) {
	ran := 0
	for _, src := range metaSources(t) {
		t.Run(src.name, func(t *testing.T) {
			if filepath.IsAbs(src.path) || strings.Contains(src.path, "..") {
				t.Skipf("path %q outside the project", src.path)
			}
			want := metaScan(t, src, src.content)
			if len(want) == 0 {
				t.Skip("no findings to compare")
			}
			for _, rw := range metaRewrites() {
				content, ok := rw.apply(src)
				if !ok {
					continue
				}
				ran++
				if got := metaScan(t, src, content); !slices.Equal(got, want) {
					t.Errorf("%s rewrite of %s changes the findings\noriginal: %v\nrewritten: %v", rw.name, src.path, want, got)
				}
			}
		})
	}
	if ran == 0 {
		t.Fatal("no rewrite was applied")
	}
}

// jsonNode is a parsed JSON value that keeps object key order and duplicate
// keys, so a rewrite changes only what it means to change.
type jsonNode struct {
	kind  rune // '{', '[', or 0 for a scalar
	keys  []string
	items []*jsonNode
	raw   json.RawMessage // scalars: the original token, re-encoded
	str   *string         // string scalars, for re-escaping
}

func parseJSONNode(s string) (*jsonNode, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	n, err := decodeJSONNode(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	return n, nil
}

func decodeJSONNode(dec *json.Decoder) (*jsonNode, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		n := &jsonNode{kind: rune(v)}
		for dec.More() {
			if n.kind == '{' {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("object key %v", k)
				}
				n.keys = append(n.keys, key)
			}
			item, err := decodeJSONNode(dec)
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, item)
		}
		if _, err := dec.Token(); err != nil { // closing delimiter
			return nil, err
		}
		return n, nil
	case string:
		s := v
		return &jsonNode{str: &s}, nil
	case json.Number:
		return &jsonNode{raw: json.RawMessage(v.String())}, nil
	default: // bool or nil
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return &jsonNode{raw: b}, nil
	}
}

// render writes n back as JSON. indent "" with prefix "" gives minified output;
// reverse writes object keys in reverse order; escape writes every ASCII
// letter in strings and keys as a \u escape.
func (n *jsonNode) render(prefix, indent string, reverse, escape bool) string {
	var b bytes.Buffer
	n.write(&b, prefix, indent, reverse, escape)
	return b.String()
}

func (n *jsonNode) write(b *bytes.Buffer, prefix, indent string, reverse, escape bool) {
	switch {
	case n.str != nil:
		b.WriteString(jsonString(*n.str, escape))
		return
	case n.kind == 0:
		b.Write(n.raw)
		return
	}
	open, closing := "[", "]"
	if n.kind == '{' {
		open, closing = "{", "}"
	}
	b.WriteString(open)
	order := make([]int, len(n.items))
	for i := range order {
		order[i] = i
	}
	if reverse && n.kind == '{' {
		slices.Reverse(order)
	}
	inner := prefix + indent
	for j, i := range order {
		if j > 0 {
			b.WriteString(",")
		}
		if indent != "" {
			b.WriteString("\n" + inner)
		}
		if n.kind == '{' {
			b.WriteString(jsonString(n.keys[i], escape))
			b.WriteString(":")
			if indent != "" {
				b.WriteString(" ")
			}
		}
		n.items[i].write(b, inner, indent, reverse, escape)
	}
	if indent != "" && len(order) > 0 {
		b.WriteString("\n" + prefix)
	}
	b.WriteString(closing)
}

func jsonString(s string, escape bool) string {
	enc, _ := json.Marshal(s) // a Go string always encodes
	if !escape {
		return string(enc)
	}
	var out strings.Builder
	verbatim := 0 // characters still belonging to an escape sequence
	for _, r := range string(enc) {
		switch {
		case verbatim > 0:
			out.WriteRune(r)
			verbatim--
			if r == 'u' && verbatim == 0 {
				verbatim = 4 // the hex digits of \uXXXX
			}
		case r == '\\':
			out.WriteRune(r)
			verbatim = 1
		case r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'):
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}
