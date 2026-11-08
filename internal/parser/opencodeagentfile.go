// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/safeyaml"
	"gopkg.in/yaml.v3"
)

// openCodeAgentNativeKeys are the frontmatter keys only OpenCode 2 knows. From
// v2.1.4 (config/plugin/agent.ts nativeKeys): "A file that uses any of them is
// read as V2, whatever else it contains", and V1 fields in it, `permission`
// among them, are ignored with a warning.
var openCodeAgentNativeKeys = map[string]bool{"permissions": true, "request": true, "system": true, "disabled": true}

// OpenCodeAgentPermission returns the permission rules of an OpenCode agent or
// mode Markdown file's frontmatter as JSON, in the order the file wrote them,
// or nil when there are none (#642). native reports a file read as V2 (#748):
// its rules are the `permissions` list and a `permission` block in it is not
// read. Otherwise they are the v1 `permission` block.
//
// Order matters because OpenCode resolves a permission by the last matching
// rule, and Frontmatter.Raw is a map that loses it, so the block is decoded
// from a yaml.Node instead. Measured with opencode 1.18.18: a committed
// .opencode/agent/<name>.md with `permission: {bash: allow}` resolves the
// agent's bash rule to allow, the same as agent.<name>.permission in
// opencode.json.
func OpenCodeAgentPermission(content string) (rules json.RawMessage, native bool) {
	block, ok := frontmatterBlock(content)
	if !ok {
		return nil, false
	}
	var doc yaml.Node
	if safeyaml.Unmarshal([]byte(block), &doc) != nil || len(doc.Content) == 0 {
		return nil, false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if openCodeAgentNativeKeys[root.Content[i].Value] {
			native = true
		}
	}
	want := "permission"
	if native {
		want = "permissions"
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == want {
			var b strings.Builder
			if !writeOrderedJSON(&b, root.Content[i+1]) {
				return nil, native
			}
			return json.RawMessage(b.String()), native
		}
	}
	return nil, native
}

// frontmatterBlock returns the YAML between the leading `---` fences. It is the
// one fence rule shared by InstructionFrontmatter and OpenCodeAgentPermission.
func frontmatterBlock(content string) (string, bool) {
	s := strings.TrimLeft(content, "\ufeff \t\r\n")
	if !strings.HasPrefix(s, "---") {
		return "", false
	}
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return "", false
	}
	rest := s[nl+1:]
	end := -1
	for _, fence := range []string{"\n---", "\n..."} {
		if i := strings.Index(rest, fence); i >= 0 && (end < 0 || i < end) {
			end = i
		}
	}
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// writeOrderedJSON renders a YAML node as JSON, keeping mapping key order.
// Scalars are written as strings unless YAML tags them as bool, int, float or
// null; a permission value only ever needs strings and nested mappings.
func writeOrderedJSON(b *strings.Builder, n *yaml.Node) bool {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return false
		}
		return writeOrderedJSON(b, n.Content[0])
	case yaml.AliasNode:
		return writeOrderedJSON(b, n.Alias)
	case yaml.MappingNode:
		b.WriteByte('{')
		for i := 0; i+1 < len(n.Content); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			k, _ := json.Marshal(n.Content[i].Value)
			b.Write(k)
			b.WriteByte(':')
			if !writeOrderedJSON(b, n.Content[i+1]) {
				return false
			}
		}
		b.WriteByte('}')
		return true
	case yaml.SequenceNode:
		b.WriteByte('[')
		for i, c := range n.Content {
			if i > 0 {
				b.WriteByte(',')
			}
			if !writeOrderedJSON(b, c) {
				return false
			}
		}
		b.WriteByte(']')
		return true
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!bool", "!!int", "!!float":
			var v any
			if n.Decode(&v) != nil {
				return false
			}
			out, _ := json.Marshal(v)
			b.Write(out)
		case "!!null":
			b.WriteString("null")
		default:
			out, _ := json.Marshal(n.Value)
			b.Write(out)
		}
		return true
	}
	return false
}
