package parser

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenCodeAgentPermission(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
	}{
		{"none", "---\ndescription: x\n---\nbody\n", ""},
		{"no frontmatter", "body only\n", ""},
		{"shorthand", "---\npermission: allow\n---\n", `"allow"`},
		// Order is the point: OpenCode resolves by the last matching rule.
		{"ordered object", "---\npermission:\n  read:\n    \"*.env\": ask\n    \"*\": allow\n  bash: allow\n---\n",
			`{"read":{"*.env":"ask","*":"allow"},"bash":"allow"}`},
		{"reverse order kept", "---\npermission:\n  read:\n    \"*\": allow\n    \"*.env\": ask\n---\n",
			`{"read":{"*":"allow","*.env":"ask"}}`},
		// An alias resolves to the anchored node, keeping its order.
		{"alias", "---\nbase: &b\n  bash: deny\n  edit: allow\npermission: *b\n---\n",
			`{"bash":"deny","edit":"allow"}`},
		{"sequence", "---\npermission: [allow, deny]\n---\n", `["allow","deny"]`},
		// Typed scalars keep their JSON type; everything else is a string.
		{"typed scalars", "---\npermission:\n  a: true\n  b: 3\n  c: 1.5\n  d: null\n  e: \"7\"\n---\n",
			`{"a":true,"b":3,"c":1.5,"d":null,"e":"7"}`},
		// A scalar forced to a tag it cannot decode as is not a permission.
		{"undecodable tagged scalar", "---\npermission: !!int nope\n---\n", ""},
		{"undecodable nested scalar", "---\npermission:\n  bash: !!bool nope\n---\n", ""},
		{"undecodable in sequence", "---\npermission: [allow, !!float nope]\n---\n", ""},
		{"not a mapping", "---\n- permission\n---\n", ""},
		{"empty frontmatter", "---\n---\n", ""},
		{"invalid yaml", "---\npermission: [\n---\n", ""},
		{"fence only", "---", ""},
		{"unterminated", "---\npermission: allow\n", ""},
	} {
		got := string(OpenCodeAgentPermission(tc.content))
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

// writeOrderedJSON is only ever handed nodes from a parsed document, but a
// document node must unwrap and an empty or unknown node must fail.
func TestWriteOrderedJSON_NodeKinds(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("a: allow\n"), &doc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	var b strings.Builder
	if !writeOrderedJSON(&b, &doc) || b.String() != `{"a":"allow"}` {
		t.Errorf("document node: got %q", b.String())
	}
	for name, n := range map[string]*yaml.Node{
		"empty document": {Kind: yaml.DocumentNode},
		"zero kind":      {},
	} {
		var b strings.Builder
		if writeOrderedJSON(&b, n) {
			t.Errorf("%s: expected failure, wrote %q", name, b.String())
		}
	}
}
