package parser

import "testing"

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
	} {
		got := string(OpenCodeAgentPermission(tc.content))
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}
