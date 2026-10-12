package parser

import (
	"reflect"
	"testing"
)

// Each case was run against Claude Code 2.1.296 with a pre-approved command.
func TestSkillShellCommands(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		want          []string
	}{
		{"inline", "!`touch m`", []string{"touch m"}},
		{"mid-line", "Run this: !`touch m` now", []string{"touch m"}},
		{"fenced", "```!\ntouch m\n```", []string{"touch m"}},
		{"fenced multi-line", "```!\necho a\ntouch m\n```", []string{"echo a\ntouch m"}},
		// The regex matches; the content starts with "bash", which is what the
		// permission check then sees (it did not run under Bash(touch:*)).
		{"fenced with a language", "```!bash\ntouch m\n```", []string{"bash\ntouch m"}},
		{"inside an ordinary fence", "```bash\n!`touch m`\n```", []string{"touch m"}},
		{"inside an HTML comment", "<!-- !`touch m` -->", []string{"touch m"}},
		{"two on a line", "!`a` and !`b`", []string{"a", "b"}},
		{"no whitespace before the bang", "hello!`touch m`", nil},
		{"double backticks", "!``touch m``", nil},
		{"plain inline code", "Use `touch m` to test", nil},
	} {
		if got := SkillShellCommands(tc.content); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
