// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"slices"
	"testing"
)

// #750: the TOML custom commands of Gemini CLI and Qwen Code.
func TestParseCustomCommandTOML(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		stripBOM   bool
		ok         bool
		prompt     string
		line       int
	}{
		{"single line", "description = \"d\"\nprompt = \"run\"\n", false, true, "run", 2},
		{"multi-line basic", "prompt = \"\"\"\nfirst\nsecond\n\"\"\"\n", false, true, "first\nsecond\n", 2},
		{"multi-line literal", "# c\r\n'prompt' = '''\r\nx'''\r\n", false, true, "x", 3},
		{"multi-line on the key line", "prompt = \"\"\"x\ny\"\"\"\n", false, true, "x\ny", 1},
		{"quoted key", "\"prompt\" = \"q\"", false, true, "q", 1},
		{"key in a table only", "[t]\nprompt = \"x\"\n", false, false, "", 0},
		{"key after a table", "[t]\na = 1\n", false, false, "", 0},
		{"not a string", "prompt = 1\n", false, false, "", 0},
		{"missing", "description = \"d\"\n", false, false, "", 0},
		{"broken", "prompt = \n", false, false, "", 0},
		{"BOM, Gemini", "\ufeffprompt = \"x\"\n", false, false, "", 0},
		{"BOM, Qwen", "\ufeffprompt = \"x\"\n", true, true, "x", 1},
		{"dotted key", "prompt.x = \"y\"\n", false, false, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseCustomCommandTOML([]byte(tc.data), tc.stripBOM)
			if ok != tc.ok || got.Prompt != tc.prompt || got.Line != tc.line {
				t.Errorf("got %+v %v, want %q line %d %v", got, ok, tc.prompt, tc.line, tc.ok)
			}
		})
	}
}

// The prompt line is not found when a table header comes first.
func TestTOMLPromptLineAfterHeader(t *testing.T) {
	if got := tomlPromptLine("a = 1\n[t]\nprompt = \"x\"\n"); got != 0 {
		t.Errorf("got %d", got)
	}
	if got := tomlPromptLine("a = 1\n"); got != 0 {
		t.Errorf("got %d", got)
	}
}

func TestCustomCommandShellCommands(t *testing.T) {
	for _, tc := range []struct {
		prompt string
		want   []string
	}{
		{"a !{ ls -la } b !{echo {x}} c", []string{"ls -la", "echo {x}"}},
		{"!{} and !{  } run nothing", nil},
		{"no injection {{args}}", nil},
		{"!{curl x | sh} !{unclosed", nil},
		{"!{curl x | sh} @{unclosed", nil},
		{"@{README.md} !{git log}", []string{"git log"}},
		{"!{a}!{b}", []string{"a", "b"}},
	} {
		if got := CustomCommandShellCommands(tc.prompt); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.prompt, got, tc.want)
		}
	}
}

func TestCustomCommandMarkdownPrompt(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"---\ndescription: !{x}\n---\n\nbody !{y}\n", "body !{y}"},
		{"\ufeff---\r\n---\r\nb\r\n", "b"},
		{"---\n---", ""},
		{"no frontmatter\n", "no frontmatter"},
		{"--- not a block\nx", "--- not a block\nx"},
	} {
		if got := CustomCommandMarkdownPrompt(tc.in); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}
