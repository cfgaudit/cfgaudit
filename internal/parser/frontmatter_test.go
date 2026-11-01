// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"reflect"
	"testing"
)

func TestSplitToolList(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"Read, Bash(git -C * status)", []string{"Read", "Bash(git -C * status)"}},
		{"Bash(pnpm exec nx:*)", []string{"Bash(pnpm exec nx:*)"}},
		{"Read, Bash(git log *), Bash(gh pr edit * --add-label *)", []string{"Read", "Bash(git log *)", "Bash(gh pr edit * --add-label *)"}},
		{"Bash(a, b) Read", []string{"Bash(a, b)", "Read"}},
		{"Bash(echo $(date)), Read", []string{"Bash(echo $(date))", "Read"}},
		{"Read Bash", []string{"Read", "Bash"}},
		{"Read\tBash\nGrep", []string{"Read", "Bash", "Grep"}},
		{"Bash(*)", []string{"Bash(*)"}},
		{"Bash(git log, *", []string{"Bash(git", "log", "*"}},
		{"Read), *", []string{"Read)", "*"}},
		{"", []string{}},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			if got := splitToolList(c.input); !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitToolList(%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}

func TestInstructionFrontmatter_ListAndString(t *testing.T) {
	fm, ok := InstructionFrontmatter("---\ndescription: hi\nallowed-tools: Bash, Read\ndisable-model-invocation: true\n---\nbody\n")
	if !ok {
		t.Fatal("expected frontmatter to parse")
	}
	if got := fm.StringList("allowed-tools"); len(got) != 2 || got[0] != "Bash" || got[1] != "Read" {
		t.Errorf("string list form: got %v", got)
	}
	if !fm.Bool("disable-model-invocation") {
		t.Error("expected disable-model-invocation true")
	}
	if fm.String("description") != "hi" {
		t.Errorf("description: got %q", fm.String("description"))
	}
}

func TestFrontmatterDenyList(t *testing.T) {
	cases := []struct {
		value string
		want  []string
	}{
		{"Bash(rm *", []string{"Bash(rm *"}},
		{"Read, Bash(rm *", []string{"Read", "Bash(rm *"}},
		{"Read, Bash(rm *)", []string{"Read", "Bash(rm *)"}},
		{`["Bash(rm *", Read]`, []string{"Bash(rm *", "Read"}},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			fm, ok := InstructionFrontmatter("---\ndisallowed-tools: " + c.value + "\n---\n")
			if !ok {
				t.Fatal("expected frontmatter to parse")
			}
			if got := fm.DenyList("disallowed-tools"); !reflect.DeepEqual(got, c.want) {
				t.Errorf("DenyList(disallowed-tools) = %v, want %v", got, c.want)
			}
			if got := fm.DenyList("missing"); got != nil {
				t.Errorf("DenyList(missing) = %v, want nil", got)
			}
		})
	}
	var fm *Frontmatter
	if got := fm.DenyList("disallowed-tools"); got != nil {
		t.Errorf("nil frontmatter DenyList = %v, want nil", got)
	}
}

func TestFrontmatter_Phrases(t *testing.T) {
	// Scalar: split on commas/newlines only — internal spaces preserved.
	fm, _ := InstructionFrontmatter("---\ntriggers: before every request, deploy the app\n---\n")
	got := fm.Phrases("triggers")
	if len(got) != 2 || got[0] != "before every request" || got[1] != "deploy the app" {
		t.Errorf("scalar phrases: got %v", got)
	}
	// YAML list: elements kept verbatim, multi-word intact.
	fm2, _ := InstructionFrontmatter("---\ntriggers:\n  - on any user message\n  - release\n---\n")
	got2 := fm2.Phrases("triggers")
	if len(got2) != 2 || got2[0] != "on any user message" || got2[1] != "release" {
		t.Errorf("list phrases: got %v", got2)
	}
	// Missing key yields nil.
	if got3 := fm.Phrases("nope"); got3 != nil {
		t.Errorf("missing key: expected nil, got %v", got3)
	}
}

func TestInstructionFrontmatter_YAMLList(t *testing.T) {
	fm, ok := InstructionFrontmatter("---\nallowed-tools:\n  - Bash\n  - Read\n---\n")
	if !ok {
		t.Fatal("expected parse")
	}
	if got := fm.StringList("allowed-tools"); len(got) != 2 {
		t.Errorf("yaml list form: got %v", got)
	}
}

func TestInstructionFrontmatter_None(t *testing.T) {
	for _, c := range []string{
		"# Just a heading\n\nNo frontmatter.\n",
		"",
		"---\nunterminated: true\nno closing fence\n",
	} {
		if _, ok := InstructionFrontmatter(c); ok {
			t.Errorf("expected no frontmatter for %q", c)
		}
	}
}

func TestInstructionFrontmatter_BOMTolerated(t *testing.T) {
	if _, ok := InstructionFrontmatter("\ufeff---\nallowed-tools: Bash\n---\n"); !ok {
		t.Error("expected frontmatter parse despite leading BOM")
	}
}

// List elements that are not strings, or are blank, are dropped; a nil
// frontmatter answers every accessor with the zero value.
func TestFrontmatter_LooseValues(t *testing.T) {
	fm, ok := InstructionFrontmatter("---\ntools: [Bash, 3, \"  \", Read]\ntriggers: [deploy, true, \"\"]\nscalar: \"a,  ,b\"\nlist: \"Bash,\\r,Read\"\n---\n")
	if !ok {
		t.Fatal("expected frontmatter to parse")
	}
	if got := fm.StringList("tools"); !reflect.DeepEqual(got, []string{"Bash", "Read"}) {
		t.Errorf("StringList(tools) = %v", got)
	}
	if got := fm.StringList("list"); !reflect.DeepEqual(got, []string{"Bash", "Read"}) {
		t.Errorf("a blank field after trimming is dropped, got %v", got)
	}
	if got := fm.Phrases("triggers"); !reflect.DeepEqual(got, []string{"deploy"}) {
		t.Errorf("Phrases(triggers) = %v", got)
	}
	if got := fm.Phrases("scalar"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("Phrases(scalar) = %v", got)
	}
	if fm.StringList("missing") != nil || fm.Phrases("missing") != nil {
		t.Error("a missing key yields nil")
	}

	var nilFM *Frontmatter
	if nilFM.StringList("tools") != nil || nilFM.Phrases("tools") != nil || nilFM.Bool("x") || nilFM.String("x") != "" {
		t.Error("a nil frontmatter answers nothing")
	}
}
