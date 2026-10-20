package parser

import (
	"reflect"
	"testing"
)

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
