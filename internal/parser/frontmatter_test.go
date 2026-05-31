package parser

import "testing"

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
