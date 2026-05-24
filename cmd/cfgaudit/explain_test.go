package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunExplain_KnownRule(t *testing.T) {
	var b bytes.Buffer
	if code := runExplain(&b, []string{"CFG001"}); code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	out := b.String()
	if !strings.Contains(out, "CFG001") {
		t.Errorf("expected output to mention CFG001, got: %s", out)
	}
	if !strings.Contains(out, "docs/rules/CFG001.md") {
		t.Errorf("expected a Docs URL, got: %s", out)
	}
	if strings.Contains(out, "**") {
		t.Errorf("expected bold markers stripped, got: %s", out)
	}
}

func TestRunExplain_CaseInsensitive(t *testing.T) {
	var b bytes.Buffer
	if code := runExplain(&b, []string{"cfg010"}); code != 0 {
		t.Errorf("expected lowercase id to resolve, got exit %d", code)
	}
}

func TestRunExplain_UnknownRule(t *testing.T) {
	var b bytes.Buffer
	if code := runExplain(&b, []string{"CFG999"}); code != 2 {
		t.Errorf("expected exit 2 for unknown rule, got %d", code)
	}
	if !strings.Contains(b.String(), "unknown rule") {
		t.Errorf("expected 'unknown rule' message, got: %s", b.String())
	}
}

func TestRunExplain_NoArg(t *testing.T) {
	var b bytes.Buffer
	if code := runExplain(&b, nil); code != 2 {
		t.Errorf("expected exit 2 with no arg, got %d", code)
	}
	if !strings.Contains(b.String(), "usage") {
		t.Errorf("expected usage message, got: %s", b.String())
	}
}

func TestRenderRuleDoc_PreservesCodeFence(t *testing.T) {
	md := "# Title\n\n**Bold** text.\n\n```json\n{\"x\": \"**not bold**\"}\n```\n"
	out := renderRuleDoc(md)
	if strings.Contains(out, "**Bold**") {
		t.Errorf("expected bold stripped outside code, got: %s", out)
	}
	if !strings.Contains(out, `"**not bold**"`) {
		t.Errorf("expected code-fence content preserved verbatim, got: %s", out)
	}
	if !strings.Contains(out, "Title") || strings.Contains(out, "# Title") {
		t.Errorf("expected heading marker stripped, got: %s", out)
	}
}
