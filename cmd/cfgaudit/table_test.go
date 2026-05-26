package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestResolveFormat(t *testing.T) {
	cases := []struct {
		flag string
		tty  bool
		want string
	}{
		{"auto", true, "table"},
		{"auto", false, "text"},
		{"text", true, "text"},    // explicit text wins on a TTY
		{"table", false, "table"}, // explicit table wins when piped
		{"json", true, "json"},
		{"sarif", false, "sarif"},
	}
	for _, c := range cases {
		if got := resolveFormat(c.flag, c.tty); got != c.want {
			t.Errorf("resolveFormat(%q, tty=%v) = %q, want %q", c.flag, c.tty, got, c.want)
		}
	}
}

func TestRenderTable(t *testing.T) {
	var buf bytes.Buffer
	renderTable(&buf, []finding.Finding{
		{RuleID: "CFG036", Severity: finding.Error, File: "CLAUDE.md", Line: 52,
			Message: "CLAUDE.md line 52 uses command substitution reading a sensitive path (Part A) — reading credential files has no legitimate use. Remove it"},
		{RuleID: "CFG006", Severity: finding.Warn, File: ".claude/settings.local.json",
			Message: "permissions.deny is absent or empty — no guardrails block destructive operations"},
	}, "1.0.3")
	out := buf.String()

	if !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "RULE") || !strings.Contains(out, "LOCATION") || !strings.Contains(out, "MESSAGE") {
		t.Errorf("expected a header row, got:\n%s", out)
	}
	if !strings.Contains(out, "CLAUDE.md:52") {
		t.Errorf("expected file:line location, got:\n%s", out)
	}
	// The explanatory tail after " — " is dropped in table mode.
	if strings.Contains(out, "no legitimate use") || strings.Contains(out, "no guardrails block") {
		t.Errorf("expected message tail to be trimmed, got:\n%s", out)
	}
	if !strings.Contains(out, "cfgaudit 1.0.3 — 2 findings") {
		t.Errorf("expected summary line, got:\n%s", out)
	}
}

func TestRenderTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	renderTable(&buf, nil, "1.0.3")
	if got := strings.TrimSpace(buf.String()); got != "cfgaudit 1.0.3 — no findings" {
		t.Errorf("unexpected empty output: %q", got)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("hello", 10); got != "hello" {
		t.Errorf("short string changed: %q", got)
	}
	got := truncateRunes("abcdefghij", 5)
	if []rune(got)[4] != '…' || len([]rune(got)) != 5 {
		t.Errorf("expected 5 runes ending in ellipsis, got %q", got)
	}
}
