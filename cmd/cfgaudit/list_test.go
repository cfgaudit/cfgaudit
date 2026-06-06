package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestList_Text(t *testing.T) {
	out, code := listOutput(nil)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	for _, want := range []string{"ID", "SEVERITY", "OWASP", "CFG001", "rules total"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestList_JSON(t *testing.T) {
	out, code := listOutput([]string{"--format", "json"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	var rules []ruleSummary
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(rules) < 20 {
		t.Errorf("expected many rules, got %d", len(rules))
	}
	if rules[0].ID == "" || rules[0].Severity == "" || rules[0].OWASP == "" || rules[0].Description == "" {
		t.Errorf("expected fully-populated summary, got %+v", rules[0])
	}
}

func TestList_OwaspFilter(t *testing.T) {
	out, code := listOutput([]string{"--format", "json", "--owasp", "LLM01"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	var rules []ruleSummary
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("expected some LLM01 rules")
	}
	for _, r := range rules {
		if r.OWASP != "LLM01" {
			t.Errorf("filter leaked a non-LLM01 rule: %+v", r)
		}
	}
}

func TestList_OwaspMCPFilter(t *testing.T) {
	out, code := listOutput([]string{"--format", "json", "--owasp", "MCP05"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	var rules []ruleSummary
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("expected some MCP05 rules")
	}
	for _, r := range rules {
		if r.OWASPMCP != "MCP05" {
			t.Errorf("filter leaked a non-MCP05 rule: %+v", r)
		}
	}
}

func TestList_BadFlag(t *testing.T) {
	if _, code := listOutput([]string{"--nope"}); code != 2 {
		t.Errorf("expected exit 2 for unknown flag, got %d", code)
	}
}

func TestSummarize(t *testing.T) {
	doc := "# CFG999 — `permissions.allow` does a thing\n\n**Severity:** `error` · `warn`\n**OWASP:** [LLM06:2025 – Excessive Agency](https://x)\n**OWASP MCP:** [MCP02:2025 – Privilege Escalation via Scope Creep](https://y) — provisional (MCP Top 10 v0.1)\n"
	s := summarize("CFG999", doc)
	if s.Description != "permissions.allow does a thing" {
		t.Errorf("description: got %q", s.Description)
	}
	if s.Severity != "error/warn" {
		t.Errorf("severity: got %q", s.Severity)
	}
	if s.OWASP != "LLM06" {
		t.Errorf("owasp: got %q", s.OWASP)
	}
	if s.OWASPMCP != "MCP02" {
		t.Errorf("owasp_mcp: got %q", s.OWASPMCP)
	}
}

func TestSummarize_NoMCPMapping(t *testing.T) {
	doc := "# CFG998 — a thing\n\n**Severity:** `error`\n**OWASP:** [LLM01:2025 – Prompt Injection](https://x)\n"
	if s := summarize("CFG998", doc); s.OWASPMCP != "" {
		t.Errorf("expected empty OWASPMCP for a non-MCP rule, got %q", s.OWASPMCP)
	}
}
