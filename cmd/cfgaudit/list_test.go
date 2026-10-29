// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	cfgaudit "github.com/cfgaudit/cfgaudit"
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
	// Every rule, not only the first: docs titled "# CFGxxx: ..." printed no
	// description (#916).
	for _, r := range rules {
		if r.ID == "" || r.Severity == "" || r.OWASP == "" || r.Description == "" {
			t.Errorf("expected fully-populated summary, got %+v", r)
		}
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
	doc := "# CFG999 — `permissions.allow` does a thing\n\n**Severity:** `error` · `warn`\n**OWASP:** [LLM03:2026 – Excessive Agency](https://x)\n**OWASP MCP:** [MCP02:2025 – Privilege Escalation via Scope Creep](https://y) — provisional (MCP Top 10 v0.1)\n"
	s := summarize("CFG999", doc)
	if s.Description != "permissions.allow does a thing" {
		t.Errorf("description: got %q", s.Description)
	}
	if s.Severity != "error/warn" {
		t.Errorf("severity: got %q", s.Severity)
	}
	if s.OWASP != "LLM03" {
		t.Errorf("owasp: got %q", s.OWASP)
	}
	if s.OWASPMCP != "MCP02" {
		t.Errorf("owasp_mcp: got %q", s.OWASPMCP)
	}
}

func TestSummarize_NoMCPMapping(t *testing.T) {
	doc := "# CFG998 — a thing\n\n**Severity:** `error`\n**OWASP:** [LLM01:2026 – Prompt Injection](https://x)\n"
	if s := summarize("CFG998", doc); s.OWASPMCP != "" {
		t.Errorf("expected empty OWASPMCP for a non-MCP rule, got %q", s.OWASPMCP)
	}
}

func TestDocAgents(t *testing.T) {
	got, ok := docAgents("# CFG999 — x\n\n**Severity:** `error`\n**Agents:** cursor, Claude-Code, `vscode`, cursor\n")
	if !ok || strings.Join(got, ",") != "claude-code,cursor,vscode" {
		t.Errorf("docAgents = %v, %v", got, ok)
	}
	if got, ok := docAgents("# CFG999 — x\n"); ok || got == nil || len(got) != 0 {
		t.Errorf("a doc without the line gives an empty, non-nil list and false, got %v, %v", got, ok)
	}
}

// #1036: every rule doc has an "**Agents:**" line that names at least one
// agent, and only known ones.
func TestList_AgentsLines(t *testing.T) {
	for _, id := range cfgaudit.RuleIDs() {
		doc, _ := cfgaudit.RuleDoc(id)
		agents, ok := docAgents(doc)
		if !ok {
			t.Errorf("%s: no **Agents:** line; add one next to Severity and OWASP (see CONTRIBUTING)", id)
			continue
		}
		if len(agents) == 0 {
			t.Errorf("%s: empty **Agents:** line", id)
		}
		for _, a := range agents {
			if knownAgents[a] == "" {
				t.Errorf("%s: unknown agent %q; add it to knownAgents first", id, a)
			}
		}
	}
}

func TestList_AgentFilter(t *testing.T) {
	out, code := listOutput([]string{"--format", "json", "--agent", "Cursor"})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: %s", code, out)
	}
	var rules []ruleSummary
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("expected some rules for cursor")
	}
	for _, r := range rules {
		if !contains(r.Agents, "cursor") {
			t.Errorf("filter leaked a rule without cursor: %+v", r)
		}
	}
	if out, code := listOutput([]string{"--agent", "nope"}); code != 2 || !strings.Contains(out, "unknown agent") {
		t.Errorf("unknown agent: exit %d, %q", code, out)
	}
}

// The JSON always carries an agents array, also for a rule not classified yet,
// so a consumer never meets null.
func TestList_AgentsAlwaysArray(t *testing.T) {
	out, _ := listOutput([]string{"--format", "json"})
	if strings.Contains(out, `"agents": null`) {
		t.Error("agents is null for some rule")
	}
}
