package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/rules"
)

func TestSarifLevel(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.Error: "error",
		finding.Warn:  "warning",
		finding.Info:  "note",
		"":            "none",
	}
	for in, want := range cases {
		if got := sarifLevel(in); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncodeSARIF_Shape(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "CFG001", Severity: finding.Error, File: ".claude/settings.json", Message: "msg-1"},
		{RuleID: "CFG009", Severity: finding.Warn, File: ".claude/settings.json", Line: 5, Col: 3, Message: "msg-2"},
	}
	allRules := []rules.Rule{stubRule{id: "CFG001"}, stubRule{id: "CFG009"}}

	var buf bytes.Buffer
	if err := encodeSARIF(&buf, findings, "0.1.0", allRules); err != nil {
		t.Fatalf("encodeSARIF: %v", err)
	}

	// First, the document must parse as JSON.
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if doc.Version != "2.1.0" {
		t.Errorf("doc.Version = %q, want 2.1.0", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-2.1.0") {
		t.Errorf("doc.Schema does not reference sarif-2.1.0: %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}

	run := doc.Runs[0]
	if run.Tool.Driver.Name != "cfgaudit" || run.Tool.Driver.Version != "0.1.0" {
		t.Errorf("driver name/version unexpected: %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules in catalog, got %d", len(run.Tool.Driver.Rules))
	}
	for _, r := range run.Tool.Driver.Rules {
		if !strings.HasPrefix(r.HelpURI, "https://github.com/cfgaudit/cfgaudit/blob/main/docs/rules/") {
			t.Errorf("rule helpUri does not look right: %q", r.HelpURI)
		}
	}

	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
		t.Errorf("levels wrong: %s / %s", run.Results[0].Level, run.Results[1].Level)
	}
	if run.Results[1].Locations[0].PhysicalLocation.Region == nil ||
		run.Results[1].Locations[0].PhysicalLocation.Region.StartLine != 5 {
		t.Errorf("expected line 5 region on second result, got %+v",
			run.Results[1].Locations[0].PhysicalLocation.Region)
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("expected no region on first result (line=0), got %+v",
			run.Results[0].Locations[0].PhysicalLocation.Region)
	}
}

// AVE-in-SARIF contract: a mapped rule carries its AVE id and OWASP id in
// properties on both the rule catalog entry and each result, while the CFG id
// stays the ruleId (cfgaudit is CFG-native, not AVE-native). Locks the output
// contract, since removing these keys later would be a breaking change.
func TestEncodeSARIF_TaxonomyProperties(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "CFG090", Severity: finding.Warn, File: "CLAUDE.md", Line: 3, Message: "recon"},
	}
	var buf bytes.Buffer
	if err := encodeSARIF(&buf, findings, "0.1.0", []rules.Rule{stubRule{id: "CFG090"}}); err != nil {
		t.Fatalf("encodeSARIF: %v", err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	run := doc.Runs[0]

	res := run.Results[0]
	if res.RuleID != "CFG090" {
		t.Errorf("ruleId must stay the CFG id, got %q", res.RuleID)
	}
	if res.Properties["ave_id"] != "AVE-2026-00032" || res.Properties["owasp_llm"] != "LLM06" {
		t.Errorf("result properties wrong: %v", res.Properties)
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.Properties["ave_id"] != "AVE-2026-00032" || rule.Properties["owasp_llm"] != "LLM06" {
		t.Errorf("rule properties wrong: %v", rule.Properties)
	}
}
