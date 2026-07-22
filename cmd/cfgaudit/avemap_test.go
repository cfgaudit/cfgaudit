package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/rules"
)

var aveIDRe = regexp.MustCompile(`^AVE-2026-\d{5}$`)

// The AVE map is the one coupling point to AVE. Guard it against drift: every id
// must be well-formed, map onto a registered rule, and appear in the crosswalk
// doc, so the map, docs/cfgaudit-to-ave.md, and the emitted output can't diverge.
func TestAVEMap_ConsistentWithCrosswalk(t *testing.T) {
	registered := map[string]bool{}
	for _, r := range rules.All {
		registered[r.ID()] = true
	}

	crosswalk, err := os.ReadFile(filepath.Join("..", "..", "docs", "cfgaudit-to-ave.md"))
	if err != nil {
		t.Fatalf("read crosswalk: %v", err)
	}
	doc := string(crosswalk)

	for ruleID, aveID := range aveByRule {
		if !registered[ruleID] {
			t.Errorf("aveByRule maps %s, which is not a registered rule", ruleID)
		}
		if !aveIDRe.MatchString(aveID) {
			t.Errorf("%s → %q is not a well-formed AVE id", ruleID, aveID)
		}
		if !strings.Contains(doc, aveID) {
			t.Errorf("%s → %s is not referenced in docs/cfgaudit-to-ave.md — map and crosswalk have drifted", ruleID, aveID)
		}
	}
}

// A rule that carries an AVE id must also resolve an OWASP LLM id, so the output
// never emits an AVE mapping without the primary OWASP one beside it.
func TestAVEMap_MappedRulesHaveOWASP(t *testing.T) {
	for ruleID := range aveByRule {
		if ruleOWASP(ruleID) == "" {
			t.Errorf("%s has an AVE id but no OWASP LLM id parsed from its doc header", ruleID)
		}
	}
}

func TestWithTaxonomy_EnrichesFindings(t *testing.T) {
	in := []finding.Finding{
		{RuleID: "CFG090", Severity: finding.Warn}, // mapped
		{RuleID: "CFG006", Severity: finding.Warn}, // OWASP but no AVE
	}
	out := withTaxonomy(in)
	if out[0].OWASP != "LLM06" || out[0].AVEID != "AVE-2026-00032" {
		t.Errorf("CFG090: got owasp=%q ave=%q", out[0].OWASP, out[0].AVEID)
	}
	if out[1].OWASP == "" {
		t.Errorf("CFG006 should carry an OWASP id")
	}
	if out[1].AVEID != "" {
		t.Errorf("CFG006 has no AVE class and must emit no ave id, got %q", out[1].AVEID)
	}
}

func TestTaxonomyProps_OmittedWhenAbsent(t *testing.T) {
	// A synthetic rule id with no doc and no AVE mapping yields nil (SARIF omits it).
	if p := taxonomyProps("CFG999"); p != nil {
		t.Errorf("expected nil props for an unmapped/undocumented rule, got %v", p)
	}
}
