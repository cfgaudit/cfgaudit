package main

import (
	"regexp"

	cfgaudit "github.com/cfgaudit/cfgaudit"
	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// jsonFinding is a finding enriched with its taxonomy ids for machine output.
// The mapping is rule-level, so the ids are resolved by RuleID at serialization
// time rather than stored on finding.Finding — the core finding type stays
// unchanged and the text/table output is untouched. Both fields are omitempty:
// every rule has an OWASP id, but only the ~34 rules in aveByRule carry an AVE
// id, and a new rule for a threat AVE has not catalogued carries none.
type jsonFinding struct {
	finding.Finding
	OWASP string `json:"OWASP,omitempty"`
	AVEID string `json:"AVEID,omitempty"`
}

// withTaxonomy wraps each finding with its OWASP LLM and AVE ids for JSON output.
func withTaxonomy(findings []finding.Finding) []jsonFinding {
	out := make([]jsonFinding, len(findings))
	for i, f := range findings {
		out[i] = jsonFinding{Finding: f, OWASP: ruleOWASP(f.RuleID), AVEID: ruleAVE(f.RuleID)}
	}
	return out
}

// aveByRule maps a cfgaudit rule to its primary AVE behavioral class
// (Agentic Vulnerability Enumeration, https://github.com/aveproject/ave). It is
// deliberately a single file rather than a per-rule doc-header line: AVE is early
// and single-vendor, and the whole mapping is meant to be removable (see
// docs/cfgaudit-to-ave.md) — deleting one file reverses it, where scattering the
// id across 34 doc headers would not. The primary ids here are sourced from the
// mappings in docs/cfgaudit-to-ave.md; a rule may cover more than one AVE class,
// but only the canonical one is emitted so the output field stays singular
// (matching AVE's own one-ruleId-per-class SARIF model).
//
// OWASP LLM ids are NOT here — they are intrinsic to every rule and parsed from
// the `**OWASP:**` doc header (see ruleOWASP), the existing single source of
// truth used by `cfgaudit list`.
var aveByRule = map[string]string{
	// instruction / skill content
	"CFG024": "AVE-2026-00029", // hidden Unicode → homoglyph/unicode obfuscation
	"CFG026": "AVE-2026-00007", // override/persona → goal hijack
	"CFG029": "AVE-2026-00021", // bypass prompts → autonomous action without confirmation
	"CFG030": "AVE-2026-00010", // conceal behavior → covert instruction concealment
	"CFG031": "AVE-2026-00003", // sensitive path → credential exfil
	"CFG032": "AVE-2026-00025", // pseudo-system/role injection → conversation-history injection
	"CFG033": "AVE-2026-00039", // image-exfil sink → covert channel
	"CFG035": "AVE-2026-00011", // configure/trust MCP → dynamic tool call
	"CFG036": "AVE-2026-00003", // embedded exfil shell → credential exfil
	"CFG051": "AVE-2026-00048", // allowed-tools grant → unsafe delegation
	"CFG056": "AVE-2026-00058", // broad trigger → deceptive trigger scope
	"CFG057": "AVE-2026-00057", // encoded payload → obfuscated payload
	"CFG081": "AVE-2026-00027", // survive compaction → multi-turn persistence
	"CFG085": "AVE-2026-00048", // subagent perm mode → unsafe delegation
	"CFG090": "AVE-2026-00032", // network reconnaissance instruction

	// command content
	"CFG008": "AVE-2026-00004", // reverse shell → shell-pipe code execution
	"CFG014": "AVE-2026-00004", // curl|sh → shell-pipe code execution
	"CFG027": "AVE-2026-00008", // persistence → self-replication
	"CFG028": "AVE-2026-00008", // write trust files → self-replication
	"CFG037": "AVE-2026-00003", // SSH key read → credential exfil
	"CFG038": "AVE-2026-00003", // env dump → credential exfil
	"CFG039": "AVE-2026-00005", // rm -rf → recursive filesystem destruction
	"CFG072": "AVE-2026-00039", // DNS exfil → covert channel

	// MCP configuration
	"CFG007": "AVE-2026-00047", // settings secret → hardcoded credentials
	"CFG050": "AVE-2026-00047", // MCP env/headers secret → hardcoded credentials
	"CFG054": "AVE-2026-00047", // entropy secret → hardcoded credentials
	"CFG065": "AVE-2026-00047", // Continue inline apiKey → hardcoded credentials
	"CFG073": "AVE-2026-00047", // crypto signing key → hardcoded credentials
	"CFG052": "AVE-2026-00017", // name shadowing → server impersonation
	"CFG059": "AVE-2026-00017", // typosquat → server impersonation
	"CFG019": "AVE-2026-00055", // MCP inline script → untrusted launch config command exec
	"CFG020": "AVE-2026-00055", // MCP env code injection → untrusted launch config command exec
	"CFG070": "AVE-2026-00055", // MCP repo-relative command → untrusted launch config command exec
}

// ruleAVE returns the primary AVE id for a rule, or "" if none is mapped.
func ruleAVE(id string) string { return aveByRule[id] }

var docOwaspLLMRe = regexp.MustCompile(`LLM\d{2}`)

// ruleOWASP returns the OWASP LLM id for a rule, parsed from its doc header —
// the same single source of truth `cfgaudit list` reads. "" if the doc is
// missing or carries no LLM id.
func ruleOWASP(id string) string {
	doc, ok := cfgaudit.RuleDoc(id)
	if !ok {
		return ""
	}
	return docOwaspLLMRe.FindString(doc)
}
