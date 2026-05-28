package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg003 struct{}

var CFG003 = &cfg003{}

func init() { All = append(All, CFG003) }

func (r *cfg003) ID() string { return "CFG003" }

// No MinVersion: this rule is presence-based — it fires only when
// enableAllProjectMcpServers is actually set, which by definition means a Claude
// Code version that recognises the key. Version-gating would add no correctness
// and could wrongly skip a stale dangerous key on an older detected version.

func (r *cfg003) Check(t *Target) []finding.Finding {
	if t.Settings == nil {
		return nil
	}
	raw, ok := t.Settings.Raw["enableAllProjectMcpServers"]
	if !ok {
		return nil
	}
	if string(raw) != "true" {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG003",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "enableAllProjectMcpServers: true auto-approves every MCP server in any .mcp.json in the repository — anyone with commit access can execute arbitrary code (CVE-2025-59536)" + userScopeNote(t),
	}}
}
