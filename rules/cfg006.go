package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg006 struct{}

var CFG006 = &cfg006{}

func init() { All = append(All, CFG006) }

func (r *cfg006) ID() string { return "CFG006" }

func (r *cfg006) Check(t *Target) []finding.Finding {
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
		RuleID:   "CFG006",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message:  "enableAllProjectMcpServers: true auto-approves every MCP server in any .mcp.json in the repository — anyone with commit access can execute arbitrary code (CVE-2025-59536)",
	}}
}
