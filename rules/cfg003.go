package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg003 struct{}

var CFG003 = &cfg003{}

func init() { All = append(All, CFG003) }

func (r *cfg003) ID() string { return "CFG003" }

// MinVersion returns the lowest Claude Code release where enableAllProjectMcpServers
// is known to be a recognised settings.json key. The setting predates the bundled
// 0.2.x changelog entries so this gate is effectively a no-op for modern installs;
// it exists to satisfy the version-gating contract uniformly across rules.
func (r *cfg003) MinVersion() string { return "0.2.21" }

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
		Message:  "enableAllProjectMcpServers: true auto-approves every MCP server in any .mcp.json in the repository — anyone with commit access can execute arbitrary code (CVE-2025-59536)",
	}}
}
