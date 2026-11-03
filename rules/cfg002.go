// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg002 struct{}

var CFG002 = &cfg002{}

func init() { All = append(All, CFG002) }

func (r *cfg002) ID() string { return "CFG002" }

var editGrantRe = regexp.MustCompile(`^Edit\((.*)\)$`)

type foreignAgentConfig struct {
	pattern string
	sample  string
	agent   string
	regexp  *regexp.Regexp
}

var foreignAgentConfigs = []foreignAgentConfig{
	newForeignAgentConfig(".mcp.json", ".mcp.json", "VS Code and Kimi Code"),
	newForeignAgentConfig(".vscode/settings.json", ".vscode/settings.json", "VS Code"),
	newForeignAgentConfig(".vscode/tasks.json", ".vscode/tasks.json", "VS Code"),
	newForeignAgentConfig(".vscode/mcp.json", ".vscode/mcp.json", "VS Code"),
	newForeignAgentConfig(".github/mcp.json", ".github/mcp.json", "GitHub Copilot CLI"),
	newForeignAgentConfig(".github/hooks/*.json", ".github/hooks/hook.json", "GitHub Copilot"),
	newForeignAgentConfig(".cursor/mcp.json", ".cursor/mcp.json", "Cursor"),
	newForeignAgentConfig(".cursor/cli.json", ".cursor/cli.json", "Cursor"),
	newForeignAgentConfig(".cursor/permissions.json", ".cursor/permissions.json", "Cursor"),
	newForeignAgentConfig(".cursor/hooks.json", ".cursor/hooks.json", "Cursor"),
	newForeignAgentConfig(".codex/config.toml", ".codex/config.toml", "Codex"),
	newForeignAgentConfig(".codex/hooks.json", ".codex/hooks.json", "Codex"),
	newForeignAgentConfig(".gemini/settings.json", ".gemini/settings.json", "Gemini CLI"),
	newForeignAgentConfig(".qwen/settings.json", ".qwen/settings.json", "Qwen Code"),
	newForeignAgentConfig(".roo/mcp.json", ".roo/mcp.json", "Roo Code"),
	newForeignAgentConfig(".devin/config.json", ".devin/config.json", "Devin CLI"),
	newForeignAgentConfig(".devin/config.local.json", ".devin/config.local.json", "Devin CLI"),
	newForeignAgentConfig(".devin/mcp_config.json", ".devin/mcp_config.json", "Devin CLI"),
	newForeignAgentConfig(".devin/mcp_config.local.json", ".devin/mcp_config.local.json", "Devin CLI"),
	newForeignAgentConfig("opencode.json", "opencode.json", "OpenCode"),
	newForeignAgentConfig("opencode.jsonc", "opencode.jsonc", "OpenCode"),
	newForeignAgentConfig(".opencode/opencode.json", ".opencode/opencode.json", "OpenCode"),
	newForeignAgentConfig(".opencode/opencode.jsonc", ".opencode/opencode.jsonc", "OpenCode"),
	newForeignAgentConfig(".kiro/**", ".kiro/settings/mcp.json", "Kiro"),
	newForeignAgentConfig(".windsurf/**", ".windsurf/hooks.json", "Windsurf"),
	newForeignAgentConfig(".windsurfrules", ".windsurfrules", "Windsurf"),
	newForeignAgentConfig("cline_mcp_settings.json", "cline_mcp_settings.json", "Cline"),
	newForeignAgentConfig(".cline/**", ".cline/rules/rule.md", "Cline"),
	newForeignAgentConfig(".clinerules", ".clinerules", "Cline"),
}

func newForeignAgentConfig(pattern, sample, agent string) foreignAgentConfig {
	return foreignAgentConfig{pattern: pattern, sample: sample, agent: agent, regexp: globToPathRegexp(pattern)}
}

func (r *cfg002) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		entry = strings.TrimSpace(entry)
		unrestricted := unrestrictedFileWrite(entry)
		pattern, edit := editGrant(entry)
		if !unrestricted && !edit {
			continue
		}
		if deniedInSameFile(t, entry) {
			continue
		}
		if unrestricted {
			findings = append(findings, finding.Finding{
				RuleID: "CFG002", Severity: finding.Warn, File: t.SettingsFile,
				Message: "permissions.allow contains \"" + entry + "\" — grants unrestricted file-write access; scope to specific directories" + userScopeNote(t),
			})
			continue
		}
		reachable := reachableForeignConfigs(pattern)
		if len(reachable) == 0 {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID: "CFG002", Severity: finding.Warn, File: t.SettingsFile,
			Message: "permissions.allow contains \"" + entry + "\" — lets Claude modify configuration consumed by another agent without a separate approval: " + strings.Join(reachable, ", ") + "; narrow the grant or explicitly deny foreign-agent configuration" + userScopeNote(t),
		})
	}
	return findings
}

func unrestrictedFileWrite(entry string) bool {
	if entry == "Edit" || entry == "Write" {
		return true
	}
	pattern, ok := editGrant(entry)
	if !ok {
		return false
	}
	return pattern == "*" || pattern == "**" || pattern == "**/*"
}

func editGrant(entry string) (string, bool) {
	m := editGrantRe.FindStringSubmatch(entry)
	if m == nil {
		return "", false
	}
	pattern := normalizeGrantPattern(m[1])
	return pattern, pattern != ""
}

func normalizeGrantPattern(pattern string) string {
	pattern = strings.TrimSpace(strings.ReplaceAll(pattern, `\`, "/"))
	pattern = strings.TrimPrefix(pattern, "./")
	pattern = strings.TrimPrefix(pattern, "/")
	return pattern
}

func reachableForeignConfigs(pattern string) []string {
	pattern = normalizeGrantPattern(pattern)
	basenameOnly := !strings.Contains(pattern, "/")
	grantRegexp := globToPathRegexp(pattern)
	exact := !strings.ContainsAny(pattern, "*?")

	var out []string
	for _, config := range foreignAgentConfigs {
		candidate := config.sample
		if basenameOnly {
			candidate = path.Base(candidate)
		}
		if grantRegexp.MatchString(candidate) || exact && config.regexp.MatchString(pattern) {
			out = append(out, config.pattern+" ("+config.agent+")")
		}
	}
	return out
}
