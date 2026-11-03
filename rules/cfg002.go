// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

type cfg002 struct{}

var CFG002 = &cfg002{}

func init() { All = append(All, CFG002) }

func (r *cfg002) ID() string { return "CFG002" }

var unrestrictedWriteRe = regexp.MustCompile(`^(?:Edit|Write)(?:\(\s*\*+\s*\))?$`)
var fileGrantRe = regexp.MustCompile(`^(Edit|Write)\((.*)\)$`)
var sensitiveEditFrom = version.Version{Major: 2, Minor: 1, Patch: 317}

var foreignAgentConfigs = []string{
	".mcp.json",
	".vscode/settings.json", ".vscode/tasks.json",
	".cursor/mcp.json", ".cursor/cli.json", ".cursor/permissions.json", ".cursor/hooks.json",
	".codex/config.toml", ".codex/hooks.json",
	".gemini/settings.json", ".qwen/settings.json", ".roo/mcp.json", ".github/mcp.json",
}

var claudeSensitiveEditConfigs = map[string]bool{
	".mcp.json": true, ".vscode/settings.json": true, ".vscode/tasks.json": true,
}

func (r *cfg002) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		entry = strings.TrimSpace(entry)
		tool, pattern, ok := fileGrant(entry)
		if !ok {
			continue
		}
		if deniedInSameFile(t, entry) {
			continue
		}
		reachable := reachableForeignConfigs(tool, pattern, t.ClaudeVersion)
		if len(reachable) > 0 {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG002",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Message:  "permissions.allow contains \"" + entry + "\" — lets Claude modify configuration consumed by another agent without a separate approval: " + strings.Join(reachable, ", ") + "; narrow the grant or explicitly deny foreign-agent configuration" + userScopeNote(t),
			})
			continue
		}
		if unrestrictedWriteRe.MatchString(entry) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG002",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Message:  "permissions.allow contains \"" + entry + "\" — grants unrestricted file-write access; scope to specific directories" + userScopeNote(t),
			})
		}
	}
	return findings
}

func fileGrant(entry string) (tool, pattern string, ok bool) {
	if entry == "Edit" || entry == "Write" {
		return entry, "**", true
	}
	m := fileGrantRe.FindStringSubmatch(entry)
	if m == nil {
		return "", "", false
	}
	return m[1], strings.TrimSpace(strings.ReplaceAll(m[2], `\`, "/")), true
}

func reachableForeignConfigs(tool, pattern string, claudeVersion *version.Version) []string {
	p := strings.TrimPrefix(strings.TrimSpace(pattern), "./")
	if p == "" {
		return nil
	}
	lower := strings.ToLower(p)
	wild := strings.ContainsAny(p, "*?")
	if !wild {
		for _, config := range foreignAgentConfigs {
			if configProtectedFromEdit(tool, config, claudeVersion) {
				continue
			}
			if lower == config || strings.HasSuffix(lower, "/"+config) {
				return []string{config}
			}
		}
		return nil
	}
	if p[0] != '*' && !strings.Contains(lower, ".") {
		return nil
	}

	re := compileGrantPattern(p)
	var out []string
	for _, config := range foreignAgentConfigs {
		if !configProtectedFromEdit(tool, config, claudeVersion) && re.MatchString(config) {
			out = append(out, config)
		}
	}
	return out
}

func configProtectedFromEdit(tool, config string, claudeVersion *version.Version) bool {
	return tool == "Edit" && claudeVersion != nil && claudeVersion.AtLeast(sensitiveEditFrom) && claudeSensitiveEditConfigs[config]
}

func compileGrantPattern(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`(?i)^`)
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String())
}
