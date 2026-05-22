package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg011 struct{}

var CFG011 = &cfg011{}

func init() { All = append(All, CFG011) }

func (r *cfg011) ID() string { return "CFG011" }

// dangerousToolFragments are case-insensitive substring patterns marking state-mutating tools.
// A tool name containing any of these should not be on alwaysAllow without an explicit decision.
var dangerousToolFragments = []string{
	"write", "delete", "remove", "edit", "exec",
	"run_command", "shell", "bash", "kill", "patch",
	"move_file", "rename", "create_file", "create_directory",
}

// alwaysAllowSizeThreshold is the count at which a non-wildcard, non-dangerous list
// is still considered too broad — auto-approving this many tools is rarely deliberate.
const alwaysAllowSizeThreshold = 10

func (r *cfg011) Check(t *Target) []finding.Finding {
	if t.Settings == nil || len(t.Settings.MCPServers) == 0 {
		return nil
	}
	names := make([]string, 0, len(t.Settings.MCPServers))
	for n := range t.Settings.MCPServers {
		names = append(names, n)
	}
	sort.Strings(names)

	var findings []finding.Finding
	for _, name := range names {
		s := t.Settings.MCPServers[name]
		if len(s.AlwaysAllow) == 0 {
			continue
		}
		if msg := analyzeAlwaysAllow(s.AlwaysAllow); msg != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG011",
				Severity: finding.Warn,
				File:     t.SettingsFile,
				Message:  "mcpServers." + name + ".alwaysAllow " + msg,
			})
		}
	}
	return findings
}

func analyzeAlwaysAllow(list []string) string {
	for _, tool := range list {
		if tool == "*" {
			return "contains wildcard \"*\" — auto-approves every tool the server exposes, with no per-call prompt"
		}
	}
	var dangerous []string
	for _, tool := range list {
		if matchesDangerousTool(tool) {
			dangerous = append(dangerous, "\""+tool+"\"")
		}
	}
	if len(dangerous) > 0 {
		return "includes state-mutating tools " + strings.Join(dangerous, ", ") + " — auto-approval should be limited to read-only tools"
	}
	if len(list) >= alwaysAllowSizeThreshold {
		return fmt.Sprintf("auto-approves %d tools — review whether each is safe to bypass confirmation for", len(list))
	}
	return ""
}

func matchesDangerousTool(tool string) bool {
	low := strings.ToLower(tool)
	for _, frag := range dangerousToolFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}
