package rules

import (
	"fmt"
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
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		// Codex spells the same decision as an approval mode rather than a tool
		// list. Only "approve" removes the prompt, and the parser records just
		// that value, so anything present here already means "never asks".
		if key := ref.Server.ApprovalModeKey; key != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG011",
				Severity: finding.Warn,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + "." + key + " is \"approve\", so every tool this server exposes runs without a confirmation prompt," +
					" including ones added to the server later. Codex asks for approval by default (\"auto\"); use \"writes\" to keep the prompt for state-changing tools, or \"prompt\" to keep it for all of them",
			})
		}
		if msg := analyzeApprovedTools(ref.Server.ApprovedTools); msg != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG011",
				Severity: finding.Warn,
				File:     ref.File,
				Message:  "mcpServers." + ref.Name + " sets approval_mode \"approve\" " + msg,
			})
		}
		if len(ref.Server.AlwaysAllow) == 0 {
			continue
		}
		if msg := analyzeAlwaysAllow(ref.Server.AlwaysAllow); msg != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG011",
				Severity: finding.Warn,
				File:     ref.File,
				Message:  "mcpServers." + ref.Name + ".alwaysAllow " + msg,
			})
		}
	}
	return findings
}

// analyzeApprovedTools judges the per-tool Codex form of the same decision. The
// tools are named one by one there, so there is no wildcard case; what is left
// is the state-mutating check and the size threshold alwaysAllow already uses.
func analyzeApprovedTools(tools []string) string {
	if len(tools) == 0 {
		return ""
	}
	if dangerous := dangerousToolNames(tools); len(dangerous) > 0 {
		return "on the state-mutating tools " + strings.Join(dangerous, ", ") +
			" — those calls run with no confirmation prompt, and auto-approval should be limited to read-only tools"
	}
	if len(tools) >= alwaysAllowSizeThreshold {
		return fmt.Sprintf("on %d tools — review whether each is safe to bypass confirmation for", len(tools))
	}
	return ""
}

// dangerousToolNames returns the quoted names that match a state-mutating
// fragment, preserving input order.
func dangerousToolNames(list []string) []string {
	var dangerous []string
	for _, tool := range list {
		if matchesDangerousTool(tool) {
			dangerous = append(dangerous, "\""+tool+"\"")
		}
	}
	return dangerous
}

func analyzeAlwaysAllow(list []string) string {
	for _, tool := range list {
		if tool == "*" {
			return "contains wildcard \"*\" — auto-approves every tool the server exposes, with no per-call prompt"
		}
	}
	dangerous := dangerousToolNames(list)
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
