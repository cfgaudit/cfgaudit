// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg125 struct{}

var CFG125 = &cfg125{}

func init() { All = append(All, CFG125) }

func (r *cfg125) ID() string { return "CFG125" }

type agentBypassSite struct {
	label, file, command string
	line                 int
	severity             finding.Severity
}

func (r *cfg125) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	seen := map[string]bool{}
	for _, site := range agentBypassSites(t) {
		key := site.file + "\x00" + site.label + "\x00" + site.command + "\x00" + strconv.Itoa(site.line)
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, inv := range agentInvocations(site.command) {
			flag, ok := agentBypass(inv)
			if !ok {
				continue
			}
			detail := "the child agent runs with its approval or sandbox controls disabled"
			if site.severity == finding.Error {
				detail = "this auto-run site disables the child agent's approval or sandbox controls"
			}
			findings = append(findings, finding.Finding{
				RuleID: "CFG125", Severity: site.severity, File: site.file, Line: site.line,
				Message: site.label + " starts " + inv.agent + " with " + flag + "; " + detail + ". Remove the bypass option",
			})
			break
		}
	}
	return findings
}

func agentBypassSites(t *Target) []agentBypassSite {
	var sites []agentBypassSite
	userCommand := map[string]bool{}
	for _, command := range t.SkillShellCommands {
		userCommand[t.InstructionFile+"\x00"+command] = true
	}
	for _, site := range commandSites(t) {
		severity := finding.Error
		if site.HookInput || userCommand[site.File+"\x00"+site.Command] || strings.Contains(site.Label, "frontmatter hooks.") {
			severity = finding.Warn
		}
		sites = append(sites, agentBypassSite{label: site.Label, file: site.File, command: site.Command, line: site.Line, severity: severity})
	}
	if tasks := t.VSCodeTasks; tasks != nil {
		for _, task := range tasks.Tasks {
			severity := finding.Warn
			kind := "VS Code task"
			if task.RunOptions != nil && task.RunOptions.RunOn == "folderOpen" {
				severity = finding.Error
				kind = "VS Code folderOpen task"
			}
			for _, command := range task.CommandLines() {
				sites = append(sites, agentBypassSite{label: kind + " \"" + task.Label + "\" command", file: t.VSCodeTasksFile, command: command, severity: severity})
			}
		}
	}
	for _, ref := range t.mcpServerRefs() {
		command := strings.TrimSpace(ref.Server.Command + " " + strings.Join(ref.Server.Args, " "))
		if command != "" {
			sites = append(sites, agentBypassSite{label: "mcpServers." + ref.Name + " command", file: ref.File, command: command, severity: finding.Error})
		}
	}
	for _, script := range t.LaunchedScripts {
		if script.Via != "" || script.Partial || !shellScriptRe.MatchString(script.File) {
			continue
		}
		severity := finding.Error
		if script.Skill != "" {
			severity = finding.Warn
		}
		for _, line := range scriptCommandLines(script.Content) {
			sites = append(sites, agentBypassSite{label: script.Label, file: script.File, command: maskMessageQuotes(line.text), line: line.line, severity: severity})
		}
	}
	return sites
}
