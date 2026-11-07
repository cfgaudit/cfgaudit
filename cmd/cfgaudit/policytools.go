// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// rooPolicyTarget collects what Roo Code keeps in a repository.
func rooPolicyTarget(dir string, p config.Policy, vscode *rules.Target, servers map[string]parser.MCPServer) *rules.Target {
	roo := &rules.RooPolicy{
		SettingsFile: filepath.Join(dir, ".vscode", "settings.json"),
		IgnoreFile:   filepath.Join(dir, ".rooignore"),
		MCPFile:      filepath.Join(dir, ".roo", "mcp.json"),
		MCP:          servers,
	}
	if vscode != nil && vscode.VSCodeSettings != nil {
		roo.Allowed = rawStrings(vscode.VSCodeSettings, "roo-cline.allowedCommands")
		roo.Denied = rawStrings(vscode.VSCodeSettings, "roo-cline.deniedCommands")
	}
	if data, err := scanroot.ReadFile(roo.IgnoreFile); err == nil {
		roo.Ignore = string(data)
	}
	return &rules.Target{Scope: finding.ScopeProject, PolicyAgent: "roo-code", PolicyDeny: p.Deny, PolicyForbid: p.ForbidAllow.PolicyRules, PolicyRoo: roo}
}

func rawStrings(s *parser.VSCodeSettings, key string) []string {
	raw, ok := s.RawValue(key)
	if !ok {
		return nil
	}
	var out []string
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// geminiToolsOff returns the categories Gemini CLI has switched off. tools.exclude
// takes whole tools, and an entry with arguments is only a name that matches
// nothing; a tools.core list leaves out everything it does not name.
func geminiToolsOff(s *parser.GeminiSettings, deny config.PolicyRules) map[string]bool {
	excluded := s.ExcludedMCPServers()
	result := map[string]bool{"mcp-tools": len(deny.MCPTools) > 0 && (slices.Contains(excluded, "*") ||
		!slices.ContainsFunc(deny.MCPTools, func(v string) bool {
			server, _, _ := strings.Cut(v, ":")
			return !slices.Contains(excluded, server)
		}))}
	if s.Tools == nil {
		return result
	}
	off := func(tool string) bool {
		if slices.Contains(s.Tools.Exclude, tool) {
			return true
		}
		return len(s.Tools.Core) > 0 && !slices.ContainsFunc(s.Tools.Core, func(e string) bool {
			return e == tool || strings.HasPrefix(e, tool+"(")
		})
	}
	result["commands"] = off("run_shell_command")
	result["read"] = off("read_file") && off("read_many_files")
	result["write"] = off("write_file") && off("replace")
	result["fetch"] = off("web_fetch")
	return result
}

// piToolsOff returns the categories pi has switched off in .pi/settings.json.
// Plain names in defaultTools replace the defaults, and a list of only +name
// and -name entries changes them.
func piToolsOff(dir string) map[string]bool {
	enabled := map[string]bool{"read": true, "bash": true, "edit": true, "write": true}
	data, err := scanroot.ReadFile(filepath.Join(dir, ".pi", "settings.json"))
	var s struct {
		DefaultTools parser.ToolNames `json:"defaultTools"`
	}
	if err != nil || json.Unmarshal(data, &s) != nil || s.DefaultTools == nil {
		return nil
	}
	plain := slices.ContainsFunc(s.DefaultTools, func(e string) bool { return !strings.HasPrefix(e, "+") && !strings.HasPrefix(e, "-") })
	if plain {
		clear(enabled)
	}
	for _, e := range s.DefaultTools {
		if name, ok := strings.CutPrefix(e, "-"); ok {
			delete(enabled, name)
		} else {
			enabled[strings.TrimPrefix(e, "+")] = true
		}
	}
	return map[string]bool{
		"commands": !enabled["bash"] && !enabled["powershell"],
		"read":     !enabled["read"] && !enabled["grep"] && !enabled["find"],
		"write":    !enabled["edit"] && !enabled["write"],
	}
}

// remainingCategories are the deny categories a tool switch has not covered.
func remainingCategories(off map[string]bool) []string {
	var out []string
	for _, c := range []string{"commands", "read", "write", "fetch", "mcp-tools"} {
		if !off[c] {
			out = append(out, c)
		}
	}
	return out
}

// rooUnenforced are the categories Roo Code cannot carry: fetch, and read or
// write when an entry is outside the project, which .rooignore allows.
func rooUnenforced(deny config.PolicyRules) []string {
	out := []string{"fetch"}
	home := func(s string) bool { return strings.HasPrefix(s, "~/") }
	if slices.ContainsFunc(deny.Read, home) {
		out = append(out, "read")
	}
	if slices.ContainsFunc(deny.Write, home) {
		out = append(out, "write")
	}
	return out
}

// toolSwitchAgent is CFG118's entry for an agent that can only turn tools off,
// or none when every category is off.
func toolSwitchAgent(agent, name, path string, off map[string]bool, reason string) []rules.UnenforceableAgent {
	left := remainingCategories(off)
	if len(left) == 0 {
		return nil
	}
	return []rules.UnenforceableAgent{{Agent: agent, Name: name, Path: path, Categories: left, Reason: reason}}
}
