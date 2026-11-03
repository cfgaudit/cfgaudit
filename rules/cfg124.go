// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg124 struct{}

var CFG124 = &cfg124{}

func init() { All = append(All, CFG124) }

func (r *cfg124) ID() string { return "CFG124" }

func (r *cfg124) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		mode, ok := fullAgentMCP(ref.Server.Command, ref.Server.Args)
		if !ok {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID: "CFG124", Severity: finding.Warn, File: ref.File,
			Message: "mcpServers." + ref.Name + " launches " + mode + " as a full agent server; MCP clients can delegate to an agent with its own tools and approval model. Use a purpose-built MCP server instead",
		})
	}
	return findings
}

func fullAgentMCP(command string, args []string) (string, bool) {
	inv, ok := agentInvocationExec(command, args)
	if !ok {
		return "", false
	}
	lower := make([]string, len(inv.args))
	for i, arg := range inv.args {
		lower[i] = strings.ToLower(strings.Trim(arg, "'\"()[]{};,"))
	}
	switch inv.agent {
	case "codex":
		args := agentSubcommandArgs(lower, map[string]bool{"-c": true, "--config": true, "-a": true, "--ask-for-approval": true, "-s": true, "--sandbox": true})
		if len(args) > 0 && (args[0] == "app-server" || args[0] == "mcp-server") {
			return "codex " + args[0], true
		}
	case "claude":
		args := agentSubcommandArgs(lower, map[string]bool{"--permission-mode": true, "--model": true, "--add-dir": true})
		if len(args) > 1 && args[0] == "mcp" && args[1] == "serve" {
			return "claude mcp serve", true
		}
	}
	return "", false
}

func agentSubcommandArgs(args []string, takesValue map[string]bool) []string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return args[i+1:]
		}
		if !strings.HasPrefix(arg, "-") {
			return args[i:]
		}
		if !strings.Contains(arg, "=") && takesValue[arg] {
			i++
		}
	}
	return nil
}
