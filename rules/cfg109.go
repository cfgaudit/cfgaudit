// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg109 struct{}

var CFG109 = &cfg109{}

func init() { All = append(All, CFG109) }

func (r *cfg109) ID() string { return "CFG109" }

// Check reports a committed agent config file cfgaudit could not parse.
//
// The finding exists because the alternative is worse. Before it, a single
// unparseable config ended the whole scan with exit 2 and printed one line to
// stderr, so every finding in every other file of that repository disappeared:
// a project whose .codex/config.toml does not parse was reported clean while its
// settings.json carried defaultMode: bypassPermissions and a redirected
// ANTHROPIC_BASE_URL.
//
// The agents do not treat it that way either. Codex 0.156.1, handed a
// .codex/config.toml whose [permissions] table holds a non-profile value, logs
// "Invalid configuration; using defaults" and runs. Claude Code 2.1.282, handed
// a .claude/settings.json that is not valid JSON, starts the session and applies
// the settings it can still read. A file that cannot be parsed is a layer that
// does not load, not a reason to stop.
//
// So the file is reported for what can be said about it with certainty: it is
// committed, it does not parse, the settings it declares are not in force, and
// no rule that would otherwise read that surface ran. Error severity, because
// the scan of that surface is incomplete and the repository's stated
// configuration is not the one anyone gets.
func (r *cfg109) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	findings := skippedMCPServers(t)
	if t.UnreadableFile == "" {
		return findings
	}
	msg := "cfgaudit could not parse this committed config file, so no rule for its surface ran and the settings it declares are not in force for the agent either" +
		" — agents skip a config layer they cannot read (Codex logs \"Invalid configuration; using defaults\" and runs; Claude Code starts the session without the file)." +
		" Fix the file or remove it, so that what the repository declares is what its readers get"
	if t.UnreadableReason != "" {
		msg += ". The parser reported: " + t.UnreadableReason
	}
	return append(findings, finding.Finding{
		RuleID:   "CFG109",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     t.UnreadableFile,
		Message:  msg,
	})
}

// skippedMCPServers reports each server of a .mcp.json that Claude Code
// skips because an env value is not a string (#1189). Measured on Claude Code
// 2.1.316: `claude mcp list` warns "Skipped — invalid MCP server config for
// \"x\": env.MAX_TOKENS: expected string, received number" (also for a bool
// and null), and the other servers in the file load. cfgaudit still reads the
// server, so the other rules check it; this says it is not in force for
// Claude Code. Info: one server of a readable file, not a file that is lost.
func skippedMCPServers(t *Target) []finding.Finding {
	if filepath.Base(t.ProjectMCPFile) != ".mcp.json" {
		return nil
	}
	names := make([]string, 0, len(t.ProjectMCP))
	for name, s := range t.ProjectMCP {
		if len(s.NonStringEnv) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var out []finding.Finding
	for _, name := range names {
		keys := t.ProjectMCP[name].NonStringEnv
		out = append(out, finding.Finding{
			RuleID:   "CFG109",
			Severity: finding.Info,
			Scope:    t.Scope,
			File:     t.ProjectMCPFile,
			Key:      "mcpServers." + name + ".env",
			Message: "mcpServers." + name + ".env sets " + strings.Join(keys, ", ") + " to a value that is not a string, so Claude Code skips this server (\"invalid MCP server config ... expected string\") and loads the others." +
				" Quote the value (\"64000\") so the server starts; cfgaudit still checks it",
		})
	}
	return out
}
