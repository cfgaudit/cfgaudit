// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg052 struct{}

var CFG052 = &cfg052{}

func init() { All = append(All, CFG052) }

func (r *cfg052) ID() string { return "CFG052" }

// Check reports an mcpServers block in a Claude Code settings.json, which has
// no effect (#1215). CFG052 used to report a server name declared both there
// and in .mcp.json as a shadowing conflict. Measured on Claude Code 2.1.316,
// `claude mcp list` and `claude mcp get` show a server from .mcp.json but not
// one defined only in .claude/settings.json, and the settings reference has
// no such key: there is no second source, so there is no conflict either.
// What is left is a block the developer probably expects to start a server.
//
// The other MCP rules still read the block: a secret committed in it is
// public whether or not Claude Code uses it.
func (r *cfg052) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || len(t.Settings.MCPServers) == 0 {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG052",
		Severity: finding.Info,
		File:     t.SettingsFile,
		Key:      "mcpServers",
		Message: "mcpServers in a Claude Code settings.json has no effect — Claude Code reads MCP servers from the project .mcp.json, from ~/.claude.json (claude mcp add) or from a plugin, not from settings.json; move the " +
			strconv.Itoa(len(t.Settings.MCPServers)) + " server(s) there or remove the block" + userScopeNote(t),
	}}
}
