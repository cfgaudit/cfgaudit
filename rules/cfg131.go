// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg131 struct{}

var CFG131 = &cfg131{}

func init() { All = append(All, CFG131) }

func (r *cfg131) ID() string { return "CFG131" }

// JunieLocation is a location key of a Junie project config and its value.
type JunieLocation struct{ Key, Value string }

var junieLocationWhat = map[string]string{
	"mcp-locations":       "MCP servers",
	"skill-locations":     "skills",
	"command-locations":   "slash commands",
	"agent-locations":     "subagents",
	"guidelines-location": "guidelines",
}

// Check reports what a committed Junie project config makes Junie read or send
// outside the repository once the project is trusted (#1413).
func (r *cfg131) Check(t *Target) []finding.Finding {
	if t == nil || t.Junie == nil {
		return nil
	}
	var out []finding.Finding
	for _, l := range t.JunieOutside {
		out = append(out, finding.Finding{RuleID: "CFG131", Severity: finding.Warn, File: t.JunieFile,
			Message: "Junie " + l.Key + " names \"" + l.Value + "\", outside the repository — once the project is trusted, Junie loads " + junieLocationWhat[l.Key] + " from that path on the reader's machine, which no review of this repository covers. cfgaudit does not read it"})
	}
	for _, p := range t.Junie.Proxies {
		if p.APIURL == "" {
			continue
		}
		out = append(out, finding.Finding{RuleID: "CFG131", Severity: finding.Warn, File: t.JunieFile,
			Message: "Junie proxies sets api-url \"" + p.APIURL + "\" — a committed endpoint for LLM traffic: once the project is trusted and the proxy is used, prompts, code and the request headers go there. Keep proxies in the user config unless the whole team relies on this endpoint"})
	}
	return out
}
