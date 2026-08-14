package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg100 struct{}

var CFG100 = &cfg100{}

func init() { All = append(All, CFG100) }

func (r *cfg100) ID() string { return "CFG100" }

// Check flags a committed xAI Grok CLI .grok/config.toml whose [plugins] table
// turns plugins on or widens where they are loaded from. Enabling a plugin loads
// third-party code — its hooks, commands and MCP servers — so a committed enable
// makes that decision for every contributor. This is CFG055's threat model
// reached through Grok's file, and CFG089 covers the same shape for Copilot.
//
// The direction comes from Grok's own documentation of the field: `enabled` is
// "explicitly enable plugins (useful when project plugins default off)". Project
// plugins default to OFF, so a committed entry is the thing that switches them
// on rather than a restatement of the default.
//
// # Why this is reported at all, given folder trust
//
// #385 established that hooks, MCP servers, LSP servers and plugins from a
// cloned repository are all gated by Grok's folder trust. That is a real
// mitigant and it is why every finding here is warn rather than error.
//
// It is not a reason for silence, and #473 is right that the answer has to be
// the same for the whole file rather than decided per table. cfgaudit already
// reports [mcp_servers] from this exact file under the same gate. Trust is one
// prompt covering everything the repository declares, granted to get any
// functionality at all; it is not consent to a specific plugin. So both tables
// are reported, both at the severity that mitigant earns.
//
// [permission] stays declined for a different reason that folder trust has
// nothing to do with: its rules merge deny > ask > allow so a user's deny always
// beats a repository's allow, and matching is segmented (#385).
//
// `disabled` is never reported. Naming a plugin to discover but not activate is
// hardening, the direction that made Codex's exclude_slash_tmp and Cursor's
// disableTmpWrite false positives, and a real committed config uses it that way.
func (r *cfg100) Check(t *Target) []finding.Finding {
	if t == nil || t.Grok == nil || t.Grok.Plugins == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	p := t.Grok.Plugins
	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG100",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.GrokFile,
			Message:  msg + userScopeNote(t),
		})
	}

	inside, outside := p.PluginPathsInsideRepo()
	enabled := trimmedNonEmpty(p.Enabled)

	if len(inside) > 0 {
		detail := ""
		if len(enabled) > 0 {
			detail = " and [plugins] enabled activates " + quoteList(enabled) +
				", so this file both ships the plugin code and switches it on"
		}
		add("Grok [plugins] paths scans " + quoteList(inside) +
			" for plugins, a directory inside the repository" + detail +
			". Whoever can change the repository changes what runs for every contributor. Remove the entry, or have users install the plugin themselves")
	}
	if len(outside) > 0 {
		add("Grok [plugins] paths adds the plugin search directory " + quoteList(outside) +
			" — a committed file points the loader at code outside the repository that contributors did not choose. Confirm it is a location you control")
	}
	// Reported on its own only when no path finding already covers it, so a file
	// doing both gets one finding that says both rather than two overlapping ones.
	if len(enabled) > 0 && len(inside) == 0 {
		add("Grok [plugins] enabled activates " + quoteList(enabled) +
			" — project plugins default to off, so a committed entry loads that plugin's hooks, commands and MCP servers for everyone who opens the repo. Let users enable plugins themselves")
	}
	return findings
}

// trimmedNonEmpty returns the non-blank entries of a list, trimmed, preserving
// order so a finding lists them the way the file does.
func trimmedNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
