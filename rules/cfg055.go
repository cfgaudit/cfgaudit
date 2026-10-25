// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg055 struct{}

var CFG055 = &cfg055{}

func init() { All = append(All, CFG055) }

func (r *cfg055) ID() string { return "CFG055" }

// Check flags a committed settings.json that registers a plugin marketplace
// (extraKnownMarketplaces) or auto-enables a plugin (enabledPlugins). Enabling a
// plugin loads its hooks, slash commands, and MCP servers on session start, so a
// repo-committed enable runs third-party code for everyone who opens it — the
// plugin-system analogue of CFG003. Scoped to project / project-local settings;
// a user's own ~/.claude/settings.json is their choice and is not flagged.
func (r *cfg055) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	raw := t.Settings.Raw

	marketsRaw, marketsKey := t.Settings.Marketplaces()
	markets := objectKeys(marketsRaw)
	registered := make(map[string]bool, len(markets))
	inRepo := make(map[string]bool, len(markets))
	for _, m := range markets {
		switch {
		case officialMarketplace(marketsRaw, m), anthropicMarketplace(marketsRaw, m):
		case inRepoMarketplace(marketsRaw, m):
			inRepo[m] = true
		default:
			registered[m] = true
		}
	}

	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG055", Severity: sev, File: t.SettingsFile, Message: msg + userScopeNote(t)})
	}

	for _, entry := range enabledPluginEntries(raw["enabledPlugins"]) {
		mkt := ""
		if i := strings.LastIndex(entry, "@"); i >= 0 {
			mkt = entry[i+1:]
		}
		switch {
		case mkt != "" && inRepo[mkt]:
			add(finding.Warn, "enabledPlugins auto-enables \""+entry+"\" from a marketplace in a directory of this repository ("+marketsKey+"); its hooks/commands/MCP run on session start for anyone who opens the repo. The code is under the same review as this file, but let users opt in")
		case mkt != "" && registered[mkt]:
			add(finding.Error, "enabledPlugins auto-enables \""+entry+"\" from a marketplace this same settings file registers ("+marketsKey+") — a committed file fully controls the supply chain and runs the plugin's hooks/commands/MCP for anyone who opens the repo. Remove it and let users opt in")
		default:
			add(finding.Warn, "enabledPlugins auto-enables the plugin \""+entry+"\" — a committed file loads its hooks/commands/MCP on session start for anyone who opens the repo; let users enable plugins themselves")
		}
	}

	for _, m := range markets {
		if officialMarketplace(marketsRaw, m) {
			continue
		}
		add(finding.Warn, marketsKey+" registers the plugin marketplace \""+m+"\" — a committed file points users at a marketplace source they did not choose; review it and pin the source to a fixed ref")
	}

	return findings
}

// officialMarketplace reports whether the marketplace name is Anthropic's
// official one registered with its own source, github
// anthropics/claude-plugins-official. Claude Code knows that marketplace
// already, so the entry hands nobody a source they did not choose, and a
// plugin enabled from it is a plain enable, not one from a marketplace the
// file controls (#872).
func officialMarketplace(raw json.RawMessage, name string) bool {
	if name != "claude-plugins-official" {
		return false
	}
	src := marketplaceSource(raw, name)
	return src.Source == "github" && strings.EqualFold(src.Repo, "anthropics/claude-plugins-official")
}

// marketplaceSourceSpec is the source object of one extraKnownMarketplaces
// entry.
type marketplaceSourceSpec struct {
	Source string `json:"source"`
	Repo   string `json:"repo"`
	URL    string `json:"url"`
	Path   string `json:"path"`
}

// marketplaceSource returns the source of the marketplace name in raw, or the
// zero value.
func marketplaceSource(raw json.RawMessage, name string) marketplaceSourceSpec {
	var m map[string]struct {
		Source marketplaceSourceSpec `json:"source"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return marketplaceSourceSpec{}
	}
	return m[name].Source
}

// anthropicGitURLRe is a git URL of a repository in the anthropics
// organisation on github.com.
var anthropicGitURLRe = regexp.MustCompile(`(?i)^(?:https://|ssh://git@|git@)github\.com[/:]anthropics/[\w.\-]+(?:\.git)?/?(?:#.*)?$`)

// anthropicMarketplace reports whether the marketplace's source is a
// repository in Anthropic's own GitHub organisation, under whatever name it
// is registered: "claude-code-plugins" from anthropics/claude-code,
// "anthropic-agent-skills" from anthropics/skills. The source pins the
// publisher, so a plugin enabled from it is a plain enable, as for the
// official marketplace (#893).
func anthropicMarketplace(raw json.RawMessage, name string) bool {
	src := marketplaceSource(raw, name)
	switch src.Source {
	case "github":
		owner, _, ok := strings.Cut(src.Repo, "/")
		return ok && strings.EqualFold(owner, "anthropics")
	case "git":
		return anthropicGitURLRe.MatchString(src.URL)
	}
	return false
}

// inRepoMarketplace reports whether the marketplace is a directory or file
// inside the repository ("./.agents"): its plugins are code under the same
// review as the settings file. An absolute path, a home path or one that
// climbs out with ".." is not (#893).
func inRepoMarketplace(raw json.RawMessage, name string) bool {
	src := marketplaceSource(raw, name)
	if src.Source != "directory" && src.Source != "file" {
		return false
	}
	p := strings.ReplaceAll(strings.TrimSpace(src.Path), `\`, "/")
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "$") || (len(p) > 1 && p[1] == ':') {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// objectKeys returns the sorted keys of a JSON object value, or nil.
func objectKeys(b json.RawMessage) []string {
	if len(b) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// enabledPluginEntries returns the sorted plugin-id@marketplace keys of
// enabledPlugins whose value is "enabled" (boolean true or a non-empty array).
func enabledPluginEntries(b json.RawMessage) []string {
	if len(b) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	var out []string
	for k, v := range m {
		if pluginEnabled(v) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func pluginEnabled(v json.RawMessage) bool {
	var b bool
	if err := json.Unmarshal(v, &b); err == nil {
		return b
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(v, &arr); err == nil {
		return len(arr) > 0
	}
	return false
}
