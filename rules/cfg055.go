// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg055 struct{}

var CFG055 = &cfg055{}

func init() { All = append(All, CFG055) }

func (r *cfg055) ID() string { return "CFG055" }

// Check flags a committed settings.json that registers a plugin marketplace
// (extraKnownMarketplaces) or enables a plugin (enabledPlugins), the
// plugin-system analogue of CFG003. Scoped to project / project-local
// settings; a user's own ~/.claude/settings.json is their choice and is not
// flagged.
//
// Measured on Claude Code 2.1.316 (#1178), after accepting the trust dialog
// and nothing else: a marketplace the file registers is added and cloned
// without a prompt. A plugin from a local directory marketplace then loads
// in place and its SessionStart hook runs in that first session. A plugin
// from a git source, or from claude-plugins-official, is not installed: the
// /plugin Errors tab lists it and one Enter installs it.
func (r *cfg055) Check(t *Target) []finding.Finding {
	if t != nil && t.Devin != nil && t.Scope != finding.ScopeUser {
		return devinRequiredPluginFindings(t)
	}
	if t == nil || t.Settings == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	raw := t.Settings.Raw

	marketsRaw, marketsKey := t.Settings.Marketplaces()
	markets := objectKeys(marketsRaw)
	registered := make(map[string]bool, len(markets))
	inRepo := make(map[string]bool, len(markets))
	sameOwner := make(map[string]bool, len(markets))
	owner := repoGitHubOwner(t.ProjectDir)
	for _, m := range markets {
		switch {
		case officialMarketplace(marketsRaw, m), anthropicMarketplace(marketsRaw, m):
		case inRepoMarketplace(marketsRaw, m):
			inRepo[m] = true
		case owner != "" && marketplaceOwner(marketsRaw, m) == owner:
			sameOwner[m] = true
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
			add(finding.Warn, "enabledPlugins enables \""+entry+"\" from a marketplace in a directory of this repository ("+marketsKey+"); Claude Code loads it in place once the folder is trusted, without an install prompt, and its hooks/commands/MCP run for everyone. The code is under the same review as this file, but let users opt in")
		case mkt != "" && sameOwner[mkt]:
			add(finding.Warn, "enabledPlugins enables \""+entry+"\" from a marketplace this file registers ("+marketsKey+") on the repository owner's own GitHub account ("+owner+"); Claude Code adds the marketplace without asking once the folder is trusted, and the plugin is one install away in /plugin. The publisher is the one that controls this repository; pin the source to a fixed ref and let users opt in")
		case mkt != "" && registered[mkt]:
			add(finding.Error, "enabledPlugins enables \""+entry+"\" from a marketplace this same settings file registers ("+marketsKey+") — a committed file controls both the source and the enable. Claude Code adds the marketplace without asking once the folder is trusted; a plugin from a local directory then runs at once, one from a git source is one install away in /plugin. Remove it and let users opt in")
		case mkt == "claude-plugins-official":
			add(finding.Info, "enabledPlugins enables \""+entry+"\" from Anthropic's official marketplace; Claude Code does not install it on this alone, each user installs it from /plugin. Partner plugins listed there are third-party code, so check that this one is meant for everyone")
		default:
			add(finding.Warn, "enabledPlugins enables the plugin \""+entry+"\" for everyone who trusts the repo; once installed, its hooks/commands/MCP run in every session here. Let users enable plugins themselves")
		}
	}

	for _, m := range markets {
		if officialMarketplace(marketsRaw, m) || inRepo[m] {
			continue
		}
		add(finding.Warn, marketsKey+" registers the plugin marketplace \""+m+"\" — Claude Code adds it without asking once the folder is trusted, a source users did not choose; review it and pin the source to a fixed ref")
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

// marketplaceGitURLOwnerRe takes the owner from a git URL on github.com.
var marketplaceGitURLOwnerRe = regexp.MustCompile(`(?i)^(?:https://|ssh://git@|git@)github\.com[/:]([A-Za-z0-9][A-Za-z0-9-]*)/`)

// marketplaceOwner returns the lower-cased GitHub owner of the marketplace's
// source, a github repo or a git URL on github.com, or "". CFG055 compares it
// with the owner of the scanned repository: an exact match is the publisher
// that controls this repository (#1178). A fork keeps the upstream owner in
// the source while its origin names the fork owner, so it does not match.
func marketplaceOwner(raw json.RawMessage, name string) string {
	src := marketplaceSource(raw, name)
	switch src.Source {
	case "github":
		if o, _, ok := strings.Cut(src.Repo, "/"); ok {
			return strings.ToLower(o)
		}
	case "git":
		if m := marketplaceGitURLOwnerRe.FindStringSubmatch(src.URL); m != nil {
			return strings.ToLower(m[1])
		}
	}
	return ""
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

// devinRequiredPluginFindings reports the repo level's requiredPlugins in a
// committed .devin/config.json (#1603). Measured on Devin CLI 3000.12.32 with
// no account: `devin doctor` in the repository recorded the requirement,
// installed the plugin and activated it, skills and hooks included, with no
// login and no prompt, and it stayed installed (inactive) outside the
// repository. A local path that is absolute or starts with ~ loads whatever
// sits there on the reader's machine, so it is an error.
func devinRequiredPluginFindings(t *Target) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Devin.RequiredPluginSources() {
		if p.Ref == "" {
			continue
		}
		sev := finding.Warn
		what := "the plugin \"" + p.Ref + "\""
		if p.Kind == "local" {
			what = "the local plugin folder \"" + p.Ref + "\""
			if parser.ManifestPathEscapes(p.Ref) {
				sev = finding.Error
				what += ", outside the repository, so what loads depends on the reader's machine"
			}
		}
		out = append(out, finding.Finding{
			RuleID:   "CFG055",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.DevinFile,
			Key:      "requiredPlugins",
			Message:  ".devin/config.json requiredPlugins installs " + what + ": Devin installs and activates a required plugin, with its skills, hooks and MCP servers, for anyone who runs it in this repository, with no prompt, and keeps it installed afterwards. Remove the entry, or move it to optionalPlugins, which Devin does not install",
		})
	}
	return out
}
