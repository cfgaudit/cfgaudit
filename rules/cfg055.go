package rules

import (
	"encoding/json"
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

	markets := objectKeys(raw["extraKnownMarketplaces"])
	registered := make(map[string]bool, len(markets))
	for _, m := range markets {
		registered[m] = true
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
		if mkt != "" && registered[mkt] {
			add(finding.Error, "enabledPlugins auto-enables \""+entry+"\" from a marketplace this same settings file registers (extraKnownMarketplaces) — a committed file fully controls the supply chain and runs the plugin's hooks/commands/MCP for anyone who opens the repo. Remove it and let users opt in")
		} else {
			add(finding.Warn, "enabledPlugins auto-enables the plugin \""+entry+"\" — a committed file loads its hooks/commands/MCP on session start for anyone who opens the repo; let users enable plugins themselves")
		}
	}

	for _, m := range markets {
		add(finding.Warn, "extraKnownMarketplaces registers the plugin marketplace \""+m+"\" — a committed file points users at a marketplace source they did not choose; review it and pin the source to a fixed ref")
	}

	return findings
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
