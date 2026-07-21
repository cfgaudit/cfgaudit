package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg089 struct{}

var CFG089 = &cfg089{}

func init() { All = append(All, CFG089) }

func (r *cfg089) ID() string { return "CFG089" }

// Check flags a repository-level Copilot `.github/copilot/settings.json` that
// registers a plugin marketplace or auto-enables a plugin. Installing a plugin
// loads third-party code — its hooks, commands and MCP servers — on session
// start, so a repo-level enable makes that decision for every contributor. This
// is CFG055's threat model reached through Copilot's file instead of Claude's,
// and the key names are identical.
//
// **Severity is warn throughout**, one step below CFG055's escalation. Copilot's
// docs describe this file as repository-level and read by both the CLI and the
// cloud agent, but never say it is meant to be committed the way Cursor's hook
// docs do — the committability is inferred, and an inferred surface does not
// carry an error.
//
// A marketplace source is reported as **unpinned** when it names a remote origin
// with no immutable pin. Deliberately not phrased as "defaults to the default
// branch": `sha` is documented as a full-40-character pin *"immune to
// force-pushes or tag/branch moves"*, but what an omitted `ref` resolves to is
// undocumented, and asserting it would be a guess.
func (r *cfg089) Check(t *Target) []finding.Finding {
	if t == nil || t.CopilotSettings == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	cs := t.CopilotSettings

	registered := make(map[string]bool, len(cs.ExtraKnownMarketplaces))
	names := make([]string, 0, len(cs.ExtraKnownMarketplaces))
	for name := range cs.ExtraKnownMarketplaces {
		registered[name] = true
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG089",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.CopilotSettingsFile,
			Message:  msg + userScopeNote(t),
		})
	}

	plugins := make([]string, 0, len(cs.EnabledPlugins))
	for spec, enabled := range cs.EnabledPlugins {
		if enabled {
			plugins = append(plugins, spec)
		}
	}
	sort.Strings(plugins)
	for _, spec := range plugins {
		mkt := ""
		if i := strings.LastIndex(spec, "@"); i >= 0 {
			mkt = spec[i+1:]
		}
		detail := " — a repository-level file installs and loads a third-party plugin's hooks, commands and MCP servers on session start for everyone who opens the repo; let users enable plugins themselves"
		if mkt != "" && registered[mkt] {
			detail = " from a marketplace this same file registers (extraKnownMarketplaces)" + detail
		}
		add("enabledPlugins auto-enables \"" + spec + "\"" + detail)
	}

	for _, name := range names {
		src := cs.ExtraKnownMarketplaces[name].Source
		if !src.Remote() {
			continue // a "directory" source is on disk — no upstream trust edge
		}
		if marketplacePinned(src) {
			continue
		}
		add("extraKnownMarketplaces." + name + " registers a plugin marketplace from \"" + src.Location() +
			"\" with no immutable pin — neither a full-SHA `sha` nor a full-SHA `ref`, so whoever controls the upstream can change what is installed under every contributor. Pin the source to a full 40-character commit SHA")
	}

	return findings
}

// marketplacePinned reports whether a marketplace source is fixed to an
// immutable commit. Reuses CFG074's full-SHA matcher: a bare branch or tag name
// in `ref` moves under whoever controls it, so it does not pin.
func marketplacePinned(src parser.CopilotMarketplaceSource) bool {
	return fullCommitSHARe.MatchString(strings.TrimSpace(src.SHA)) ||
		fullCommitSHARe.MatchString(strings.TrimSpace(src.Ref))
}
