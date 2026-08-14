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
// Committability is no longer inferred. The CLI configuration reference states
// it: repository settings "are committed to the repository and shared with
// collaborators", and its repository-level table gives both keys as
// "Merged — repository overrides user for same key". So a committed entry does
// not merely add to a teammate's configuration, it wins over their own value for
// the same key.
//
// **Severity stays warn throughout** even so, and the reason has changed from an
// inference to a measurement. #471 asked whether the enabledPlugins-from-a-
// self-registered-marketplace case should now escalate to error the way CFG055
// does, since the old justification for warn was the inference. It should not:
// across 97 real .github/copilot/settings.json files, 33 (34%) carry that exact
// pairing, and they include dotnet/runtime, dotnet/roslyn, dotnet/aspnetcore and
// microsoft/testfx registering their own marketplace and enabling their own
// plugins. Registering the marketplace you publish is how a repository ships a
// first-party plugin, not a footgun, and an error on a third of the population
// would teach people to skip the rule. CFG055's escalation rests on a population
// this one does not share.
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
		detail := " — a repository-level file installs and loads a third-party plugin's hooks, commands and MCP servers on session start for everyone who opens the repo, and the documented merge behaviour is \"repository overrides user for same key\", so it wins over a contributor's own setting rather than adding to it; let users enable plugins themselves"
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
