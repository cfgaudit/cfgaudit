package rules

import (
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// commandSite is one location in settings.json that holds a shell command string
// Claude Code executes. The content rules (CFG008/009/014/015) inspect every site
// uniformly: hooks are not the only place a repo-controlled settings file can
// smuggle a command — credential helpers (apiKeyHelper, awsCredentialExport, …),
// the status line, OTEL headers, and file-suggestion scripts all run a shell
// command too (CVE-2025-59536 attack class).
type commandSite struct {
	// Label is the finding-friendly origin of the command, already phrased as a
	// noun ending in "command" (e.g. "hooks.SessionStart command", "apiKeyHelper
	// command") so rules can append their verb directly.
	Label   string
	Command string
}

// commandSites returns every non-empty command-bearing site in s, in a stable
// order: hooks first (by event name), then the credential/runtime helpers in a
// fixed order. Returns nil for nil settings.
func commandSites(s *parser.Settings) []commandSite {
	if s == nil {
		return nil
	}
	var sites []commandSite

	events := make([]string, 0, len(s.Hooks))
	for e := range s.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, group := range s.Hooks[event] {
			for _, h := range group.Hooks {
				if h.Command != "" {
					sites = append(sites, commandSite{Label: "hooks." + event + " command", Command: h.Command})
				}
			}
		}
	}

	add := func(label, cmd string) {
		if cmd != "" {
			sites = append(sites, commandSite{Label: label + " command", Command: cmd})
		}
	}
	add("apiKeyHelper", s.StringField("apiKeyHelper"))
	add("awsCredentialExport", s.StringField("awsCredentialExport"))
	add("awsAuthRefresh", s.StringField("awsAuthRefresh"))
	add("gcpAuthRefresh", s.StringField("gcpAuthRefresh"))
	add("otelHeadersHelper", s.StringField("otelHeadersHelper"))
	add("statusLine", s.CommandHelperField("statusLine"))
	add("fileSuggestion", s.CommandHelperField("fileSuggestion"))

	return sites
}

// credentialHelper names a settings key whose command exists to mint or refresh
// authentication material. Its mere presence in a project-scoped settings file is
// suspicious regardless of content (CFG016): a cloned repo should never ship the
// script that produces your credentials.
type credentialHelper struct {
	Key     string
	Command string
}

// credentialHelpers returns the credential-helper keys present (non-empty) in s,
// in a fixed order.
func credentialHelpers(s *parser.Settings) []credentialHelper {
	if s == nil {
		return nil
	}
	var out []credentialHelper
	add := func(key, cmd string) {
		if cmd != "" {
			out = append(out, credentialHelper{Key: key, Command: cmd})
		}
	}
	add("apiKeyHelper", s.StringField("apiKeyHelper"))
	add("awsCredentialExport", s.StringField("awsCredentialExport"))
	add("awsAuthRefresh", s.StringField("awsAuthRefresh"))
	add("gcpAuthRefresh", s.StringField("gcpAuthRefresh"))
	return out
}
