package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// commandSite is one location that holds a shell command string Claude Code (or
// another agent) executes. The content rules (CFG008/009/014/015/…) inspect every
// site uniformly: hooks are not the only place a repo-controlled config can
// smuggle a command — credential helpers (apiKeyHelper, awsCredentialExport, …),
// the status line, OTEL headers, file-suggestion scripts (CVE-2025-59536 attack
// class), and each MCP server's headersHelper all run a shell command too.
type commandSite struct {
	// Label is the finding-friendly origin of the command, already phrased as a
	// noun ending in "command" (e.g. "hooks.SessionStart command", "apiKeyHelper
	// command") so rules can append their verb directly.
	Label string
	// File is the config file the command was declared in, so a finding is
	// attributed correctly (settings.json vs an MCP config such as .mcp.json).
	File    string
	Command string
}

// commandSites returns every non-empty command-bearing site in the target, in a
// stable order: settings.json hooks (by event name), then its credential/runtime
// helpers, then each MCP server's headersHelper (attributed to the MCP source
// file). Returns nil for a nil target.
func commandSites(t *Target) []commandSite {
	if t == nil {
		return nil
	}
	var sites []commandSite

	if s := t.Settings; s != nil {
		events := make([]string, 0, len(s.Hooks))
		for e := range s.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range s.Hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "hooks." + event + " command", File: t.SettingsFile, Command: h.Command})
					}
				}
			}
		}

		add := func(label, cmd string) {
			if cmd != "" {
				sites = append(sites, commandSite{Label: label + " command", File: t.SettingsFile, Command: cmd})
			}
		}
		add("apiKeyHelper", s.StringField("apiKeyHelper"))
		add("awsCredentialExport", s.StringField("awsCredentialExport"))
		add("awsAuthRefresh", s.StringField("awsAuthRefresh"))
		add("gcpAuthRefresh", s.StringField("gcpAuthRefresh"))
		add("otelHeadersHelper", s.StringField("otelHeadersHelper"))
		add("statusLine", s.CommandHelperField("statusLine"))
		add("fileSuggestion", s.CommandHelperField("fileSuggestion"))
	}

	for _, ref := range t.mcpServerRefs() {
		if cmd := ref.Server.HeadersHelper; cmd != "" {
			sites = append(sites, commandSite{Label: "mcpServers." + ref.Name + ".headersHelper command", File: ref.File, Command: cmd})
		}
	}

	// OpenAI Codex config.toml `notify` — a program (argv) Codex spawns on events.
	if t.Codex != nil && len(t.Codex.Notify) > 0 {
		sites = append(sites, commandSite{Label: "Codex notify command", File: t.CodexFile, Command: strings.Join(t.Codex.Notify, " ")})
	}

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
