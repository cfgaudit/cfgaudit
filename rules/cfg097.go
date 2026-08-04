package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg097 struct{}

var CFG097 = &cfg097{}

func init() { All = append(All, CFG097) }

func (r *cfg097) ID() string { return "CFG097" }

// Check flags a committed Gemini CLI *remote* agent definition that points the
// CLI at another agent over cleartext, or hands it a credential in the file.
//
// A `.gemini/agents/*.md` whose frontmatter carries `agent_card_url`,
// `agent_card_json` or `auth` is a remote agent (agentLoader.ts,
// guessIntendedKind). The CLI fetches the A2A agent card at that URL and then
// talks to whatever it describes, with the credentials the same file supplies.
// Gemini's docs call these files project-level and team-shared, so both
// decisions are made for everyone who opens the repo.
//
// Two findings, both error:
//
//   - a `http://` card URL to a non-loopback host. The card, the conversation
//     with the agent it describes, and any auth header travel in the clear. This
//     is CFG049's threat model on the field that is not an MCP server.
//   - an `auth` value that is a literal rather than a reference. The docs use
//     `$VAR` throughout, but the schema is plain strings, so a committed
//     credential is accepted. Reuses the same literal test as CFG065, so `$VAR`
//     references and obvious placeholders are not reported.
//
// A https:// card URL on its own is not a finding. Pointing at a remote agent is
// what the file is for; only the cleartext and the credential are.
func (r *cfg097) Check(t *Target) []finding.Finding {
	if t == nil || t.GeminiRemote == nil {
		return nil
	}
	remote := t.GeminiRemote
	var findings []finding.Finding
	add := func(msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG097",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.InstructionFile,
			Message:  msg + userScopeNote(t),
		})
	}

	if url := remote.CardURL; url != "" && isCleartextRemoteURL(url) {
		add("Gemini remote agent agent_card_url is \"" + url + "\" — a non-loopback host over cleartext http://, so the agent card, everything the CLI then exchanges with the agent it describes, and any auth header travel unencrypted. Use https://, or a loopback address for a local agent")
	}

	if len(remote.AuthSecrets) > 0 {
		fields := make([]string, 0, len(remote.AuthSecrets))
		for field, value := range remote.AuthSecrets {
			if isInlineSecretLiteral(value) {
				fields = append(fields, field)
			}
		}
		sort.Strings(fields)
		if len(fields) > 0 {
			add("Gemini remote agent auth." + strings.Join(fields, ", auth.") +
				" contains a hardcoded credential literal — a committed secret exposed to anyone with repo access, sent to the remote agent this file names. Reference it instead, e.g. token: $MY_TOKEN")
		}
	}
	return findings
}

// isCleartextRemoteURL reports whether a URL reaches a non-loopback host over
// plain http. Loopback is silent: a card served by a local process is not an
// exposure. Reuses the loopback test the proxy and hook rules already share.
func isCleartextRemoteURL(raw string) bool {
	u := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(u), "http://") {
		return false
	}
	return !proxyTargetsLoopback(u)
}
