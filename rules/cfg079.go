package rules

import (
	"encoding/json"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg079 struct{}

var CFG079 = &cfg079{}

func init() { All = append(All, CFG079) }

func (r *cfg079) ID() string { return "CFG079" }

// autoModeConfig is the subset of the `autoMode` object cfgaudit inspects. Its
// allow / soft_deny / environment arrays tune the classifier that decides what
// runs without a prompt when permissions.defaultMode is "auto" — and each array
// REPLACES the corresponding built-in classifier section entirely unless the
// literal "$defaults" is spliced in as an entry.
type autoModeConfig struct {
	Allow    []string `json:"allow"`
	SoftDeny []string `json:"soft_deny"`
}

// No MinVersion: presence-based, like CFG004. The `autoMode` object is only
// honoured on a Claude Code version that supports it, and gating on the detected
// version could wrongly skip a stale weakening value.

// Check flags a committed `autoMode` object that weakens the auto-mode permission
// classifier: a broad `allow` entry (the classifier auto-approves unrestricted
// shell), or a `soft_deny` array that drops the built-in deny baseline by
// replacing it without re-splicing "$defaults". Under defaultMode:"auto" (CFG004)
// this silently widens what runs with no confirmation.
func (r *cfg079) Check(t *Target) []finding.Finding {
	if t.Settings == nil {
		return nil
	}
	raw, ok := t.Settings.Raw["autoMode"]
	if !ok {
		return nil
	}
	var am autoModeConfig
	if err := json.Unmarshal(raw, &am); err != nil {
		return nil // a mistyped autoMode is reported by CFG012, not here
	}

	var findings []finding.Finding
	for _, entry := range am.Allow {
		if isBroadAutoModeAllow(entry) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG079",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  "autoMode.allow contains \"" + strings.TrimSpace(entry) + "\" — the auto-mode classifier auto-approves unrestricted shell; under defaultMode: \"auto\" this runs commands with no confirmation. Scope the classifier allow rules to specific commands" + userScopeNote(t),
			})
			break // one finding is enough; the whole allow section is broad
		}
	}
	// A soft_deny section that is present but omits "$defaults" replaces the
	// built-in deny baseline entirely — the classifier loses its default guards.
	if _, present := rawHasKey(raw, "soft_deny"); present && !containsDefaults(am.SoftDeny) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG079",
			Severity: finding.Warn,
			File:     t.SettingsFile,
			Message:  "autoMode.soft_deny replaces the built-in auto-mode deny rules without including \"$defaults\" — the classifier's safety baseline is dropped, so more actions auto-approve under defaultMode: \"auto\". Add \"$defaults\" to keep the built-in deny rules" + userScopeNote(t),
		})
	}
	return findings
}

// isBroadAutoModeAllow reports whether an autoMode.allow entry grants the
// classifier unrestricted execution: a bare `*`/`**` (auto-approve everything)
// or an unrestricted shell grant (Bash / Bash(*) / PowerShell(*)).
func isBroadAutoModeAllow(entry string) bool {
	e := strings.TrimSpace(entry)
	if e == "*" || e == "**" {
		return true
	}
	return unrestrictedBashRe.MatchString(e)
}

func containsDefaults(entries []string) bool {
	for _, e := range entries {
		if strings.TrimSpace(e) == "$defaults" {
			return true
		}
	}
	return false
}

// rawHasKey reports whether a JSON object contains the given key (distinguishing
// an absent key from a present key with an empty array — an explicit empty
// soft_deny still replaces the built-in defaults).
func rawHasKey(obj json.RawMessage, key string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil {
		return nil, false
	}
	v, ok := m[key]
	return v, ok
}
