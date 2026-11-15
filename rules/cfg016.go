// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg016 struct{}

var CFG016 = &cfg016{}

func init() { All = append(All, CFG016) }

func (r *cfg016) ID() string { return "CFG016" }

// Check flags the presence of a credential-helper command in a project-scoped
// settings file. apiKeyHelper / awsCredentialExport / awsAuthRefresh /
// gcpAuthRefresh each run a shell command whose output becomes authentication
// material; a cloned repository that ships one both executes code on startup
// (covered for content by CFG008/014/015) and can hand back attacker-controlled
// credentials. These helpers belong in user-global or managed settings, never in
// a repo. Presence is flagged regardless of how benign the command looks.
//
// At project / project-local scope this is an error. At user scope it is the
// expected, documented location, so the finding is informational only.
func (r *cfg016) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	helpers := credentialHelpers(t.Settings)
	if len(helpers) == 0 {
		return nil
	}

	var findings []finding.Finding
	for _, h := range helpers {
		if h.Key == "proxyAuthHelper" && t.Scope != finding.ScopeUser {
			findings = append(findings, proxyAuthHelperFinding(t))
			continue
		}
		if t.Scope == finding.ScopeUser {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG016",
				Severity: finding.Info,
				File:     t.SettingsFile,
				Message:  h.Key + " runs a shell command to produce credentials — expected at user scope; confirm the command and its source are trusted",
			})
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG016",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message:  h.Key + " defines a credential helper in project-scoped settings — a cloned repository must never ship the command that mints your credentials; it runs on startup (RCE) and its output is sent as your auth token. Move it to user-global (~/.claude/settings.json) or managed settings",
		})
	}
	return findings
}

// proxyAuthEnableVar turns proxyAuthHelper on; without it Claude Code does not
// read the helper at all (2.1.321 to 2.1.325).
const proxyAuthEnableVar = "CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER"

// proxyAuthHelperFinding judges a proxyAuthHelper in project settings (#1765).
// Measured on Claude Code 2.1.325: the same file's env can set the enabling
// variable, and the helper then runs once the folder is trusted. Without it the
// helper runs only for a user who set the variable, which is warn.
func proxyAuthHelperFinding(t *Target) finding.Finding {
	const what = "proxyAuthHelper defines a shell command whose output Claude Code sends as the Proxy-Authorization header, from project settings once the folder is trusted"
	if v, ok := t.Settings.Env[proxyAuthEnableVar]; ok && truthyEnv(v) {
		return finding.Finding{RuleID: "CFG016", Severity: finding.Error, File: t.SettingsFile,
			Message: what + ", and the same file's env sets " + proxyAuthEnableVar + ", so a cloned repository turns the helper on by itself. It runs on startup (RCE) and sees the proxy's credential challenge. Move it to user-global (~/.claude/settings.json) or managed settings"}
	}
	return finding.Finding{RuleID: "CFG016", Severity: finding.Warn, File: t.SettingsFile,
		Message: what + ". It runs only for a user who set " + proxyAuthEnableVar + " (an early-access switch), and then on startup with the proxy's credential challenge. Move it to user-global (~/.claude/settings.json) or managed settings"}
}

// truthyEnv reports an env value that switches something on: set, and not
// "0", "false", "no" or "off".
func truthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
