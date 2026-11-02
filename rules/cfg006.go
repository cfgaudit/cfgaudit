// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg006 struct{}

var CFG006 = &cfg006{}

func init() { All = append(All, CFG006) }

func (r *cfg006) ID() string { return "CFG006" }

// MinVersion returns the lowest Claude Code release where permissions.deny is
// honoured. Unlike the presence-based rules, CFG006 is absence-based — it fires
// when the deny guardrail is *missing*, which is only meaningful on a version
// that supports deny. That makes version-gating the correct tool here (it would
// suppress a misleading "deny absent" finding on a pre-deny release). The deny
// list is foundational and present in every observed release, so in practice the
// gate is a no-op; it is declared because the gate is semantically right, not for
// uniformity.
func (r *cfg006) MinVersion() string { return "0.2.21" }

func (r *cfg006) Check(t *Target) []finding.Finding {
	if t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	if len(t.effectiveDeny()) > 0 {
		return nil
	}
	// A settings.local.json need not repeat the project deny list: Claude Code
	// merges it with the sibling settings.json, whose deny rules still apply.
	if t.SiblingDeny {
		return nil
	}
	// A committed settings.local.json is a history of "always allow" answers;
	// a shared deny list belongs in settings.json, and CFG013 reports the
	// committed file itself (#1193).
	// A file Claude Code discards keeps its finding: its deny list is on paper
	// only, which CFG006 owns (see CFG012).
	if !t.discarded() {
		if t.Scope == finding.ScopeProjectLocal {
			return nil
		}
		// Without a whole-tool grant or a permissive mode, everything the
		// allow list does not name still prompts, so a missing deny list
		// changes nothing (#1193: 341 of 405 corpus findings were of that
		// kind).
		if !broadGrant(t.Settings.Permissions.Allow) && !permissiveDenyMode(t.Settings.Permissions.DefaultMode) {
			return nil
		}
	}
	return []finding.Finding{{
		RuleID:   "CFG006",
		Severity: finding.Warn,
		File:     t.SettingsFile,
		Message: "permissions.deny is absent or empty — no guardrails block destructive operations (rm -rf, git push --force, etc.); add explicit denylist entries" +
			discardedNote(t) + userScopeNote(t),
	}}
}

// denyGuardedTools are the tools a deny list is there to narrow: shell
// commands, file reads and writes, and fetches (#1193). A whole-tool grant of
// WebSearch, Grep or a single MCP tool opens nothing a deny entry is written
// for.
var denyGuardedTools = map[string]bool{
	"Bash": true, "Read": true, "Write": true, "Edit": true,
	"MultiEdit": true, "NotebookEdit": true, "WebFetch": true,
}

// broadGrant reports an allow entry that grants one of denyGuardedTools whole:
// the bare tool name ("Bash", "Edit") or a wildcard-only specifier
// ("Bash(*)", "Read(**)", "Bash(*:*)").
func broadGrant(allow []string) bool {
	for _, a := range allow {
		a = strings.TrimSpace(a)
		open := strings.IndexByte(a, '(')
		if open < 0 {
			if denyGuardedTools[a] {
				return true
			}
			continue
		}
		if !denyGuardedTools[a[:open]] || !strings.HasSuffix(a, ")") {
			continue
		}
		switch strings.TrimSpace(a[open+1 : len(a)-1]) {
		case "", "*", "**", ":*", "*:*", "//**", "/**":
			return true
		}
	}
	return false
}

// permissiveDenyMode reports a defaultMode in which the deny list is the only
// gate left (#1193).
func permissiveDenyMode(mode string) bool {
	switch mode {
	case "auto", "bypassPermissions", "dontAsk":
		return true
	}
	return false
}
