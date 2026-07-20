package rules

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg048 struct{}

var CFG048 = &cfg048{}

func init() { All = append(All, CFG048) }

func (r *cfg048) ID() string { return "CFG048" }

// blanketAutoApproveKeys are the .vscode/settings.json booleans that auto-approve
// every agent tool call (including terminal commands) without confirmation.
//
// Scope caveat: upstream VS Code registers chat.tools.global.autoApprove with
// ConfigurationScope.APPLICATION_MACHINE, so it is *ignored* when it appears in a
// committed workspace settings.json. It is kept here at warn rather than dropped
// because VS Code forks (Cursor, Windsurf) read the same file and may honour it
// at workspace scope — an unverified fork behaviour is a reason to downgrade the
// severity, not to delete the coverage. The keys that upstream really does apply
// from a workspace file are the object-valued ones below.
var blanketAutoApproveKeys = []string{
	"chat.tools.global.autoApprove", // current
	"chat.tools.autoApprove",        // earlier / experimental
}

// The object-valued auto-approve settings. Neither declares a scope, so both take
// the registry default of ConfigurationScope.WINDOW and *are* applied from a
// committed .vscode/settings.json. Neither is `restricted`, so workspace trust
// does not gate them either.
const (
	editsAutoApproveKey = "chat.tools.edits.autoApprove"
	urlsAutoApproveKey  = "chat.tools.urls.autoApprove"
)

// sensitiveEditPatternRe matches the glob patterns VS Code's own default denies —
// files whose edit has immediate side effects. Re-enabling auto-approval for any
// of them is the unambiguous finding: it is dangerous whether the committed map
// replaces the defaults or merges into them.
var sensitiveEditPatternRe = regexp.MustCompile(`(?i)\.vscode|(?:^|[/\\.*])\.git(?:$|[/\\*])|\.env\b|package\.json|\.code-workspace|\.lock\b|-lock\.|gradle|Cargo\.toml|web\.config|\.gitattributes|build\.rs|server\.xml`)

// broadGlobRe matches a pattern that covers the whole tree.
var broadGlobRe = regexp.MustCompile(`^\*{1,2}(?:/\*{1,2})*$`)

// broadURLRe matches a URL pattern with no meaningful host restriction —
// the fetch-tool analogue of CFG040's unrestricted WebFetch.
var broadURLRe = regexp.MustCompile(`^(?:\*{1,2}|(?:https?|\*)://\*{1,2}(?:/.*)?)$`)

// Check flags a committed .vscode/settings.json that blanket-auto-approves agent
// tools. VS Code and its forks (Cursor, Windsurf) read this file, so a repo that
// ships chat.tools(.global).autoApprove: true silently removes the human-in-the-
// loop for anyone who opens it in agent mode — the cross-agent analogue of
// CFG001 (defaultMode: bypassPermissions).
func (r *cfg048) Check(t *Target) []finding.Finding {
	if t == nil || t.VSCodeSettings == nil {
		return nil
	}
	var findings []finding.Finding
	for _, key := range blanketAutoApproveKeys {
		val, present := t.VSCodeSettings.BoolField(key)
		if !present || !val {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Warn, // upstream-inert (application-scoped); see blanketAutoApproveKeys
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: "\"" + key + "\": true blanket-auto-approves every agent tool call, including terminal commands" +
				" — committed to a repo this removes the confirmation prompt for anyone who opens it in agent mode (it also disables the terminal allow/deny list). Upstream VS Code ignores this key from a workspace file (it is application-scoped), but forks that read the same file may not. Remove it",
		})
	}

	findings = append(findings, r.checkEdits(t)...)
	findings = append(findings, r.checkURLs(t)...)
	return findings
}

// checkEdits inspects chat.tools.edits.autoApprove, a map of glob → bool deciding
// which file edits the agent may make unattended. VS Code's default approves
// everything *except* a denylist of files with immediate side effects — notably
// **/.vscode/*.json, which is what makes this chain into CFG047.
func (r *cfg048) checkEdits(t *Target) []finding.Finding {
	entries, ok := t.VSCodeSettings.ObjectField(editsAutoApproveKey)
	if !ok {
		return nil
	}
	var findings []finding.Finding
	var broad []string
	keptProtection := false

	for _, pat := range sortedRawKeys(entries) {
		approved := rawIsTrue(entries[pat])
		switch {
		case sensitiveEditPatternRe.MatchString(pat):
			if !approved {
				keptProtection = true // the default denial is still in place
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG048",
				Severity: finding.Error,
				Scope:    t.Scope,
				File:     t.VSCodeSettingsFile,
				Message: editsAutoApproveKey + " sets \"" + pat + "\": true — auto-approves agent edits to a file VS Code protects by default." +
					" Editing .vscode/*.json unattended chains into a task that runs on folder open (CFG047), so this is a path to unprompted code execution. Remove the entry",
			})
		case broadGlobRe.MatchString(pat) && approved:
			broad = append(broad, pat)
		}
	}

	// A tree-wide approval is the default value, so on its own it is only a
	// finding when the committed map drops the protective denials with it — and
	// it is redundant once a specific re-enabled denial has already been reported.
	if len(broad) > 0 && !keptProtection && len(findings) == 0 {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: editsAutoApproveKey + " sets \"" + strings.Join(broad, "\", \"") + "\": true without restating the default denials" +
				" (**/.vscode/*.json, **/.git/**, .env, lockfiles) — if the committed map replaces the defaults rather than merging into them, agent edits to those files are auto-approved. Re-add the denials, or scope the pattern",
		})
	}
	return findings
}

// checkURLs inspects chat.tools.urls.autoApprove, a map of URL pattern → approval
// deciding which endpoints chat tools may reach unattended. Only patterns with no
// meaningful host restriction are flagged: committing a specific internal docs
// host is ordinary team configuration.
func (r *cfg048) checkURLs(t *Target) []finding.Finding {
	entries, ok := t.VSCodeSettings.ObjectField(urlsAutoApproveKey)
	if !ok {
		return nil
	}
	var findings []finding.Finding
	for _, pat := range sortedRawKeys(entries) {
		if !broadURLRe.MatchString(strings.TrimSpace(pat)) || !urlEntryApproves(entries[pat]) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: urlsAutoApproveKey + " auto-approves \"" + pat + "\" — any host the agent asks for is fetched without confirmation," +
				" which is an exfiltration channel as well as an injection one (the fetched page becomes context). Restrict it to the specific hosts you trust",
		})
	}
	return findings
}

// rawIsTrue reports whether a raw JSON value is the boolean true.
func rawIsTrue(raw json.RawMessage) bool {
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}

// urlEntryApproves reports whether a chat.tools.urls.autoApprove value grants
// approval. The value is either a bool or an object with per-direction flags;
// approving either direction is enough to matter.
func urlEntryApproves(raw json.RawMessage) bool {
	if rawIsTrue(raw) {
		return true
	}
	var o struct {
		ApproveRequest  bool `json:"approveRequest"`
		ApproveResponse bool `json:"approveResponse"`
	}
	return json.Unmarshal(raw, &o) == nil && (o.ApproveRequest || o.ApproveResponse)
}

// sortedRawKeys returns the keys of a raw-object map in a stable order.
func sortedRawKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
