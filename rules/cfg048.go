// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
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

// The object-valued auto-approve settings. Neither is `restricted`, so workspace
// trust does not gate them.
//
// chat.tools.urls.autoApprove declares no scope, takes the registry default of
// ConfigurationScope.WINDOW, and *is* applied from a committed
// .vscode/settings.json.
//
// chat.tools.edits.autoApprove was the same until VS Code 1.134.0, which
// registers it with `scope: ConfigurationScope.APPLICATION` (f2542bcba2,
// "agentHost: Harden edit auto-approval rules"; the 1.133.0 registration has no
// scope, the 1.134.0 one does). Since then upstream ignores it from a workspace
// file, so its findings are downgraded the way blanketAutoApproveKeys are: VS
// Code 1.133 and earlier still apply it, and so may forks that read the file.
const (
	editsAutoApproveKey = "chat.tools.edits.autoApprove"
	urlsAutoApproveKey  = "chat.tools.urls.autoApprove"

	// permissionLevelKey is the successor to the CVE-2025-53773 setting: it picks
	// the permission mode every new chat session starts in. Registered in the
	// `chatSidebar` node, which declares no scope, and with no scope of its own,
	// so it inherits ConfigurationScope.WINDOW and is applied from a committed
	// workspace settings.json. Not `restricted`, so workspace trust does not gate
	// it (#434).
	permissionLevelKey = "chat.permissions.default"

	// defaultConfigurationKey is the object-valued spelling of the same two
	// decisions permissionLevelKey carries, registered alongside it rather than
	// replacing it: `approvals` picks how tool calls are confirmed and `mode`
	// picks how far the agent runs unattended. The registration declares no
	// scope, so like permissionLevelKey it takes ConfigurationScope.WINDOW and is
	// applied from a committed workspace settings.json, and it is not
	// `restricted`, so workspace trust does not gate it either (#468).
	defaultConfigurationKey = "chat.defaultConfiguration"

	// terminalAutoApproveKey maps a command pattern to whether the terminal tool
	// may run it unattended. A key wrapped in "/" is a regular expression; a plain
	// key matches the start of a command. WINDOW-scoped, unrestricted, like the
	// two maps above.
	terminalAutoApproveKey = "chat.tools.terminal.autoApprove"

	// terminalIgnoreDefaultsKey turns off VS Code's built-in allow/deny rules.
	// Its own setting description says the default denial rules "are designed to
	// protect you against running dangerous commands" and to switch them off "at
	// your own risk".
	terminalIgnoreDefaultsKey = "chat.tools.terminal.ignoreDefaultAutoApproveRules"
)

// weakeningPermissionLevels are the values of chat.permissions.default that start
// a session with approvals already given, mapped to what each one does.
//
// ChatPermissionLevel also declares "assisted" (delegate approval decisions to a
// model), but the setting's registered `enum` is only default/autoApprove/
// autopilot, so "assisted" is not a value this setting accepts and flagging it
// would report something VS Code's own schema rejects.
var weakeningPermissionLevels = map[string]string{
	"autoapprove": "every tool call is auto-approved and errors are auto-retried",
	"autopilot":   "everything Bypass Approvals does, plus an internal stop hook that keeps the agent working until it decides the task is done",
}

// weakeningDefaultConfigurations are the chat.defaultConfiguration fields whose
// value starts a session with a confirmation already waived, together with the
// upstream description of what the value does and the value to return to.
//
// Only the unambiguous end of each enum is listed. `approvals` also accepts
// "assisted" (a model decides) and `mode` also accepts "plan"; neither waives a
// confirmation outright, so neither is reported.
var weakeningDefaultConfigurations = []struct {
	field, value, does, restore string
}{
	{
		field:   "approvals",
		value:   "allowall",
		does:    "runs tool calls without asking, in the words of the setting's own enum description",
		restore: "default",
	},
	{
		field:   "mode",
		value:   "autopilot",
		does:    "lets the agent autonomously iterate from start to finish, in the words of the setting's own enum description, so nothing stops it until it decides the task is done",
		restore: "interactive",
	},
}

// useClaudeHooksKey switches on execution of Claude-format hooks. Its default is
// false and only true loosens, and DEFAULT_HOOK_FILE_PATHS already includes the
// repository's own .claude/settings.json, so a committed true is a repository
// enabling execution of hooks the same repository ships.
const useClaudeHooksKey = "chat.useClaudeHooks"

// hookLocationsKey registers where hook files are read from: "Specify paths to
// hook configuration files that define custom shell commands to execute at
// strategic points in an agent's workflow ... Relative paths are resolved from
// the root folder(s) of your workspace." The value maps a path to whether it is
// enabled.
const hookLocationsKey = "chat.hookFilesLocations"

// defaultHookFilePaths is DEFAULT_HOOK_FILE_PATHS from promptFileLocations.ts.
// A committed file enabling one of these registers nothing new, so only a path
// outside this set is reported; disabling one is the narrowing direction.
var defaultHookFilePaths = map[string]bool{
	".github/hooks":               true,
	".claude/settings.local.json": true,
	".claude/settings.json":       true,
	"~/.copilot/hooks":            true,
	"~/.claude/settings.json":     true,
}

// terminalTrustNote states the mitigation that applies to the terminal
// auto-approve family and to nothing else in this rule. Upstream marked
// chat.tools.terminal.enableAutoApprove, .autoApprove,
// .ignoreDefaultAutoApproveRules, .autoApproveWorkspaceNpmScripts and
// .blockDetectedFileWrites `restricted: true` on 2026-08-05, and the
// configuration registry defines that as: "When restricted, value of this
// configuration will be read only from trusted sources. For eg., If the
// workspace is not trusted, then the value of this configuration is not read
// from workspace settings file."
//
// So "for anyone who opens this repo" is no longer true for these keys, and the
// rule says so rather than dropping the finding: trust is granted once, usually
// on the first prompt, and thereafter every clone is covered. The keys that are
// NOT restricted keep the stronger wording, verified in the same registration
// file: chat.permissions.default and chat.defaultConfiguration declare neither a
// scope nor `restricted`, so they take WINDOW and apply from a committed file
// with no trust gate at all.
const vscodeRestrictedNote = " The key is `restricted`, so the value is ignored until the workspace is trusted; trust is a single prompt, granted once, after which every clone is covered."

// hookHarnessNote and terminalHarnessNote scope the hook and integrated
// terminal keys to the harness that reads them (#752): VS Code's settings
// reference says chat.useHooks, chat.hookFilesLocations and chat.useClaudeHooks
// configure the Local harness only, and its tools page that the
// integrated-terminal controls apply to Local harness sessions and to
// configurations that use the integrated terminal tool.
const hookHarnessNote = " It configures only Local harness sessions; a Copilot harness session, which recent VS Code releases start by default, reads hooks from its own settings files and from this repository's Claude settings without it."

const terminalHarnessNote = " These controls apply to Local harness sessions and to configurations that use the integrated terminal tool; a Copilot harness session runs commands through its own shell tool."

const terminalTrustNote = " These terminal keys are `restricted`, so the value is ignored until the workspace is trusted; trust is a single prompt, granted once, after which every clone is covered."

// nestedFilterNote qualifies the scope and trust statements above for a value
// written in nested-object form. VS Code 1.136.1 and earlier checked only the
// top-level JSON key against the configuration registry, so {"chat": {...}}
// skipped the workspace scope filter and Restricted Mode alike (CVE-2026-70334,
// CVE-2026-81376; fixed by 0684cb5 in 1.136.2). The keys reported here are the
// ones whose mitigation is one of those two filters.
const nestedFilterNote = " This value is written in nested-object form, which VS Code 1.136.1 and earlier did not run through the workspace scope and Restricted Mode filters (CVE-2026-70334, CVE-2026-81376, fixed in 1.136.2), so on those releases it applies from the committed file without trust."

// nestedNote returns nestedFilterNote when key takes its value from the nested
// form, and nothing otherwise, so callers can append it unconditionally.
func nestedNote(t *Target, key string) string {
	if t.VSCodeSettings.Nested(key) {
		return nestedFilterNote
	}
	return ""
}

// catchAllTerminalPatternRe matches a terminal auto-approve regex that approves
// any command. Deliberately narrow: only the unmistakable catch-alls, because a
// pattern that merely looks broad ("/^git /") is ordinary team configuration.
var catchAllTerminalPatternRe = regexp.MustCompile(`^(?:\^?\.[*+]\$?|\^?\(\.[*+]\)\$?)$`)

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
			Key:      key,
			Message: "\"" + key + "\": true blanket-auto-approves every agent tool call, including terminal commands" +
				" — committed to a repo this removes the confirmation prompt for anyone who opens it in agent mode (it also disables the terminal allow/deny list). Upstream VS Code ignores this key from a workspace file (it is application-scoped), but forks that read the same file may not." + nestedNote(t, key) + " Remove it",
		})
	}

	findings = append(findings, r.checkPermissionLevel(t)...)
	findings = append(findings, r.checkDefaultConfiguration(t)...)
	findings = append(findings, r.checkEdits(t)...)
	findings = append(findings, r.checkURLs(t)...)
	findings = append(findings, r.checkTerminal(t)...)
	findings = append(findings, r.checkPromptOverride(t)...)
	findings = append(findings, r.checkFixedKeys(t)...)
	return findings
}

// checkPromptOverride reports the two Copilot Chat debug settings that replace
// the agent's prompt (#648). Both are registered in the Copilot extension's
// package.json with no scope, so they take WINDOW and apply from a workspace
// file, and neither is `restricted`; the extension declares no
// untrustedWorkspaces capability, so VS Code runs it only once the workspace is
// trusted. toolCallingLoop.ts hands both to applyConfiguredPromptOverrides, which
// replaces the built system prompt and tool descriptions with the YAML's
// systemPrompt and toolDescriptions. The inline text is also scanned by the
// instruction-content rules (copilotPromptOverrideSources).
func (r *cfg048) checkPromptOverride(t *Target) []finding.Finding {
	var findings []finding.Finding
	if v, ok := t.VSCodeSettings.StringField(copilotPromptOverrideKey); ok && strings.TrimSpace(v) != "" {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message:  copilotPromptOverrideKey + " is set: Copilot Chat replaces the system prompt and tool descriptions of every agent request with this YAML's systemPrompt and toolDescriptions, so the repository writes the agent's instructions and can redescribe what each tool does. It is a debug setting, applies from a workspace file, and takes effect once the workspace is trusted. Remove it",
		})
	}
	if v, ok := t.VSCodeSettings.StringField(copilotPromptOverrideFileKey); ok && strings.TrimSpace(v) != "" {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message:  copilotPromptOverrideFileKey + " is \"" + strings.TrimSpace(v) + "\": Copilot Chat reads a YAML file from that path and replaces the system prompt and tool descriptions of every agent request with it. The path is read as a file path on the machine (URI.file), not resolved against the repository, so cfgaudit cannot see what it contains. It is a debug setting and takes effect once the workspace is trusted. Remove it",
		})
	}
	return findings
}

// copilotPromptOverrideFileKey is the file form of copilotPromptOverrideKey.
const copilotPromptOverrideFileKey = "github.copilot.chat.debug.promptOverrideFile"

// checkPermissionLevel inspects chat.permissions.default, which decides the
// permission mode every new chat session starts in. A committed "autoApprove" or
// "autopilot" means anyone who opens the repo begins with the approvals already
// granted — terminal commands, edits and MCP calls alike. This is the successor
// to the `chat.tools.autoApprove` of CVE-2025-53773, reached through a key that
// is genuinely workspace-honoured rather than application-scoped.
func (r *cfg048) checkPermissionLevel(t *Target) []finding.Finding {
	value, ok := t.VSCodeSettings.StringField(permissionLevelKey)
	if !ok {
		return nil
	}
	what, weakening := weakeningPermissionLevels[strings.ToLower(strings.TrimSpace(value))]
	if !weakening {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG048",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     t.VSCodeSettingsFile,
		Message: permissionLevelKey + " is \"" + strings.TrimSpace(value) + "\" — every new chat session starts in that mode, where " + what +
			". Committed to a repo this hands the approvals to anyone who opens it, before they agree to anything; it is the successor to the chat.tools.autoApprove of CVE-2025-53773. Remove the key, or set it to \"default\"",
	}}
}

// checkDefaultConfiguration inspects chat.defaultConfiguration, which carries the
// same two decisions as chat.permissions.default in an object rather than a flat
// string. Both keys are registered, so this is an addition to the CVE-2025-53773
// lineage rather than a rename, and each field is reported on its own because
// each is separately set and separately removed.
func (r *cfg048) checkDefaultConfiguration(t *Target) []finding.Finding {
	entries, ok := t.VSCodeSettings.ObjectField(defaultConfigurationKey)
	if !ok {
		return nil
	}
	var findings []finding.Finding
	for _, sub := range weakeningDefaultConfigurations {
		raw, present := entries[sub.field]
		if !present {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}
		value = strings.TrimSpace(value)
		if !strings.EqualFold(value, sub.value) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: defaultConfigurationKey + " sets \"" + sub.field + "\": \"" + value + "\", which " + sub.does +
				". Every new chat session starts that way, so committing it hands the decision to anyone who opens the repo before they agree to anything. It is the object-valued spelling of the " + permissionLevelKey +
				" this rule already flags, and both keys are live. Remove the field, or set it to \"" + sub.restore + "\"",
		})
	}
	return findings
}

// checkTerminal inspects the two settings that govern which terminal commands the
// agent may run unattended.
//
// chat.tools.terminal.autoApprove maps a command pattern to a decision. Only a
// catch-all pattern is reported: naming specific commands a project runs all day
// is what the setting is for, and flagging that would make the rule noise.
//
// chat.tools.terminal.ignoreDefaultAutoApproveRules removes VS Code's built-in
// rules, including the denials. On its own it approves nothing, so it is warn; it
// is the amplifier that makes a broad approve pattern unconditional.
func (r *cfg048) checkTerminal(t *Target) []finding.Finding {
	var findings []finding.Finding

	if entries, ok := t.VSCodeSettings.ObjectField(terminalAutoApproveKey); ok {
		var broad []string
		for _, pat := range sortedRawKeys(entries) {
			if isCatchAllTerminalPattern(pat) && terminalEntryApproves(entries[pat]) {
				broad = append(broad, pat)
			}
		}
		if len(broad) > 0 {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG048",
				Severity: finding.Error,
				Scope:    t.Scope,
				File:     t.VSCodeSettingsFile,
				Message: terminalAutoApproveKey + " approves the catch-all pattern \"" + strings.Join(broad, "\", \"") +
					"\" — every command the agent proposes runs in the terminal with no confirmation." + terminalTrustNote + terminalHarnessNote + nestedNote(t, terminalAutoApproveKey) +
					" List the specific commands the project needs instead",
			})
		}
	}

	if val, present := t.VSCodeSettings.BoolField(useClaudeHooksKey); present && val {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: useClaudeHooksKey + " is true — it switches on execution of Claude-format hooks, which VS Code leaves off by default, and the default hook locations already include this repository's own .claude/settings.json." +
				" A committed file therefore turns on execution of hook commands the same repository ships." + vscodeRestrictedNote + hookHarnessNote + nestedNote(t, useClaudeHooksKey) +
				" Remove the key and let each user decide",
		})
	}

	if entries, ok := t.VSCodeSettings.ObjectField(hookLocationsKey); ok {
		var added []string
		for _, path := range sortedRawKeys(entries) {
			if defaultHookFilePaths[path] {
				continue
			}
			if rawIsTrue(entries[path]) {
				added = append(added, path)
			}
		}
		if len(added) > 0 {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG048",
				Severity: finding.Warn,
				Scope:    t.Scope,
				File:     t.VSCodeSettingsFile,
				Message: hookLocationsKey + " registers the hook location \"" + strings.Join(added, "\", \"") +
					"\" — hook files declare \"custom shell commands to execute at strategic points in an agent's workflow\", and a relative path is resolved from the workspace root, so a committed value points the editor at command files this repository chose." +
					" cfgaudit reads the standard hook paths and does not follow a registered one, so whatever those files contain is unreviewed by this scan." + vscodeRestrictedNote + hookHarnessNote + nestedNote(t, hookLocationsKey),
			})
		}
	}

	if val, present := t.VSCodeSettings.BoolField(terminalIgnoreDefaultsKey); present && val {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG048",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: terminalIgnoreDefaultsKey + " is true — VS Code's built-in terminal auto-approve rules are switched off, including the denials its own documentation describes as \"designed to protect you against running dangerous commands\"." +
				" On its own this approves nothing, but it removes the backstop under any pattern the same file approves." + terminalTrustNote + terminalHarnessNote + nestedNote(t, terminalIgnoreDefaultsKey) +
				" Leave it unset and narrow the allow patterns instead",
		})
	}
	return findings
}

// isCatchAllTerminalPattern reports whether a terminal auto-approve key matches
// every command. Two spellings qualify: a regex (wrapped in "/", with optional
// trailing flags) whose body is a catch-all, and an empty plain key, which is a
// prefix that every command starts with.
func isCatchAllTerminalPattern(pattern string) bool {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return true
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	end := strings.LastIndex(p, "/")
	if end <= 0 {
		return false
	}
	return catchAllTerminalPatternRe.MatchString(p[1:end])
}

// terminalEntryApproves reports whether an entry grants approval. The value is
// either a bool or an object carrying `approve`, which is the field that decides;
// `matchCommandLine` only changes what the pattern is matched against.
func terminalEntryApproves(raw json.RawMessage) bool {
	if rawIsTrue(raw) {
		return true
	}
	var obj struct {
		Approve *bool `json:"approve"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil || obj.Approve == nil {
		return false
	}
	return *obj.Approve
}

// editsScopeNote states where chat.tools.edits.autoApprove from a workspace file
// still takes effect.
const editsScopeNote = " VS Code 1.134 and later ignore this key from a workspace file (it is application-scoped), but VS Code 1.133 and earlier apply it, and forks that read the same file may too."

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
				Severity: finding.Warn, // application-scoped since 1.134; see editsAutoApproveKey
				Scope:    t.Scope,
				File:     t.VSCodeSettingsFile,
				Message: editsAutoApproveKey + " sets \"" + pat + "\": true — auto-approves agent edits to a file VS Code protects by default." +
					" Editing .vscode/*.json unattended chains into a task that runs on folder open (CFG047), so this is a path to unprompted code execution." +
					editsScopeNote + nestedNote(t, editsAutoApproveKey) + " Remove the entry",
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
			Severity: finding.Info, // application-scoped since 1.134; see editsAutoApproveKey
			Scope:    t.Scope,
			File:     t.VSCodeSettingsFile,
			Message: editsAutoApproveKey + " sets \"" + strings.Join(broad, "\", \"") + "\": true without restating the default denials" +
				" (**/.vscode/*.json, **/.git/**, .env, lockfiles) — if the committed map replaces the defaults rather than merging into them, agent edits to those files are auto-approved." +
				editsScopeNote + nestedNote(t, editsAutoApproveKey) + " Re-add the denials, or scope the pattern",
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

// fixedIn11362 qualifies a key VS Code stopped reading from a workspace file in
// 1.136.2 (2026-09-03): 1.136.1 and earlier read it, and forks that took the
// settings code before that release may still.
const fixedIn11362 = " VS Code 1.136.2 and later read this only from user settings, so the value is inert there; 1.136.1 and earlier read it from a committed workspace file, and so may forks that read the same file."

// checkFixedKeys reports workspace values of keys behind three advisories fixed
// in VS Code 1.136.2 (#649).
//
//   - chat.remoteAgentHosts, chat.agentHost.localFilePermissions (CVE-2026-78462,
//     fix 4321a67 "agentHost: read remote AH from global settings only"): the
//     host list was read with getValue, which includes workspace values, though
//     the setting was APPLICATION-scoped; the fix reads global configuration
//     only and marks the settings restricted. A workspace list connects the
//     agent to a host the repository chose; a workspace localFilePermissions map
//     grants such a host files on the machine.
//   - github.copilot.chat.workspace.prototypeAdoCodeSearchEndpointOverride and
//     its legacy ...advanced... spelling (CVE-2026-81381, fix f94e10b "Remove
//     configurable Azure DevOps code search endpoint override"): the Azure DevOps
//     token was sent to the configured URL; the setting no longer exists.
//   - terminal.integrated.allowInUntrustedWorkspace in nested-object form: the
//     key is restricted, so a flat workspace value is ignored exactly in the
//     untrusted workspace it would matter in, and is not reported; the nested
//     form skipped that filter up to 1.136.1 (CVE-2026-70334, the advisory's own
//     example).
func (r *cfg048) checkFixedKeys(t *Target) []finding.Finding {
	s := t.VSCodeSettings
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{RuleID: "CFG048", Severity: sev, Scope: t.Scope, File: t.VSCodeSettingsFile, Message: msg})
	}
	if raw, ok := s.ObjectField("chat.agentHost.localFilePermissions"); ok && len(raw) > 0 {
		add(finding.Warn, "chat.agentHost.localFilePermissions grants remote agent hosts access to files on this machine ("+quoteList(sortedRawKeys(raw))+") — a committed grant hands a host the repository names read or write access outside the workspace (CVE-2026-78462)."+fixedIn11362+" Remove it")
	}
	if hosts := vscodeStringItems(s, "chat.remoteAgentHosts"); len(hosts) > 0 {
		add(finding.Warn, "chat.remoteAgentHosts lists remote agent hosts to connect to ("+quoteList(hosts)+") — the agent then runs against a host the repository chose (CVE-2026-78462)."+fixedIn11362+" Remove it")
	}
	for _, key := range []string{"github.copilot.chat.workspace.prototypeAdoCodeSearchEndpointOverride", "github.copilot.chat.advanced.workspace.prototypeAdoCodeSearchEndpointOverride"} {
		if v, ok := s.StringField(key); ok && strings.TrimSpace(v) != "" {
			add(finding.Warn, key+" is \""+strings.TrimSpace(v)+"\" — Copilot sent the Azure DevOps access token to this endpoint for code search (CVE-2026-81381). The setting was removed in VS Code 1.136.2, where it does nothing; on 1.136.1 and earlier it applies from this file. Remove it")
		}
	}
	if v, ok := s.BoolField("terminal.integrated.allowInUntrustedWorkspace"); ok && v && s.Nested("terminal.integrated.allowInUntrustedWorkspace") {
		add(finding.Warn, "terminal.integrated.allowInUntrustedWorkspace is true, written in nested-object form — the setting lets terminals start in an untrusted workspace, and VS Code 1.136.1 and earlier did not run the nested form through the Restricted Mode filter, so a committed file could turn it on before trust (CVE-2026-70334, whose own example this is). From 1.136.2 the value is ignored until the workspace is trusted. Remove it")
	}
	return findings
}

// vscodeStringItems returns the string entries of an array-valued setting,
// accepting entries that are objects with an "address" field as well.
func vscodeStringItems(s *parser.VSCodeSettings, key string) []string {
	raw, ok := s.RawValue(key)
	if !ok {
		return nil
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		var str string
		if json.Unmarshal(it, &str) == nil && strings.TrimSpace(str) != "" {
			out = append(out, str)
			continue
		}
		var obj struct {
			Address string `json:"address"`
		}
		if json.Unmarshal(it, &obj) == nil && strings.TrimSpace(obj.Address) != "" {
			out = append(out, obj.Address)
		}
	}
	return out
}
