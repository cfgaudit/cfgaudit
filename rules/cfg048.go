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

const terminalTrustNote = " These terminal keys are `restricted`, so the value is ignored until the workspace is trusted; trust is a single prompt, granted once, after which every clone is covered."

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
			Message: "\"" + key + "\": true blanket-auto-approves every agent tool call, including terminal commands" +
				" — committed to a repo this removes the confirmation prompt for anyone who opens it in agent mode (it also disables the terminal allow/deny list). Upstream VS Code ignores this key from a workspace file (it is application-scoped), but forks that read the same file may not. Remove it",
		})
	}

	findings = append(findings, r.checkPermissionLevel(t)...)
	findings = append(findings, r.checkDefaultConfiguration(t)...)
	findings = append(findings, r.checkEdits(t)...)
	findings = append(findings, r.checkURLs(t)...)
	findings = append(findings, r.checkTerminal(t)...)
	return findings
}

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
					"\" — every command the agent proposes runs in the terminal with no confirmation." + terminalTrustNote +
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
				" A committed file therefore turns on execution of hook commands the same repository ships." + vscodeRestrictedNote +
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
					" cfgaudit reads the standard hook paths and does not follow a registered one, so whatever those files contain is unreviewed by this scan." + vscodeRestrictedNote,
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
				" On its own this approves nothing, but it removes the backstop under any pattern the same file approves." + terminalTrustNote +
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
