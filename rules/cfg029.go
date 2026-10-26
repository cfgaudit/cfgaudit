// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg029 struct{}

var CFG029 = &cfg029{}

func init() { All = append(All, CFG029) }

func (r *cfg029) ID() string { return "CFG029" }

// permissionBypassRe matches text instructing Claude to auto-approve or skip
// confirmation — disabling the permission system via system context, the
// natural-language equivalent of defaultMode: bypassPermissions (CFG004).
//
// Two groups. The first matches anywhere (unambiguous bypass language). The
// second covers ask/prompt-based forms, which must carry a permission/run object
// — so "never ask for approval" / "without asking before running" match, while
// the benign "never ask the user for API keys" / "don't ask clarifying
// questions" (UX / good practice) do not.
//
// The approve-class accepts the adverb in either position. Leading is
// unambiguous ("automatically approve …"). Trailing is not — "approve any
// pending PR automatically" is ordinary review workflow, not a permission
// bypass — so the postfix form additionally requires a permission-specific
// object between the verb and the adverb.
var permissionBypassRe = mustFiltered(`(?i)(` +
	`(?:always|automatically)\s+approve` +
	`|auto-?approve\b` +
	`|approve\b[^.\n]{0,30}?\b(?:permission|approval|confirmation|prompt)s?\b[^.\n]{0,25}?\b(?:automatically|without\s+asking|by\s+default)` +
	`|bypass\s+(?:permission|confirmation|approval)` +
	`|skip\s+(?:confirm(?:ation)?|approval|the\s+prompt)` +
	`|without\s+(?:confirm(?:ation)?|approval|prompt(?:ing)?)` +
	`|never\s+(?:prompt|confirm|require\s+approval)` +
	`|(?:without\s+asking|never\s+ask(?:ing)?|do\s+not\s+ask|don'?t\s+ask|do\s+not\s+prompt)\s+(?:the\s+user\s+)?(?:for\s+)?(?:permission|approval|confirmation|before\s+(?:running|executing|proceeding|making|applying|doing))` +
	`)`)

// prohibitionRe matches the cues that turn a line, or the line governing a list,
// into a prohibition. Kept separate from the bypass pattern because the two are
// asked different questions: this one is looked for *around* a match, never as
// one.
var prohibitionRe = regexp.MustCompile(`(?i)\b(never|do\s+not|don'?t|must\s+not|mustn'?t|may\s+not|cannot|can'?t|avoid|refuse\s+to|forbidden|prohibited|not\s+allowed|no\s+circumstances)\b`)

// noWithoutRe matches "no <up to four words>" right before a "without ..."
// match: "no file modified without approval", "No code changes without
// approval". It applies only to that branch, because "with no prompts,
// auto-approve everything" puts the same word before a real bypass (#623).
var noWithoutRe = regexp.MustCompile(`(?i)\bno\s+(?:\S+\s+){0,4}$`)

// forbiddenMarkRe matches a line marked as a forbidden item rather than worded
// as one: "❌ Bypass permissions", "- 🚫 auto-approve deploys" (#623).
var forbiddenMarkRe = regexp.MustCompile(`^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*)?\s*(?:\x{274C}|\x{1F6AB}|\x{26D4}|\x{2717}|\x{2718})`)

// antiPatternHeadRe matches a heading or list lead-in that introduces things not
// to do without a negation word: "Common failure modes", "Anti-patterns",
// "Red flags" (#623).
var antiPatternHeadRe = regexp.MustCompile(`(?i)\b(?:anti-?patterns?|failure\s+modes?|pitfalls?|common\s+mistakes|red\s+flags|what\s+not\s+to\s+do|don'?ts|traps?)\b`)

// willNotHeadRe matches a list heading that opens with "Will not" or "Won't"
// and no subject: "**Will Not:**", "**Explicitly Will NOT** (without `--force`
// flag):", the boundaries section of a command saying what it refuses to do
// (#937). A heading with a subject ("Claude will not ask before:") can
// introduce a list of actions taken without asking, so it is not matched,
// and "will not" stays out of prohibitionRe for the same reason.
var willNotHeadRe = regexp.MustCompile(`(?i)^\s*(?:#+\s*|[-*+]\s+)?(?:\*\*|__)?\s*(?:explicitly\s+|strictly\s+)?(?:will\s+not|won'?t)\b`)

// labelLeadRe captures the bold label that opens a list item ("- **The
// "cleanup" trap** — ..."), whose words say what kind of item it is (#655).
var labelLeadRe = regexp.MustCompile(`^\s*(?:[-*+]\s+|\d+[.)]\s+)?\*\*([^*]+)\*\*`)

// notPermissionAfterRe matches what turns a confirmation match into something
// other than a permission prompt (#655): "confirmation bias", and the
// confirmation of facts ("do not ask for confirmation of information already
// provided").
var notPermissionAfterRe = regexp.MustCompile(`(?i)^(?:\s+bias\b|\s+of\s+(?:the\s+)?(?:information|details?|facts?|data|requirements?|inputs?|values?|what)\b)`)

// settingValueAfterRe matches an approval word used as a configuration key
// with a value ("` + "`auto-approve: false`" + `", "auto_approve = true") rather than
// as an instruction (#655).
var settingValueAfterRe = regexp.MustCompile(`^\s*` + "`?" + `\s*[:=]`)

// flagConditionRe matches a clause that makes the match conditional on a
// command-line flag the user passes ("When ` + "`--yes`" + ` or ` + "`-y`" + `: ... skip
// confirmations"): the text documents a flag, the choice is the user's (#655).
var flagConditionRe = regexp.MustCompile(`(?i)\b(?:when|if|with)\b[^.]*?` + "`?" + `--?[a-z][\w-]*`)

// withoutGateRe matches the "without confirmation / approval / prompting"
// branch. The ask-branch ("without asking for confirmation") names the agent's
// own question and is not subject to the action check.
var withoutGateRe = regexp.MustCompile(`(?i)^without\s+(?:confirm|approval|prompt)`)

// continuedFrom returns the previous line when line i continues it: a line that
// opens in lower case is the second half of a wrapped sentence ("... and make
// other database changes" / "directly, without asking for confirmation").
func continuedFrom(lines []string, i int) string {
	if i == 0 {
		return ""
	}
	t := strings.TrimLeft(lines[i], " \t")
	if t == "" || t[0] < 'a' || t[0] > 'z' {
		return ""
	}
	return lines[i-1] + " "
}

// clauseRest returns the text after a match up to the end of its sentence.
func clauseRest(after string) string {
	for i := 0; i+1 < len(after); i++ {
		if (after[i] == '.' || after[i] == ';' || after[i] == '!' || after[i] == '?') && (after[i+1] == ' ' || after[i+1] == '\t') {
			return after[:i]
		}
	}
	return after
}

// agentActionRe matches a verb of the kind a permission prompt guards. A
// "without confirmation / approval / prompting" clause with none of these
// anywhere in it describes something else ("a behavior shows up consistently
// without prompting") (#655).
var agentActionRe = regexp.MustCompile(`(?i)\b(?:run|runs|running|ran|execut\w*|apply|applies|applying|appl\w*|commit\w*|push\w*|merg\w*|deploy\w*|install\w*|delet\w*|remov\w*|modif\w*|edit\w*|writ\w*|overwrit\w*|creat\w*|proceed\w*|continu\w*|mak\w*|chang\w*|call\w*|invok\w*|us(?:e|es|ing)|approv\w*|accept\w*|perform\w*|do|does|doing|act|acts|acting|tak\w*|fix\w*|updat\w*|work\w*|operat\w*|go|goes|going|handl\w*|process\w*|launch\w*|start\w*|send\w*|post\w*|upload\w*|download\w*|mov\w*|renam\w*|refactor\w*|implement\w*|ship\w*|releas\w*|publish\w*|drop\w*|reset\w*|rewrit\w*|tool\w*|command\w*|action\w*|step\w*|task\w*|change\w*|operation\w*)\b`)

// conditionAfterRe matches text after a match that turns it into the name of a
// condition rather than an instruction: "Destructive action without
// confirmation → stop and confirm", "... without approval is forbidden" (#623).
var conditionAfterRe = regexp.MustCompile(`(?i)^[^.;]{0,60}?(?:→\s*stop\b|\bstop\s+and\s+(?:ask|confirm)\b|\b(?:is|are)\s+(?:forbidden|prohibited|not\s+allowed|never\s+allowed)\b)`)

// modeNameAfterRe matches "auto-approve mode" and its kin, where the phrase
// names a setting the text is describing ("when auto-approve mode is on")
// rather than telling the agent to approve (#623).
var modeNameAfterRe = regexp.MustCompile(`(?i)^\s+(?:mode|setting|flag|option|policy|list|rules?|config(?:uration)?)\b`)

// listItemRe matches a markdown list item and captures its indentation, so the
// walk up to a list's governing line can tell a sibling from a parent.
var listItemRe = regexp.MustCompile(`^(\s*)(?:[-*+]|\d+[.)])\s+`)

// clauseStart returns the offset of the clause that ends at end: the text after
// the last sentence or clause break before it. A break is punctuation followed
// by whitespace, so a filename ("`.env` contents") does not split a line, while
// a real sentence boundary does.
//
// A colon is deliberately not a break. In these files a colon introduces a list
// or an enumeration that the words before it govern ("Never: push to main"), so
// cutting there would drop the very negation that is being looked for.
func clauseStart(line string, end int) int {
	start := 0
	for i := 0; i+1 < end && i+1 < len(line); i++ {
		if (line[i] == '.' || line[i] == ';' || line[i] == '!' || line[i] == '?') &&
			(line[i+1] == ' ' || line[i+1] == '\t') {
			start = i + 2
		}
	}
	return start
}

// negated reports whether the match at loc sits inside a prohibition rather than
// being one.
//
// Three shapes, in order:
//
//   - The match begins with a negation of its own ("don't ask permission",
//     "never prompt"). That IS the bypass instruction, phrased negatively, so it
//     is not negated by anything and keeps reporting. Checking this first is
//     what keeps the rule's main true positive alive.
//
//   - A negation precedes the match in the same clause ("Never auto-approve
//     destructive operations", "Do not install new packages without confirming
//     with the user"). The second one is the inverse of the finding: it demands
//     confirmation.
//
//   - The line is a list item whose governing line is a prohibition ("**Never
//     without explicit user request:**" above a list holding "Push to remote
//     without confirmation"). The negation is not on the line at all, which is
//     the shape a line-local check alone cannot see.
//
// Suppressing these is not an evasion route worth worrying about: the text that
// silences the rule is the same text the model reads, so a payload hidden under
// a fake "never do these" heading instructs the agent not to do it either.
func negated(lines []string, i int, loc []int) bool {
	line := lines[i]
	match := line[loc[0]:loc[1]]
	// What follows the match can say it is not a permission prompt at all
	// (#655), whichever way the match itself is phrased.
	if notPermissionAfterRe.MatchString(line[loc[1]:]) {
		return true
	}
	// Only a key-shaped word takes a value: "`auto-approve: false`". A colon
	// after "without confirmation" introduces a list ("Safe to run without
	// confirmation:"), which is the bypass.
	if strings.HasPrefix(strings.ToLower(match), "auto") && settingValueAfterRe.MatchString(line[loc[1]:]) {
		return true
	}
	if m := prohibitionRe.FindStringIndex(match); m != nil && m[0] == 0 {
		return false
	}
	before := line[clauseStart(line, loc[0]):loc[0]]
	if prohibitionRe.MatchString(before) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(match), "without") && noWithoutRe.MatchString(before) {
		return true
	}
	if forbiddenMarkRe.MatchString(line) || conditionAfterRe.MatchString(line[loc[1]:]) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(match), "auto") && modeNameAfterRe.MatchString(line[loc[1]:]) {
		return true
	}
	if flagConditionRe.MatchString(before) {
		return true
	}
	if withoutGateRe.MatchString(match) && !agentActionRe.MatchString(continuedFrom(lines, i)+before+match+clauseRest(line[loc[1]:])) {
		return true
	}
	if m := labelLeadRe.FindStringSubmatch(line); m != nil && antiPatternHeadRe.MatchString(m[1]) {
		return true
	}
	// A command-line flag (terraform apply -auto-approve, --auto-approve) names
	// an option of some tool, not an order to the agent (#623).
	if loc[0] > 0 && line[loc[0]-1] == '-' {
		return true
	}
	g := governingLine(lines, i)
	if introducesList(g) && (antiPatternHeadRe.MatchString(g) || forbiddenMarkRe.MatchString(g) || willNotHeadRe.MatchString(g)) {
		return true
	}
	// Only the clause the list hangs off counts, for the same reason the line
	// check is clause-scoped: a long paragraph that ends in a colon can carry a
	// negation about something else entirely. Measured, that is not theoretical
	// -- "do **not** rely on a tool EXECUTE event ... Instead, implement approval
	// as a wrapper around the tool's `execute`:" introduces a to-do list, and
	// reading its "do not" as a prohibition header suppressed a real finding in
	// the list below it.
	return introducesList(g) && prohibitionRe.MatchString(g[clauseStart(g, len(g)):])
}

// cliFlagRe finds a command-line flag in a line: `--fix`, `-y`, --yes. The
// leading character keeps "non-interactive" and a list dash out.
var cliFlagRe = regexp.MustCompile("(?:^|[\\s`(|\"'=,\\[])(--?[A-Za-z][\\w-]*)")

// agentPermissionFlags are the flags that change an agent's own permission
// handling. A line naming one of them keeps reporting: there the bypass phrase
// is about the agent.
var agentPermissionFlags = map[string]bool{
	"--dangerously-skip-permissions": true, "--allow-dangerously-skip-permissions": true,
	"--permission-mode": true, "--yolo": true, "--full-auto": true, "--trust": true,
	"--dangerously-bypass-approvals-and-sandbox": true, "--approval-mode": true,
	"--auto-approve": true, "--always-approve": true,
}

// autoApproveObjectRe is the object that makes "auto-approve" an order about
// the agent's permissions: tools, commands, edits, permissions, or all of them,
// or the no-prompt mode it runs in ("Auto-approve in yolo mode", kept from
// #655).
var autoApproveObjectRe = regexp.MustCompile(`(?i)^[^.;|]{0,40}?\b(?:all|every|everything|any|anything|tools?|tool\s+calls?|bash|shell|commands?|edits?|writes?|permissions?|permission\s+requests?|actions?|operations?|mcp|yolo|bypass|dangerously)\b`)

// autoApproveMappedRe is the same object written before an arrow, the shape of
// an approval table: "read-only tools → auto-approve".
var autoApproveMappedRe = regexp.MustCompile(`(?i)\b(?:tools?|tool\s+calls?|commands?|edits?|writes?|operations?|actions?|permissions?|bash|shell|mcp)\b[^.;|]{0,40}(?:→|->|=>)\s*$`)

// confirmingPermissionRe is what makes "without confirming" skip a
// confirmation: with a person, "first", or nothing after it.
var confirmingPermissionRe = regexp.MustCompile(`(?i)^\s*(?:$|[.,;:!)]|with\s+(?:the\s+user|me|them|anyone|a\s+human|the\s+owner|the\s+maintainer)|first\b|before\b)`)

// confirmObjectRe matches a direct object after "never confirm": "a root
// cause", "the fix", "that it works". Confirming a fact is not a permission
// prompt; "never confirm with the user" and "never confirm before running"
// have no such object.
var confirmObjectRe = regexp.MustCompile(`(?i)^\s+(?:a|an|the|any|that|this|these|those|its|their|your)\b`)

// neverPromptObjectRe is the object that makes "never prompt"/"never confirm"
// about permission: never prompt for permission, approval or confirmation, or
// before running something.
var neverPromptObjectRe = regexp.MustCompile(`(?i)^\s+(?:the\s+user\s+)?(?:for\s+(?:permission|approval|confirmation)|before\b)`)

// The bypassNoun patterns match "bypass permission(s)" used as a noun
// (Salesforce's bypass permission set): after an article, before "set", or as
// a whole list item ("sharing rules, and bypass permissions."). "and bypass
// permission prompts" is the verb and keeps reporting.
var bypassNounBeforeRe = regexp.MustCompile(`(?i)\b(?:the|a|an|any|this|that|each|its|their)\s+$`)
var bypassNounListRe = regexp.MustCompile(`(?:,|\band|\|)\s+$`)
var bypassNounAfterRe = regexp.MustCompile(`(?i)^s?\s+sets?\b`)
var bypassNounEndRe = regexp.MustCompile(`^s?\s*[,.;)]`)

// readOnlyGrantRe matches a grant limited to reading: "run read-only commands
// or tools without confirmation, but you must NEVER write code" (#867).
// Claude Code itself runs its read-only tools and commands without asking, so
// the sentence lifts no prompt that guards anything.
var readOnlyGrantRe = regexp.MustCompile(`(?i)\bread[- ]?only\s+(?:commands?|tools?|operations?|actions?|queries|checks?|git\s+commands?)\b`)

// programRunsRe and codeSpanRe find a clause that describes a program's own
// interactive prompts rather than the agent's (#867): a command in code
// formatting followed by a verb in the third person ("`gh stack merge` runs
// without prompting"), or the plural "prompts" with a command named in the
// clause ("Use `create-chat-sdk` to scaffold a project without prompts"). An
// order to the agent puts the verb first: "Run `make deploy` without
// prompting" keeps reporting.
var programRunsRe = regexp.MustCompile("`[^`]+`[*_]*\\s+(?:[^.;`]{0,60}?\\s)?(?:and\\s+`[^`]+`\\s+)?(?:runs|run|works|exits|completes|proceeds|continues)\\b[^.;]*$")

// programExitsRe matches a program as the subject of "exits ... without
// prompting": "If it exits successfully without prompting" (#914). "it" counts
// only with the verbs a process has.
var programExitsRe = regexp.MustCompile(`(?i)\b(?:it|the\s+(?:command|script|cli|tool|installer|program|binary|process))\s+(?:\w+\s+){0,2}?(?:exits|completes|succeeds|finishes|returns)\b[^.;]*$`)

// nonInteractiveRe matches a mode in which a program must not prompt: "In
// non-interactive or JSON mode, never prompt or open a browser" (#914).
var nonInteractiveRe = regexp.MustCompile(`(?i)\bnon-?interactive\b|\bheadless\b|\bJSON\s+mode\b`)
var codeSpanRe = regexp.MustCompile("`[^`]+`")

// prApprovalRe matches a line about approving a pull request, where "skip
// approval" means not submitting an approving review (#867).
var prApprovalRe = regexp.MustCompile(`(?i)\b(?:PRs?|pull\s+requests?|merge\s+requests?|MRs?)\b`)

// detectionLeadRe matches a clause that asks the agent to find the phrase, not
// to follow it: "Flag any path that can bypass approval UI" (#867).
var detectionLeadRe = regexp.MustCompile(`(?i)\b(?:flag|detect|look\s+for|check\s+for|scan\s+for|watch\s+for)\s+(?:any|anything|all|every)\b[^.;]{0,60}\b(?:that|which)\s+(?:can|could|might|may|tries|try|attempts?)\s+$`)

// notAPermissionBypass reports a match that names something other than the
// agent's permission prompts (#830): a tool's own flag being documented
// ("`--fix`: Apply fixes without prompting"), "auto-approve" as a noun or an
// approval workflow ("routes to auto-approve", "Auto-approve and merge"),
// "never prompt" about input rather than permission ("Never prompt for JSON",
// "users are never prompted"), and Salesforce's bypass permission set.
func notAPermissionBypass(line string, loc []int) bool {
	match := strings.ToLower(line[loc[0]:loc[1]])
	after := line[loc[1]:]
	before := line[:loc[0]]
	// Where a flag can make the phrase its description: anywhere in a table
	// row (a table documents commands), else in the same clause before the
	// match ("- `--fix`: Apply fixes without prompting", "use `-y` to
	// auto-approve requirements"). A flag elsewhere on the line does not.
	scope := before[clauseStart(line, loc[0]):]
	if strings.HasPrefix(strings.TrimSpace(line), "|") {
		scope = line
	}
	if flags := cliFlagRe.FindAllStringSubmatch(scope, -1); len(flags) > 0 {
		agentFlag := false
		for _, f := range cliFlagRe.FindAllStringSubmatch(line, -1) {
			if agentPermissionFlags[strings.ToLower(f[1])] {
				agentFlag = true
			}
		}
		if !agentFlag {
			return true
		}
	}
	if strings.HasPrefix(match, "without") && readOnlyGrantRe.MatchString(scope) {
		return true
	}
	if strings.HasPrefix(match, "without prompt") {
		plural := len(after) > 0 && (after[0] == 's' || after[0] == 'S')
		if programRunsRe.MatchString(scope) || programExitsRe.MatchString(scope) || plural && codeSpanRe.MatchString(scope) {
			return true
		}
	}
	// "skip the prompt and pass `--api-key-env NAME` instead" swaps a CLI's
	// key prompt for a flag (#914).
	if strings.HasPrefix(match, "skip the prompt") && cliFlagRe.MatchString(clauseRest(after)) {
		return true
	}
	if strings.HasPrefix(match, "never prompt") && nonInteractiveRe.MatchString(scope) {
		return true
	}
	if strings.HasPrefix(match, "skip approval") && prApprovalRe.MatchString(line) {
		return true
	}
	if detectionLeadRe.MatchString(scope) {
		return true
	}
	// A quoted phrase is cited, not said: ("ignore previous instructions",
	// "skip approval", "run this command") (#867).
	if q := strings.Count(before, "\""); q%2 == 1 && strings.HasPrefix(after, "\"") {
		return true
	}
	switch {
	case strings.HasPrefix(match, "without confirm") && strings.HasPrefix(strings.ToLower(after), "ing"):
		// "without confirming the running app loaded the fresh build" checks a
		// fact; "without confirming with the user" or "... first" skips a
		// confirmation and keeps reporting (#855).
		return !confirmingPermissionRe.MatchString(after[3:])
	case strings.HasPrefix(match, "auto"):
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			return true // a heading or a code comment names a topic
		}
		return !autoApproveObjectRe.MatchString(after) && !autoApproveMappedRe.MatchString(before)
	case strings.HasPrefix(match, "never prompt"), strings.HasPrefix(match, "never confirm"):
		if len(after) > 0 && isWordByte(after[0]) {
			return true // prompts, prompted, confirmed, CONFIRMED
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(after)), "interactively") {
			return true // a program's design: "Never prompt interactively inside the use case" (#867)
		}
		rest := strings.TrimPrefix(strings.TrimSpace(strings.ToLower(after)), "the user ")
		if strings.HasPrefix(match, "never confirm") && confirmObjectRe.MatchString(after) {
			return true // "Never confirm a root cause without ..." (#855)
		}
		return !neverPromptObjectRe.MatchString(after) && strings.HasPrefix(rest, "for")
	case strings.HasPrefix(match, "bypass permission"):
		return bypassNounBeforeRe.MatchString(before) || bypassNounAfterRe.MatchString(after) ||
			(bypassNounListRe.MatchString(before) && bypassNounEndRe.MatchString(after))
	}
	return false
}

// The shapes describesState skips (#884).
var (
	// A state: "apply was requested without approval", "added without
	// approval", "unresolved P1 without approval", "max iterations reached
	// without approval".
	stateBeforeRe = regexp.MustCompile(`(?i)(?:\b(?:was|were|has\s+been|have\s+been|had\s+been)\s+\w+(?:ed|en|ne|un)|\b(?:added|reached|unresolved|introduced)(?:\s+\S+){0,2})\s+$`)
	// The fix named in the same row or item: "| Write actions without
	// approval | Add human approval gate ... |".
	addGateRe = regexp.MustCompile(`(?i)\badd(?:s|ing)?\s+(?:an?\s+)?(?:\w+\s+){0,2}(?:approval|confirmation)\b`)
	// "What it will NOT do without confirmation" keeps the confirmation.
	willNotRe = regexp.MustCompile(`(?i)\b(?:will\s+not|won'?t|would\s+not|wouldn'?t)\b`)
	// Someone other than the agent approves or bypasses: "The user always
	// approves which change ...", "Members with isAdmin ... bypass permission
	// checks".
	userSubjectRe     = regexp.MustCompile(`(?i)\b(?:the\s+)?(?:user|human|maintainer|owner|reviewer)\s+$`)
	grantThirdPartyRe = regexp.MustCompile(`(?i)\b(?:members|users|admins?|administrators|owners|roles?|accounts?|callers?|clients?|superusers?)\b`)
	youRe             = regexp.MustCompile(`(?i)\byou\b`)
	codeSubjectRe     = regexp.MustCompile("`\\s*$")
	promptNounRe      = regexp.MustCompile(`(?i)^\s+(?:structure|engineering|templates?|design|files?|text|injection|caching|tokens?|quality|context|format\w*|optimi[sz]ation)\b`)
	hypotheticalRe    = regexp.MustCompile(`(?i)\b(?:would|could)\s+(?:\w+\s+){1,2}$`)
	questionWhatRe    = regexp.MustCompile(`(?i)\bwhat\s+(?:\S+\s+){1,3}(?:may|can|could|should|is\s+allowed\s+to)\s+\w+\s+$`)
	abbrevDotRe       = strings.NewReplacer("etc. ", "etc, ", "e.g. ", "e.g, ", "i.e. ", "i.e, ")
)

// describesState reports a match that names a state, a defect, a tool or a
// question rather than ordering the agent to skip a prompt (#884): status
// labels and rubric rows ("apply was requested without approval",
// "unresolved P1 without approval"), an anti-pattern row that names the fix
// ("| Write actions without approval | Add human approval gate |"), a bold
// label naming a defect ("**Destructive actions without confirmation or
// undo**"), "will NOT do without confirmation", a "Never ... etc. Without
// Approval" heading, the user or a third party as the subject, a command as
// the subject of "never prompt", "prompt" as a noun ("prompt-only", "prompt
// structure"), "would apply without prompting" and "what the tool may decide
// without confirmation".
func describesState(line string, loc []int) bool {
	match := strings.ToLower(line[loc[0]:loc[1]])
	after := line[loc[1]:]
	start := clauseStart(abbrevDotRe.Replace(line), loc[0])
	before := line[start:loc[0]]
	// A match that is itself negated ("don't ask permission") is the bypass;
	// negated() keeps it for the same reason.
	if m := prohibitionRe.FindStringIndex(match); m == nil || m[0] != 0 {
		if prohibitionRe.MatchString(before) || willNotRe.MatchString(before) {
			return true
		}
	}
	switch {
	case strings.HasPrefix(match, "without"):
		if stateBeforeRe.MatchString(before) || questionWhatRe.MatchString(before) {
			return true
		}
		t := strings.TrimSpace(line)
		if (strings.HasPrefix(t, "|") || listItemRe.MatchString(line)) && addGateRe.MatchString(line[loc[1]:]) {
			return true
		}
		if m := labelLeadRe.FindStringSubmatchIndex(line); m != nil && loc[0] >= m[2] && loc[1] <= m[3] {
			first := strings.Fields(line[m[2]:loc[0]] + " x")[0]
			if !agentActionRe.MatchString(first) && !prohibitionRe.MatchString(first) && !strings.EqualFold(first, "always") && !strings.EqualFold(first, "just") {
				return true
			}
		}
		if strings.HasPrefix(match, "without prompt") {
			if strings.HasPrefix(after, "-") || match == "without prompt" && promptNounRe.MatchString(after) {
				return true
			}
			if strings.HasPrefix(match, "without prompting") && hypotheticalRe.MatchString(before) {
				return true
			}
		}
	case strings.HasPrefix(match, "never prompt"):
		return strings.HasPrefix(after, "-") || codeSubjectRe.MatchString(before)
	case strings.HasPrefix(match, "always approve"), strings.HasPrefix(match, "automatically approve"):
		return userSubjectRe.MatchString(before)
	case strings.HasPrefix(match, "bypass permission"):
		return grantThirdPartyRe.MatchString(before) && !youRe.MatchString(before)
	}
	return false
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_'
}

// introducesList reports whether a line is the kind that governs the list under
// it: a Markdown heading, or a line that ends in a colon.
//
// Requiring that shape is what keeps the list check from reading a negation that
// is about something else. Measured over 601 instruction files seeded on this
// rule's own phrases, dropping it suppressed a real finding ("read-only tools →
// auto-approve") because an unrelated paragraph above the list happened to say
// "do not rely on a tool EXECUTE event". The prohibition headers that matter in
// real files all have this shape: "Claude must not:", "**Never:**",
// "Forbidden:", "## DO NOT", "## Must Not".
func introducesList(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "#") {
		return true
	}
	// Trailing emphasis and code markers sit outside the colon in real files
	// ("**Never:**"), so they are trimmed before the check.
	return strings.HasSuffix(strings.TrimRight(t, "*_`~ "), ":")
}

// governingLine returns the line a list item hangs under: the nearest line above
// it that is not a blank line and not a sibling or deeper list item. It returns
// "" for a line that is not a list item, and for a list whose governing line is
// further away than maxGoverningDistance, where attributing a heading to an item
// stops being justified.
func governingLine(lines []string, i int) string {
	const maxGoverningDistance = 20
	m := listItemRe.FindStringSubmatch(lines[i])
	if m == nil {
		return ""
	}
	indent := len(m[1])
	for j := i - 1; j >= 0 && i-j <= maxGoverningDistance; j-- {
		prev := lines[j]
		if strings.TrimSpace(prev) == "" {
			continue
		}
		if pm := listItemRe.FindStringSubmatch(prev); pm != nil {
			if len(pm[1]) < indent {
				return prev // the parent item of a nested list
			}
			continue // a sibling
		}
		return prev
	}
	return ""
}

func (r *cfg029) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		lines := strings.Split(src.Content, "\n")
		fenced := fencedLines(src.Content)
		for i, line := range lines {
			loc := permissionBypassRe.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if negated(lines, i, loc) || notAPermissionBypass(line, loc) || describesState(line, loc) {
				continue
			}
			// A # comment in a fenced code block says what the next command
			// does: "# Force overwrite without prompting" (#855), or what a
			// parameter means: "force: bool = False,  # Skip approval" (#867).
			if fenced[i+1] && (strings.HasPrefix(strings.TrimSpace(line), "#") || strings.Contains(line[:loc[0]], " # ")) {
				continue
			}
			lineNo := i + 1
			findings = append(findings, finding.Finding{
				RuleID:   "CFG029",
				Severity: finding.Error,
				File:     src.File,
				Line:     lineNo,
				Col:      loc[0] + 1,
				Message: src.Name + " line " + strconv.Itoa(lineNo) + " instructs the agent to bypass permission prompts (\"" + line[loc[0]:loc[1]] +
					"\") — this disables the permission system via system-context text, equivalent to defaultMode: bypassPermissions (CFG004). Remove it",
			})
		}
	}
	return findings
}
