// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg145 struct{}

// CFG145 reports a Claude Code hook whose output carries the whole
// environment or a secret-named variable into the model's context (#1685).
var CFG145 = &cfg145{}

func init() { All = append(All, CFG145) }

func (r *cfg145) ID() string { return "CFG145" }

// hookOutputAgent is where one agent sends a hook's output.
type hookOutputAgent struct {
	// name is the agent as a message names it.
	name string
	// context are the events whose stdout on success enters the model's
	// context; transcript those whose stdout only the user sees on request.
	context, transcript map[string]bool
	// transcriptWhere says where the user sees a transcript event's stdout.
	transcriptWhere string
	// json maps an output field that enters the context to the events it
	// does so in; nil events means any event.
	json map[string]map[string]bool
	// xtraceShown says how a failing hook's stderr reaches the user, for
	// the set -x finding; "" leaves set -x unreported for this agent.
	xtraceShown string
}

// hookOutputAgents are the agents whose hook output CFG145 judges, keyed by
// the prefix of their hook sites' labels ("" is Claude Code).
var hookOutputAgents = map[string]hookOutputAgent{
	// Claude Code 2.1.325, from the event descriptions in its binary:
	// "stdout shown to Claude" (PostModelSwitch: "on the next request"),
	// "stdout shown in transcript mode (ctrl+o)".
	"": {
		name:            "Claude Code",
		context:         events("SessionStart", "UserPromptSubmit", "UserPromptExpansion", "PostModelSwitch"),
		transcript:      events("PostToolUse", "PostToolUseFailure", "PermissionDenied"),
		transcriptWhere: "to anyone who opens transcript mode (Ctrl+O)",
		json:            map[string]map[string]bool{"additionalContext": nil},
		xtraceShown:     "shows to the user when the hook fails",
	},
	// Cline v4.1.26 (apps/vscode/src/sdk/hooks-adapter.ts, hook-factory.ts):
	// stdout that is not JSON is dropped; contextModification is appended as a
	// <hook_context> message for TaskStart, UserPromptSubmit, PreToolUse and
	// PostToolUse. stderr goes to the log only.
	"Cline": {
		name: "Cline",
		json: map[string]map[string]bool{"contextModification": events("TaskStart", "UserPromptSubmit", "PreToolUse", "PostToolUse")},
	},
	// Cursor (cursor.com/docs/agent/hooks): only JSON output fields reach
	// the agent.
	"Cursor": {
		name: "Cursor",
		json: map[string]map[string]bool{
			"additional_context":      events("sessionStart", "postToolUse", "postToolUseFailure"),
			"agent_message":           events("preToolUse", "beforeShellExecution", "beforeMCPExecution"),
			"followup_message":        events("stop", "subagentStop"),
			"updated_mcp_tool_output": events("postToolUse"),
		},
	},
	// Copilot CLI and VS Code (.github/hooks): docs.github.com hooks
	// configuration reference, and the CLI changelog (1.0.11 sessionStart,
	// 1.0.65 userPromptSubmitted additionalContext).
	"Copilot": {
		name: "Copilot",
		json: map[string]map[string]bool{
			"additionalContext":        events("sessionStart", "userPromptSubmitted", "postToolUse", "postToolUseFailure", "notification", "subagentStart"),
			"modifiedResult":           events("postToolUse"),
			"permissionDecisionReason": events("preToolUse"),
			"reason":                   events("agentStop", "subagentStop"),
		},
	},
	// Devin CLI (docs.devin.ai/cli/extensibility/hooks): a JSON object on
	// stdout controls the outcome.
	"Devin": {
		name: "Devin CLI",
		json: map[string]map[string]bool{
			"additionalContext": events("SessionStart", "UserPromptSubmit", "PostToolUse"),
			"reason":            events("PreToolUse"),
		},
	},
	// Antigravity (antigravity.google/docs/hooks): output is JSON on stdout.
	"Antigravity": {
		name: "Antigravity",
		json: map[string]map[string]bool{
			"systemMessage":    events("SessionStart", "PreInvocation"),
			"userMessage":      events("SessionStart", "PreInvocation"),
			"ephemeralMessage": events("SessionStart", "PreInvocation"),
			"reason":           events("PreToolUse", "Stop"),
		},
	},
	// Gemini CLI v0.68.0 (packages/core/src/hooks/hookRunner.ts): plain
	// stdout becomes a systemMessage, which reaches the user only; the model
	// gets additionalContext as <hook_context> and a blocking reason.
	"Gemini": {
		name: "Gemini CLI",
		json: map[string]map[string]bool{
			"additionalContext": events("SessionStart", "BeforeAgent", "AfterTool"),
			"reason":            events("AfterAgent", "BeforeTool", "AfterTool"),
		},
	},
	// Qwen Code v0.27.4 (hookRunner.ts PLAIN_TEXT_CONTEXT_EVENTS): plain
	// stdout becomes context for three events.
	"qwen": {
		name:    "Qwen Code",
		context: events("SessionStart", "UserPromptSubmit", "UserPromptExpansion"),
		json: map[string]map[string]bool{
			"additionalContext": events("PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch", "SubagentStart", "PreCompact"),
			"reason":            events("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolBatch", "Stop", "SubagentStop", "TodoCreated", "TodoCompleted"),
		},
	},
	// Codex rust-v0.169.0 (codex-rs/hooks/src/events): "plain stdout becomes
	// model context" for SessionStart, SubagentStart and UserPromptSubmit.
	"Codex": {
		name:    "Codex",
		context: events("SessionStart", "SubagentStart", "UserPromptSubmit"),
		json: map[string]map[string]bool{
			"additionalContext": events("PreToolUse", "PostToolUse"),
			"reason":            events("PreToolUse", "PostToolUse", "Stop", "SubagentStop"),
		},
	},
	// goose v1.59.1 (crates/goose/src/hooks/mod.rs, stop_hook.rs): most
	// events are observation-only; a block reason of PreToolUse and Stop
	// goes to the model.
	"goose plugin": {
		name: "goose",
		json: map[string]map[string]bool{"reason": events("PreToolUse", "Stop")},
	},
	// Grok Build (xai-org/grok-build, xai-grok-hooks): systemMessage goes to
	// the UI; gate events pass additionalContext, a block reason and
	// replacement tool output to the model.
	"Grok": {
		name: "Grok",
		json: map[string]map[string]bool{
			"additionalContext":        events("PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop", "SubagentStop"),
			"reason":                   events("PreToolUse", "PostToolUse", "Stop", "SubagentStop"),
			"permissionDecisionReason": events("PreToolUse"),
			"updatedToolOutput":        events("PostToolUse"),
			"updatedMCPToolOutput":     events("PostToolUse"),
		},
	},
}

// events is a set of event names.
func events(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[eventKey(n)] = true
	}
	return m
}

// eventKey is an event name compared without case or underscores, since
// Grok accepts SessionStart, sessionStart and session_start alike.
func eventKey(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", ""))
}

// sortedFieldNames returns the keys of json in order.
func sortedFieldNames(json map[string]map[string]bool) []string {
	names := make([]string, 0, len(json))
	for n := range json {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

var (
	hookFieldMu  sync.Mutex
	hookFieldRes = map[string]*regexp.Regexp{}
)

// hookFieldRe matches an output field name used as a JSON or jq object key:
// "reason": …, {additionalContext: $c}; not --reason=….
func hookFieldRe(field string) *regexp.Regexp {
	hookFieldMu.Lock()
	defer hookFieldMu.Unlock()
	re, ok := hookFieldRes[field]
	if !ok {
		re = regexp.MustCompile(`(?:^|[^\w-])\\?["']?` + regexp.QuoteMeta(field) + `\\?["']?\s*:`)
		hookFieldRes[field] = re
	}
	return re
}

// hookSiteRe reads the agent and event of a hook site from its label:
// "hooks.SessionStart command" (Claude Code), "Gemini hooks.BeforeAgent
// command", "skill frontmatter hooks.Stop command", and a script's
// "script x.sh, started by the hooks.SessionStart command,".
var hookSiteRe = regexp.MustCompile(`(?:^|started by the |and the |frontmatter )(?:(Gemini|qwen|Codex|Cursor|Copilot|Devin Desktop|Devin|Antigravity(?: plugin \S+)?|Continue|Grok|goose plugin) )?hooks\.([A-Za-z_]+) command`)

// clineHookRe is a script Cline runs as a hook: "started by Cline as its
// TaskStart hook".
var clineHookRe = regexp.MustCompile(`started by Cline as its ([A-Za-z_]+) hook`)

// hookSiteEvents returns each agent and event a site's label names.
func hookSiteEvents(label string) [][2]string {
	var out [][2]string
	for _, m := range hookSiteRe.FindAllStringSubmatch(label, -1) {
		agent := m[1]
		if strings.HasPrefix(agent, "Antigravity") {
			agent = "Antigravity"
		}
		out = append(out, [2]string{agent, m[2]})
	}
	for _, m := range clineHookRe.FindAllStringSubmatch(label, -1) {
		out = append(out, [2]string{"Cline", m[1]})
	}
	return out
}

func (r *cfg145) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	seen := map[string]bool{}
	for _, site := range commandSitesWithScripts(t) {
		if site.PowerShell || site.HookInput {
			continue
		}
		raw := site.raw()
		what, leaks := hookOutputLeak(raw)
		var sev finding.Severity
		var msg string
		for _, ae := range hookSiteEvents(site.Label) {
			a, ok := hookOutputAgents[ae[0]]
			if !ok {
				continue
			}
			event, key := ae[1], eventKey(ae[1])
			field := ""
			for _, f := range sortedFieldNames(a.json) {
				if events := a.json[f]; (events == nil || events[key]) && hookFieldRe(f).MatchString(raw) {
					field = f
					break
				}
			}
			switch {
			case leaks && (a.context[key] || field != ""):
				via := "the stdout of a " + event + " hook"
				if !a.context[key] {
					via = "a hook's " + field
				}
				sev, msg = finding.Error, site.Label+" prints "+what+": "+a.name+" adds "+via+" to the model's context, so the value goes to the model provider and into the session transcript. Print only what the session needs, never the environment or a secret"
			case sev == "" && leaks && a.transcript[key]:
				sev, msg = finding.Warn, site.Label+" prints "+what+": "+a.name+" shows the stdout of a "+event+" hook "+a.transcriptWhere+". Print only what the session needs, never the environment or a secret"
			case sev == "" && site.Line > 0 && a.context[key] && a.xtraceShown != "" && xtraceRe.MatchString(raw):
				sev, msg = finding.Warn, site.Label+" turns on xtrace (set -x): the shell prints every command with its variables expanded to stderr, which "+a.name+" "+a.xtraceShown+", secrets included. Remove set -x, or turn it off around commands that use a secret"
			}
			if sev == finding.Error {
				break
			}
		}
		if sev == "" {
			continue
		}
		key := site.File + "\x00" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding.Finding{RuleID: "CFG145", Severity: sev, File: site.File, Line: site.Line, Message: msg})
	}
	return out
}

// xtraceRe is a set -x, set -o xtrace, or a set flag bundle with x.
var xtraceRe = regexp.MustCompile(`(?:^|[;&|]\s*)set\s+(?:-[a-wyzA-Z]*x[a-zA-Z]*|-o\s+xtrace)\b`)

// hookPipeline is the commands one pipeline joins with |.
type hookPipeline []string

// hookPipelines splits a command line into pipelines at ;, &, &&, || and
// newlines outside quotes, and each pipeline into its | commands.
func hookPipelines(s string) []hookPipeline {
	var out []hookPipeline
	var cur hookPipeline
	var quote byte
	start := 0
	cut := func(i int) {
		cur = append(cur, s[start:i])
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '|' && i+1 < len(s) && s[i+1] == '|', c == '&' && i+1 < len(s) && s[i+1] == '&':
			cut(i)
			out, cur = append(out, cur), nil
			i++
			start = i + 1
		case c == '|':
			cut(i)
			start = i + 1
		case c == ';' || c == '&' || c == '\n':
			cut(i)
			out, cur = append(out, cur), nil
			start = i + 1
		}
	}
	cut(len(s))
	return append(out, cur)
}

// hookOutputLeak reports what a command writes to stdout that it should not:
// the whole environment, or a secret-named variable. "" and false when it
// writes neither, or sends the output somewhere other than stdout.
func hookOutputLeak(cmd string) (string, bool) {
	for _, p := range hookPipelines(cmd) {
		if len(p) == 0 {
			continue
		}
		if !pipelineReachesStdout(p) {
			continue
		}
		first := shellWords(p[0])
		if len(first) == 0 {
			continue
		}
		if dump := envDumpCommand(first); dump != "" {
			if len(p) > 1 && !filterKeepsSecrets(p[1:]) {
				continue
			}
			return "the whole environment (" + dump + ")", true
		}
		if len(p) > 1 {
			continue // echo "$TOKEN" | docker login --password-stdin
		}
		if name := printedSecret(p[0], first); name != "" {
			return "$" + name, true
		}
	}
	if m := substDumpRe.FindStringSubmatch(cmd); m != nil {
		return "the whole environment ($(" + m[1] + "))", true
	}
	return "", false
}

// substDumpRe is an environment dump inside a substitution that is printed:
// echo "$(env)", jq --arg c "$(printenv)".
var substDumpRe = regexp.MustCompile(`(?:\becho|\bprintf|\bjq|\bcat)\b[^;&|\n]*\$\(\s*(env|printenv|export -p)\s*\)`)

// envDumpCommand returns the command when words dump the whole environment:
// printenv with no name, env with no command to run, export -p, or cat of a
// /proc environ file.
func envDumpCommand(words []string) string {
	name := executableName(words[0])
	args := words[1:]
	switch name {
	case "printenv":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && !isRedirect(a) {
				return ""
			}
		}
		return "printenv"
	case "env":
		for _, a := range args {
			switch {
			case isRedirect(a), a == "-0", a == "--null":
			case strings.HasPrefix(a, "-"), strings.Contains(a, "="):
				return "" // env -i cmd, env FOO=bar cmd
			default:
				return "" // a command to run
			}
		}
		return "env"
	case "export":
		if len(args) > 0 && args[0] == "-p" {
			return "export -p"
		}
	case "cat", "strings", "xargs":
		for _, a := range args {
			if procEnvironRe.MatchString(a) {
				return name + " " + a
			}
		}
	}
	return ""
}

// procEnvironRe is a process's environment file under /proc.
var procEnvironRe = regexp.MustCompile(`^/proc/(?:self|\*|\$\$|\$\w+|\d+)/environ$`)

// isRedirect reports a word that starts a redirection: >file, 2>&1, <in.
func isRedirect(w string) bool {
	return strings.HasPrefix(w, ">") || strings.HasPrefix(w, "<") || strings.HasPrefix(w, "1>") || strings.HasPrefix(w, "2>") || strings.HasPrefix(w, "&>")
}

// pipelineReachesStdout reports whether the last command of a pipeline still
// writes to stdout: no redirection of stdout to a file, /dev/null or stderr,
// and no network tool at its end.
func pipelineReachesStdout(p hookPipeline) bool {
	for _, seg := range p {
		words := shellWords(seg)
		for _, w := range words {
			if strings.HasPrefix(w, ">") || strings.HasPrefix(w, "1>") || strings.HasPrefix(w, "&>") {
				return false
			}
		}
		if len(words) > 0 && hookNetworkTools[executableName(words[0])] {
			return false // CFG038
		}
	}
	return true
}

var hookNetworkTools = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true}

// passThroughTools pass the environment dump on to stdout, whole or a slice.
var passThroughTools = map[string]bool{"sort": true, "uniq": true, "head": true, "tail": true, "tee": true, "cat": true, "sed": true, "awk": true, "cut": true, "column": true, "less": true, "more": true, "tr": true}

// secretWordRe is a grep pattern that selects secrets.
var secretWordRe = regexp.MustCompile(`(?i)token|secret|key|pass|auth|cred`)

// filterKeepsSecrets reports whether the commands after an environment dump
// still print secrets: pass-through tools do, a grep for a non-secret name
// (grep ^PATH=), a count (wc, grep -c) or a quiet grep does not.
func filterKeepsSecrets(rest []string) bool {
	for _, seg := range rest {
		words := shellWords(seg)
		if len(words) == 0 {
			return false
		}
		name := executableName(words[0])
		if passThroughTools[name] {
			continue
		}
		if name != "grep" && name != "egrep" && name != "rg" {
			return false
		}
		invert, pattern := false, ""
		for _, w := range words[1:] {
			switch {
			case w == "-v" || w == "--invert-match":
				invert = true
			case w == "-c" || w == "-q" || w == "--count" || w == "--quiet" || w == "-l":
				return false
			case strings.HasPrefix(w, "-"):
			case pattern == "":
				pattern = w
			}
		}
		if !invert && !secretWordRe.MatchString(pattern) {
			return false
		}
	}
	return true
}

// varRefRe is a variable reference: $NAME, ${NAME}, ${NAME:-x}, ${#NAME}.
var varRefRe = regexp.MustCompile(`\$(?:\{(#?)([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// printedSecret returns the secret-named variable an echo, printf or printenv
// prints: echo "token: $GITHUB_TOKEN", printenv API_KEY. A reference in single
// quotes is not expanded; ${#NAME} prints a length and ${NAME:+x} a word.
func printedSecret(seg string, words []string) string {
	switch executableName(words[0]) {
	case "printenv":
		for _, a := range words[1:] {
			if !strings.HasPrefix(a, "-") && secretVarName(a) {
				return a
			}
		}
		return ""
	case "echo", "printf":
	default:
		return ""
	}
	for _, m := range varRefRe.FindAllStringSubmatch(blankSingleQuoted(seg), -1) {
		name, mod := m[4], m[3]
		if m[2] != "" {
			name = m[2]
		}
		if m[1] == "#" || strings.HasPrefix(mod, ":+") || strings.HasPrefix(mod, "+") {
			continue
		}
		if secretVarName(name) {
			return name
		}
	}
	return ""
}

// secretVarName is a variable name that holds a secret: one secretKeyName
// knows, or a bare suffix such as API_KEY or TOKEN.
func secretVarName(name string) bool {
	return secretKeyName(name) || hasSecretSuffix("_"+name)
}

// blankSingleQuoted blanks the text inside single quotes, where the shell
// expands nothing.
func blankSingleQuoted(s string) string {
	b := []byte(s)
	var quote byte
	for i, c := range b {
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				b[i] = ' '
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		}
	}
	return string(b)
}
