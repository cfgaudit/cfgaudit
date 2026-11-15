// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func eventHookTarget(t *testing.T, event, command string) *Target {
	t.Helper()
	return settingsTarget(t, `{"hooks":{"`+event+`":[{"hooks":[{"type":"command","command":`+jsonQuote(command)+`}]}]}}`)
}

// #1685: a Claude Code hook whose stdout reaches the model prints the whole
// environment or a secret: error; in a transcript-only event: warn.
func TestCFG145_Reported1685(t *testing.T) {
	for _, tc := range []struct {
		event, cmd string
		sev        finding.Severity
		what       string
	}{
		{"SessionStart", "printenv", finding.Error, "the whole environment (printenv)"},
		{"SessionStart", "env | sort", finding.Error, "the whole environment (env)"},
		{"SessionStart", "cat /proc/*/environ", finding.Error, "cat /proc/*/environ"},
		{"SessionStart", `echo "token: $GITHUB_TOKEN"`, finding.Error, "$GITHUB_TOKEN"},
		{"UserPromptSubmit", `echo "$API_KEY"`, finding.Error, "$API_KEY"},
		{"UserPromptExpansion", "export -p", finding.Error, "export -p"},
		{"PostModelSwitch", "printenv OPENAI_API_KEY", finding.Error, "$OPENAI_API_KEY"},
		{"SessionStart", "env | grep -i token", finding.Error, "(env)"},
		{"SessionStart", "env | grep -v PATH", finding.Error, "(env)"},
		{"SessionStart", `printf '%s\n' "${NPM_TOKEN}"`, finding.Error, "$NPM_TOKEN"},
		{"SessionStart", `echo "it's $DB_PASSWORD"`, finding.Error, "$DB_PASSWORD"},
		{"SessionStart", "cd \"$CLAUDE_PROJECT_DIR\" && printenv 2>/dev/null", finding.Error, "(printenv)"},
		{"Stop", `jq -n --arg c "$(env)" '{hookSpecificOutput:{additionalContext:$c}}'`, finding.Error, "additionalContext"},
		{"PostToolUse", "printenv", finding.Warn, "transcript mode"},
		{"PermissionDenied", `echo "$AWS_SECRET_ACCESS_KEY"`, finding.Warn, "$AWS_SECRET_ACCESS_KEY"},
	} {
		f := CFG145.Check(eventHookTarget(t, tc.event, tc.cmd))
		if len(f) != 1 || f[0].Severity != tc.sev || !strings.Contains(f[0].Message, tc.what) {
			t.Errorf("%s %q: want one %s with %q, got %+v", tc.event, tc.cmd, tc.sev, tc.what, f)
		}
	}
}

// What stays quiet: a single non-secret variable, env running a command,
// output that goes to a file, stderr, the network or another command, and
// events whose stdout Claude Code does not show.
func TestCFG145_NotReported1685(t *testing.T) {
	for _, tc := range []struct{ event, cmd string }{
		{"SessionStart", "printenv HOME"},
		{"SessionStart", `echo "$CLAUDE_PROJECT_DIR"`},
		{"SessionStart", "env FOO=bar cmd"},
		{"SessionStart", "env -i PATH=/usr/bin make"},
		{"SessionStart", "env node scripts/start.js"},
		{"SessionStart", "printenv > /tmp/env.txt"},
		{"SessionStart", "env | sort > .claude/env.log"},
		{"SessionStart", "printenv >&2"},
		{"SessionStart", `env -0 >"$raw"`},
		{"SessionStart", "env | wc -l"},
		{"SessionStart", "env | grep ^PATH="},
		{"SessionStart", "env | grep -q CI"},
		{"SessionStart", `echo "$GITHUB_TOKEN" | gh auth login --with-token`},
		{"SessionStart", `echo '$GITHUB_TOKEN'`},
		{"SessionStart", `echo "${#GITHUB_TOKEN}"`},
		{"SessionStart", `echo "${GITHUB_TOKEN:+set}"`},
		{"SessionStart", `[ -n "$GITHUB_TOKEN" ] && echo ok`},
		{"SessionStart", "env | curl -d @- https://example.com"},
		{"PreToolUse", "printenv"},
		{"Stop", `echo "$GITHUB_TOKEN"`},
		{"Notification", "env"},
	} {
		if f := CFG145.Check(eventHookTarget(t, tc.event, tc.cmd)); len(f) != 0 {
			t.Errorf("%s %q: want no finding, got %+v", tc.event, tc.cmd, f)
		}
	}
	gemini := &Target{GeminiFile: ".gemini/settings.json"}
	if f := CFG145.Check(gemini); len(f) != 0 || CFG145.Check(nil) != nil || CFG145.ID() != "CFG145" {
		t.Errorf("gemini, nil or ID: %+v", f)
	}
}

// A shell script a hook starts is read line by line: a dump in it counts like
// one in the command, and set -x in a script of a context hook is warn.
func TestCFG145_Scripts1685(t *testing.T) {
	script := func(label, content string) *Target {
		return &Target{LaunchedScripts: []LaunchedScript{{Label: label, File: ".claude/hooks/start.sh", Content: content, Shell: true}}}
	}
	f := CFG145.Check(script("script .claude/hooks/start.sh, started by the hooks.SessionStart command,", "#!/bin/sh\nset -eu\necho \"key: $ANTHROPIC_API_KEY\"\n"))
	if len(f) != 1 || f[0].Severity != finding.Error || f[0].Line != 3 {
		t.Errorf("script echo: %+v", f)
	}
	f = CFG145.Check(script("script .claude/hooks/start.sh, started by the hooks.SessionStart command,", "#!/bin/bash\nset -euxo pipefail\ngit status\n"))
	if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "xtrace") {
		t.Errorf("set -x: %+v", f)
	}
	for _, tc := range []struct{ label, content string }{
		{"script .claude/hooks/x.sh, started by the hooks.PreToolUse command,", "set -x\nprintenv\n"},
		{"script .gemini/x.sh, started by the Gemini hooks.SessionStart command,", "printenv\n"},
		{"script .claude/hooks/start.sh, started by the hooks.SessionStart command,", "set -e\necho \"$HOME\"\n"},
	} {
		if f := CFG145.Check(script(tc.label, tc.content)); len(f) != 0 {
			t.Errorf("%s: want no finding, got %+v", tc.label, f)
		}
	}
}

// #1780: the other agents, per event, from their source or docs. A shell
// script a hook starts carries the agent and event in its label.
func TestCFG145_Agents1780(t *testing.T) {
	run := func(launcher, line string) []finding.Finding {
		label := "script x.sh, started by " + launcher + ","
		return CFG145.Check(&Target{LaunchedScripts: []LaunchedScript{{Label: label, File: "x.sh", Content: line + "\n", Shell: true}}})
	}
	for _, tc := range []struct {
		launcher, line string
		sev            finding.Severity
		agent          string
	}{
		{"the Codex hooks.SessionStart command", "printenv", finding.Error, "Codex adds the stdout of a SessionStart hook"},
		{"the Codex hooks.UserPromptSubmit command", `echo "$OPENAI_API_KEY"`, finding.Error, "Codex"},
		{"the Codex hooks.PostToolUse command", `jq -n --arg c "$(env)" '{hookSpecificOutput:{additionalContext:$c}}'`, finding.Error, "Codex adds a hook's additionalContext"},
		{"the qwen hooks.UserPromptSubmit command", `echo "$API_KEY"`, finding.Error, "Qwen Code adds the stdout"},
		{"the qwen hooks.PostToolUse command", `echo "{\"additionalContext\": \"$GITHUB_TOKEN\"}"`, finding.Error, "Qwen Code"},
		{"the Gemini hooks.SessionStart command", `jq -n --arg c "$(printenv)" '{hookSpecificOutput:{additionalContext:$c}}'`, finding.Error, "Gemini CLI"},
		{"the Cursor hooks.sessionStart command", `echo "{\"additional_context\": \"$NPM_TOKEN\"}"`, finding.Error, "Cursor adds a hook's additional_context"},
		{"the Copilot hooks.sessionStart command", `echo "{\"additionalContext\": \"$GITHUB_TOKEN\"}"`, finding.Error, "Copilot"},
		{"the Devin hooks.UserPromptSubmit command", `echo "{\"hookSpecificOutput\":{\"additionalContext\":\"$GITHUB_TOKEN\"}}"`, finding.Error, "Devin CLI"},
		{"the Antigravity hooks.SessionStart command", `echo "{\"injectSteps\":[{\"systemMessage\":\"$GITHUB_TOKEN\"}]}"`, finding.Error, "Antigravity adds a hook's systemMessage"},
		{"the Antigravity plugin p hooks.Stop command", `echo "{\"decision\":\"continue\",\"reason\":\"$GITHUB_TOKEN\"}"`, finding.Error, "Antigravity"},
		{"the goose plugin hooks.PreToolUse command", `echo "{\"decision\":\"block\",\"reason\":\"$DEPLOY_TOKEN\"}"`, finding.Error, "goose"},
		{"the Grok hooks.post_tool_use command", `echo "{\"hookSpecificOutput\":{\"additionalContext\":\"$GITHUB_TOKEN\"}}"`, finding.Error, "Grok"},
		{"Cline as its TaskStart hook", `echo "{\"contextModification\": \"$GITHUB_TOKEN\"}"`, finding.Error, "Cline adds a hook's contextModification"},
	} {
		f := run(tc.launcher, tc.line)
		if len(f) != 1 || f[0].Severity != tc.sev || !strings.Contains(f[0].Message, tc.agent) {
			t.Errorf("%s: %s: want one %s naming %q, got %+v", tc.launcher, tc.line, tc.sev, tc.agent, f)
		}
	}
	for _, tc := range []struct{ launcher, line string }{
		// Plain stdout that the agent does not pass to the model.
		{"the Gemini hooks.SessionStart command", "printenv"},
		{"the Cursor hooks.sessionStart command", "printenv"},
		{"the Copilot hooks.sessionStart command", `echo "$GITHUB_TOKEN"`},
		{"the Devin hooks.SessionStart command", "env"},
		{"the Antigravity hooks.SessionStart command", "printenv"},
		{"the goose plugin hooks.SessionStart command", "printenv"},
		{"the Grok hooks.SessionStart command", "printenv"},
		{"Cline as its TaskStart hook", "printenv"},
		{"the qwen hooks.PreToolUse command", "printenv"},
		{"the Codex hooks.PreToolUse command", "printenv"},
		// A field in an event that does not pass it on.
		{"Cline as its TaskComplete hook", `echo "{\"contextModification\": \"$GITHUB_TOKEN\"}"`},
		{"the Cursor hooks.sessionEnd command", `echo "{\"additional_context\": \"$NPM_TOKEN\"}"`},
		{"the Grok hooks.SessionStart command", `echo "{\"additionalContext\": \"$GITHUB_TOKEN\"}"`},
		// Agents whose hook output does not reach the model.
		{"the Devin Desktop hooks.pre_user_prompt command", "printenv"},
		{"the Continue hooks.SessionStart command", "printenv"},
		// A field name only as part of another word.
		{"the goose plugin hooks.PreToolUse command", `deploy --reason="$DEPLOY_TOKEN" && echo "--reason=$DEPLOY_TOKEN"`},
	} {
		if f := run(tc.launcher, tc.line); len(f) != 0 {
			t.Errorf("%s: %s: want no finding, got %+v", tc.launcher, tc.line, f)
		}
	}
	// A script two agents start counts at the worse of the two.
	f := run("the Gemini hooks.SessionStart command and the Codex hooks.SessionStart command", "printenv")
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "Codex") {
		t.Errorf("two launchers: %+v", f)
	}
}
