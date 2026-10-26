// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG009_DollarVar(t *testing.T) {
	json := `{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify-send $TOOL_OUTPUT"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "$TOOL_OUTPUT") {
		t.Errorf("expected message to mention $TOOL_OUTPUT, got: %s", f[0].Message)
	}
}

func TestCFG009_BracedVar(t *testing.T) {
	json := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo ${CLAUDE_FILE_PATHS}"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ${VAR}, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "$CLAUDE_FILE_PATHS") {
		t.Errorf("expected message to mention $CLAUDE_FILE_PATHS, got: %s", f[0].Message)
	}
}

func TestCFG009_MultipleVars_DedupedInMessage(t *testing.T) {
	json := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"curl https://$HOST/$PATH?token=$TOKEN&host=$HOST"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	for _, v := range []string{"$HOST", "$PATH", "$TOKEN"} {
		if !strings.Contains(f[0].Message, v) {
			t.Errorf("expected message to mention %s, got: %s", v, f[0].Message)
		}
	}
	// $HOST appears twice in the command but should be listed once.
	if strings.Count(f[0].Message, "$HOST") != 1 {
		t.Errorf("expected $HOST to be deduped, got message: %s", f[0].Message)
	}
}

func TestCFG009_NoInterpolation_NoFinding(t *testing.T) {
	json := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo running tool"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for static command, got %d: %+v", len(f), f)
	}
}

// Framework-provided Claude Code path vars are trusted, not attacker-influenced (#218).
func TestCFG009_SafeFrameworkVars_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		`bash $CLAUDE_PLUGIN_ROOT/hooks/run.sh`,
		`node ${CLAUDE_PROJECT_DIR}/scripts/x.js`,
		`cat $CLAUDE_PLUGIN_ROOT/a ${CLAUDE_PROJECT_DIR}/b`,
	} {
		json := `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"` + cmd + `"}]}]}}`
		if f := CFG009.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for safe framework vars in %q, got %+v", cmd, f)
		}
	}
}

// A safe framework var mixed with a real var still flags the real one.
func TestCFG009_SafeVarMixedWithUnsafe_FlagsUnsafe(t *testing.T) {
	json := `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"$CLAUDE_PLUGIN_ROOT/x $USER_INPUT"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "$USER_INPUT") || strings.Contains(f[0].Message, "CLAUDE_PLUGIN_ROOT") {
		t.Errorf("expected only $USER_INPUT flagged, got: %s", f[0].Message)
	}
}

func TestCFG009_CommandSubstitution_NoFinding(t *testing.T) {
	// $(...) is command substitution, a separate concern (issue #38) — not flagged here.
	json := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo $(date)"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no CFG009 finding for $(...) only, got %d: %+v", len(f), f)
	}
}

func TestCFG009_PositionalParam_NoFinding(t *testing.T) {
	// $1, $@ etc. are not user-interpolated values; skipped.
	json := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"sh -c 'echo $1 $@'"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 0 {
		t.Errorf("expected no finding for positional params, got %d: %+v", len(f), f)
	}
}

func TestCFG009_OneFindingPerCommand(t *testing.T) {
	// Two separate hook commands → two findings.
	json := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo $A"},{"type":"command","command":"echo $B"}]}]}}`
	f := CFG009.Check(settingsTarget(t, json))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestCFG009_NoHooks_NoFinding(t *testing.T) {
	f := CFG009.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"],"deny":["Bash(rm *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when hooks absent, got %d", len(f))
	}
}

func TestCFG009_NoSettings_NoFinding(t *testing.T) {
	f := CFG009.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

func TestCFG009_CmdPercentVar(t *testing.T) {
	f := CFG009.Check(hookTarget(t, "echo %USERPROFILE% and %PATH%"))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for cmd %%VAR%%, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "%USERPROFILE%") {
		t.Errorf("expected message to name the cmd var, got: %s", f[0].Message)
	}
}

// Each agent ships its own project-root variable and its hooks are written
// against that one. The 2026-08-04 false-positive run found the Claude-only list
// firing on Zed's and Codex's equivalents in real repositories.
func TestCFG009_OtherAgentsProjectVarsAreSafe(t *testing.T) {
	for _, cmd := range []string{
		`cd "$ZED_WORKTREE_ROOT" && cargo test`,
		`cd "$ZED_MAIN_GIT_WORKTREE" && gwm bootstrap "$ZED_WORKTREE_ROOT"`,
		`bash ${PWD}/scripts/lint.sh`,
		`cd "$PWD" && npm test`,
	} {
		t.Run(cmd, func(t *testing.T) {
			if f := CFG009.Check(hookTarget(t, cmd)); len(f) != 0 {
				t.Errorf("expected no finding for %q, got %+v", cmd, f)
			}
		})
	}
}

// A non-framework variable alongside a safe one is still reported, and only it.
func TestCFG009_SafeVarDoesNotMaskOthers(t *testing.T) {
	f := CFG009.Check(hookTarget(t, `cd "$ZED_WORKTREE_ROOT" && run $USER_SUPPLIED`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "USER_SUPPLIED") || strings.Contains(f[0].Message, "ZED_WORKTREE_ROOT") {
		t.Errorf("only the unsafe variable should be named, got %q", f[0].Message)
	}
}

// A reference the shell expands as one argument and never parses again is not
// reported (#792); every way of getting it parsed again still is.
func TestCFG009_Quoting(t *testing.T) {
	tests := []struct {
		cmd  string
		want string // the variable reported, or "" for none
	}{
		// the hook from #792: stdin into f, f only ever in double quotes
		{`f=$(jq -r '.tool_input.file_path'); printf '%s' "$f" | grep -qE '\\.gitlab-ci\\.yml$' && "${CLAUDE_PLUGIN_ROOT}/bin/tool" "$f" || true`, ""},
		{`notify-send "$TOOL_OUTPUT"`, ""},
		{`cp "${SRC}" "${SRC}.bak"`, ""},
		{`run "$DIR/out.txt"`, ""},
		{`jq -n '$ENV.HOME'`, ""},
		{`notify-send $TOOL_OUTPUT`, "$TOOL_OUTPUT"},
		{`notify-send "x" $TOOL_OUTPUT`, "$TOOL_OUTPUT"},
		{`jq ".path == \"$f\""`, "$f"},
		{`python3 -c "print('$f')"`, "$f"},
		{`eval "$CMD"`, "$CMD"},
		{`sh -c "echo $f"`, "$f"},
		{`bash -lc 'echo $f'`, "$f"},
		{`printf '%s' "$f" | xargs sh -c 'rm $0'`, "$f"},
		{`"$CMD" --version`, "$CMD"},
		{`X=1 "$CMD"`, "$CMD"},
		{`true && "$CMD"`, "$CMD"},
		{`echo "$f`, "$f"},
		{`echo \$HOME is literal`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			f := CFG009.Check(hookTarget(t, tt.cmd))
			if tt.want == "" {
				if len(f) != 0 {
					t.Errorf("expected no finding, got %+v", f)
				}
				return
			}
			if len(f) != 1 || !strings.Contains(f[0].Message, tt.want) {
				t.Errorf("expected %s reported, got %+v", tt.want, f)
			}
		})
	}
}

// #935: framework and login variables, and a date(1) format, are not reported;
// a real cmd.exe variable and an agent-supplied one still are.
func TestCFG009_SkillDirHomeAndDateFormat(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want string // "" for no finding
	}{
		{`bash ${CLAUDE_SKILL_DIR}/scripts/check.sh`, ""},
		{`bash $HOME/.claude/hooks/log.sh`, ""},
		{`echo done >> log-$(date -u +%Y-%m-%dT%H:%M:%SZ).txt`, ""},
		{`date '+%Y-%m-%dT%H:%M'`, ""},
		{`echo %USERPROFILE%`, "%USERPROFILE%"},
		{`bash $CLAUDE_SKILL_DIR/run.sh $TOOL_OUTPUT`, "$TOOL_OUTPUT"},
	} {
		json := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":` + jsonQuote(tc.cmd) + `}]}]}}`
		f := CFG009.Check(settingsTarget(t, json))
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: want no finding, got %s", tc.cmd, f[0].Message)
		case tc.want != "" && (len(f) != 1 || !strings.Contains(f[0].Message, tc.want) || strings.Contains(f[0].Message, "CLAUDE_SKILL_DIR")):
			t.Errorf("%s: want one finding naming only %s, got %+v", tc.cmd, tc.want, f)
		}
	}
}
