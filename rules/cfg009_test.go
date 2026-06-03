package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG009_DollarVar(t *testing.T) {
	json := `{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify-send \"$TOOL_OUTPUT\""}]}]}}`
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
