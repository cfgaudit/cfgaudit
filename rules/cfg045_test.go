package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG045_DisabledByDefault(t *testing.T) {
	// Without t.ShellCheck the rule must not run (and must not exec anything).
	tg := settingsTarget(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo $X"}]}]}}`)
	if f := CFG045.Check(tg); f != nil {
		t.Errorf("expected nil when ShellCheck disabled, got %+v", f)
	}
}

func TestCFG045_NoSettings_NoFinding(t *testing.T) {
	if f := CFG045.Check(&Target{ShellCheck: true}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}

func TestParseShellcheck(t *testing.T) {
	out := []byte(`[{"line":2,"column":6,"level":"info","code":2086,"message":"Double quote to prevent globbing and word splitting."}]`)
	cs := parseShellcheck(out)
	if len(cs) != 1 || cs[0].Code != 2086 || cs[0].Level != "info" {
		t.Fatalf("unexpected parse: %+v", cs)
	}
	if parseShellcheck([]byte("not json")) != nil {
		t.Errorf("expected nil for invalid JSON")
	}
}

func TestScSeverity(t *testing.T) {
	cases := map[string]finding.Severity{
		"error":   finding.Error,
		"warning": finding.Warn,
		"info":    finding.Info,
		"style":   finding.Info,
		"weird":   finding.Info,
	}
	for level, want := range cases {
		if got := scSeverity(level); got != want {
			t.Errorf("scSeverity(%q) = %s, want %s", level, got, want)
		}
	}
}

func TestCFG045_HappyPath(t *testing.T) {
	if !ShellcheckAvailable() {
		t.Skip("shellcheck binary not installed")
	}
	tg := settingsTarget(t, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"rm $FILE"}]}]}}`)
	tg.ShellCheck = true
	f := CFG045.Check(tg)
	if len(f) == 0 {
		t.Fatal("expected shellcheck to flag the unquoted $FILE")
	}
	found := false
	for _, fi := range f {
		if fi.RuleID == "CFG045" && strings.Contains(fi.Message, "SC2086") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an SC2086 finding, got %+v", f)
	}
}
