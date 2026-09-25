package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG109_ReportsTheFileAndReason(t *testing.T) {
	f := CFG109.Check(&Target{
		Scope:            finding.ScopeProject,
		UnreadableFile:   ".codex/config.toml",
		UnreadableReason: `toml: line 13: expected table but found []any`,
	})
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if f[0].File != ".codex/config.toml" {
		t.Errorf("expected the file to be named, got %q", f[0].File)
	}
	if !strings.Contains(f[0].Message, "expected table but found") {
		t.Errorf("expected the parser's reason in the message, got %q", f[0].Message)
	}
}

// The reason is optional: a file can be unreadable for a cause the parser does
// not spell out, and the finding still has to say which file it is.
func TestCFG109_WithoutReason(t *testing.T) {
	f := CFG109.Check(&Target{Scope: finding.ScopeProject, UnreadableFile: ".mcp.json"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if strings.Contains(f[0].Message, "The parser reported") {
		t.Errorf("expected no reason clause, got %q", f[0].Message)
	}
}

func TestCFG109_OrdinaryTarget_NoFinding(t *testing.T) {
	if f := CFG109.Check(settingsTarget(t, `{"permissions":{"deny":["Bash(rm *)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding for a target with no unreadable file, got %+v", f)
	}
	if f := CFG109.Check(nil); len(f) != 0 {
		t.Errorf("expected no finding for a nil target, got %+v", f)
	}
}

// Every other rule must ignore such a target: it carries a file name and a
// reason, nothing a rule could judge.
func TestCFG109_OtherRulesIgnoreAnUnreadableTarget(t *testing.T) {
	tgt := &Target{
		Scope:            finding.ScopeProject,
		UnreadableFile:   ".codex/config.toml",
		UnreadableReason: "toml: line 1",
	}
	for _, r := range All {
		if r.ID() == "CFG109" {
			continue
		}
		if f := r.Check(tgt); len(f) != 0 {
			t.Errorf("%s fired on an unreadable-file target: %+v", r.ID(), f)
		}
	}
}
