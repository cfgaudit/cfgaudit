package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func devinPermissionTarget(allow []string) *Target {
	return &Target{
		Scope:     finding.ScopeProject,
		Devin:     &parser.DevinConfig{Permissions: &parser.Permissions{Allow: allow}},
		DevinFile: ".devin/config.json",
	}
}

// A pattern that constrains nothing auto-approves the whole category, in every
// documented kind.
func TestCFG104_Wildcards(t *testing.T) {
	f := CFG104.Check(devinPermissionTarget([]string{"Read(**)", "Write(*)", "Fetch(*)", "Exec(*)"}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn listing the wildcards, got %+v", f)
	}
	for _, want := range []string{"Read(**)", "Write(*)", "Fetch(*)", "Exec(*)"} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("message should list %q, got %q", want, f[0].Message)
		}
	}
}

// Devin matches a prefix as a whole word, so a bare privileged binary covers it
// with any arguments. One finding per rule, so each names its own binary.
func TestCFG104_PrivilegedBinaries(t *testing.T) {
	f := CFG104.Check(devinPermissionTarget([]string{"Exec(sudo)", "Exec(rm)", "Exec(chmod)", "Exec(chown)", "Exec(docker)"}))
	if len(f) != 5 {
		t.Fatalf("expected one finding per privileged binary, got %d: %+v", len(f), f)
	}
	for _, x := range f {
		if !strings.Contains(x.Message, "any arguments") {
			t.Errorf("message should explain prefix matching, got %q", x.Message)
		}
	}
}

// The measured non-findings: argument-constrained rules, bare interpreters and
// bare network binaries. Reporting the last two would fire on 15 of 51 real
// files, which is how people drive the tool.
func TestCFG104_NotReported(t *testing.T) {
	quiet := []string{
		"Exec(git status)", "Exec(npm run)", "Exec(git)", "Read(src/**)", "Write(docs/**)",
		"Exec(bash)", "Exec(python3)", "Exec(node)", "Exec(curl)", "Exec(ssh)", "Exec(scp)",
	}
	if f := CFG104.Check(devinPermissionTarget(quiet)); len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
}

// deny and ask are the narrowing direction; an absent block and a non-Devin
// target produce nothing.
func TestCFG104_NarrowingAndAbsent(t *testing.T) {
	tgt := &Target{
		Scope:     finding.ScopeProject,
		Devin:     &parser.DevinConfig{Permissions: &parser.Permissions{Deny: []string{"Exec(sudo)"}, Ask: []string{"Write(**)"}}},
		DevinFile: ".devin/config.json",
	}
	if f := CFG104.Check(tgt); len(f) != 0 {
		t.Errorf("deny/ask must not fire, got %+v", f)
	}
	if f := CFG104.Check(&Target{Devin: &parser.DevinConfig{}, DevinFile: ".devin/config.json"}); len(f) != 0 {
		t.Errorf("absent permissions, got %+v", f)
	}
	if f := CFG104.Check(&Target{}); len(f) != 0 {
		t.Errorf("non-Devin target, got %+v", f)
	}
}

// The message states the limit of what a committed rule does: it removes the
// prompt for someone who has not denied it, and does not beat someone who has.
func TestCFG104_MessageStatesTheDenyLimit(t *testing.T) {
	f := CFG104.Check(devinPermissionTarget([]string{"Exec(sudo)"}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	for _, want := range []string{"has not written their own deny", "deny is evaluated first"} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("message should contain %q, got %q", want, f[0].Message)
		}
	}
}
