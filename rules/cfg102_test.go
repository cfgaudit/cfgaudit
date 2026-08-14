package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func collisionTarget(name string, dirs ...string) *Target {
	var entries []parser.SkillFileEntry
	for _, d := range dirs {
		entries = append(entries, parser.SkillFileEntry{Dir: d, Name: name, Path: filepath.Join(d, "SKILL.md")})
	}
	return &Target{
		Scope:              finding.ScopeProject,
		SkillCollisionRoot: filepath.Join(".github", "skills"),
		SkillCollisions:    map[string][]parser.SkillFileEntry{name: entries},
	}
}

// Measured on Copilot CLI 1.0.80: the alphabetically first directory wins and
// the other is dropped with no warning.
func TestCFG102_ReportsTheDroppedCopy(t *testing.T) {
	got := onlyFinding(t, CFG102.Check(collisionTarget("deploy", "aaa-shadow", "zzz-real")), finding.Warn)
	for _, want := range []string{"deploy", "aaa-shadow", "zzz-real", "silently dropped"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
	// The finding is attributed to the copy that actually loads. Built with
	// filepath.Join so the expectation matches the OS-native separator the
	// scanner reports everywhere else, rather than assuming forward slashes.
	want := filepath.Join(".github", "skills", "aaa-shadow", "SKILL.md")
	if got.File != want {
		t.Errorf("file = %q, want %q (the winning copy)", got.File, want)
	}
}

// Three copies name both losers.
func TestCFG102_ThreeCopies(t *testing.T) {
	got := onlyFinding(t, CFG102.Check(collisionTarget("deploy", "a", "b", "c")), finding.Warn)
	for _, want := range []string{`"b", "c"`, `"a", "b", "c"`} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
}

// Several colliding names are reported separately, in a stable order.
func TestCFG102_MultipleNames(t *testing.T) {
	tg := collisionTarget("deploy", "a", "b")
	tg.SkillCollisions["build"] = []parser.SkillFileEntry{{Dir: "x", Name: "build"}, {Dir: "y", Name: "build"}}
	f := CFG102.Check(tg)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %+v", f)
	}
	if !strings.Contains(f[0].Message, `"build"`) {
		t.Errorf("expected a stable alphabetical order, got %q first", f[0].Message)
	}
}

func TestCFG102_NothingToReport(t *testing.T) {
	if f := CFG102.Check(collisionTarget("deploy", "only-one")); len(f) != 0 {
		t.Errorf("a single copy is not a collision, got %+v", f)
	}
	if f := CFG102.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no findings without an index, got %+v", f)
	}
}
