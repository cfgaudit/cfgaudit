package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func skillsLockTarget(skills map[string]parser.SkillEntry) *Target {
	return &Target{
		Scope:          finding.ScopeProject,
		SkillsLock:     &parser.SkillsLock{Skills: skills},
		SkillsLockFile: "skills-lock.json",
	}
}

func TestCFG074_UnpinnedBranch_Warn(t *testing.T) {
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"review": {Source: "vercel-labs/agent-skills", SourceType: "github", Ref: "main"},
	})
	f := CFG074.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "skills.review") || !strings.Contains(f[0].Message, "vercel-labs/agent-skills") {
		t.Errorf("expected alias + source in message, got %q", f[0].Message)
	}
	if !strings.Contains(f[0].Message, "branch/tag") {
		t.Errorf("expected branch/tag reason, got %q", f[0].Message)
	}
}

func TestCFG074_NoRef_Warn(t *testing.T) {
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"x": {Source: "owner/repo", SourceType: "github"},
	})
	f := CFG074.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for missing ref, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "does not pin a ref") {
		t.Errorf("expected no-ref reason, got %q", f[0].Message)
	}
}

func TestCFG074_AbsentSourceType_Warn(t *testing.T) {
	// sourceType absent but a remote slug present → still a remote trust edge.
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"x": {Source: "owner/repo", Ref: "v1.2.0"},
	})
	if f := CFG074.Check(tgt); len(f) != 1 {
		t.Fatalf("expected 1 Warn for tag ref, got %+v", f)
	}
}

func TestCFG074_PinnedSHA_NoFinding(t *testing.T) {
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"x": {Source: "owner/repo", SourceType: "github", Ref: "5f2e8c1a9b4d7e3f0a6c8b1d2e4f6a8c0b3d5e7f"},
	})
	if f := CFG074.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding for full SHA pin, got %+v", f)
	}
}

func TestCFG074_LocalSource_NoFinding(t *testing.T) {
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"helper": {Source: "./skills/helper", SourceType: "local"},
		"empty":  {SourceType: "github"}, // no source → no trust edge
	})
	if f := CFG074.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding for local/empty sources, got %+v", f)
	}
}

func TestCFG074_MultipleEntries_SortedAndCounted(t *testing.T) {
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"zeta":  {Source: "o/z", SourceType: "github", Ref: "main"},
		"alpha": {Source: "o/a", SourceType: "github"},
		"pinned": {Source: "o/p", SourceType: "github",
			Ref: "5f2e8c1a9b4d7e3f0a6c8b1d2e4f6a8c0b3d5e7f"},
	})
	f := CFG074.Check(tgt)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (zeta, alpha), got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "skills.alpha") || !strings.Contains(f[1].Message, "skills.zeta") {
		t.Errorf("expected alphabetical order, got %q then %q", f[0].Message, f[1].Message)
	}
}

func TestCFG074_NilTarget(t *testing.T) {
	if f := CFG074.Check(nil); f != nil {
		t.Errorf("expected nil for nil target, got %+v", f)
	}
	if f := CFG074.Check(&Target{}); f != nil {
		t.Errorf("expected nil when no skills-lock, got %+v", f)
	}
}
