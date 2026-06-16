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

func TestCFG074_NoIntegrityBranchOnly_Warn(t *testing.T) {
	// a bare branch ref with no content hash → unverified, warns.
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
	if !strings.Contains(f[0].Message, "no integrity pin") {
		t.Errorf("expected no-integrity reason, got %q", f[0].Message)
	}
}

func TestCFG074_NoIntegrityFields_Warn(t *testing.T) {
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"x": {Source: "owner/repo", SourceType: "github"},
	})
	f := CFG074.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for entry with no integrity, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "no integrity pin") {
		t.Errorf("expected no-integrity reason, got %q", f[0].Message)
	}
}

func TestCFG074_TagRefNoHash_Warn(t *testing.T) {
	// a tag ref ("v1.2.0") is not a full SHA and carries no content hash → warns.
	tgt := skillsLockTarget(map[string]parser.SkillEntry{
		"x": {Source: "owner/repo", Ref: "v1.2.0"},
	})
	if f := CFG074.Check(tgt); len(f) != 1 {
		t.Fatalf("expected 1 Warn for tag ref without hash, got %+v", f)
	}
}

func TestCFG074_Pinned_NoFinding(t *testing.T) {
	// Every real-world integrity mechanism must suppress the finding.
	sha40 := "5f2e8c1a9b4d7e3f0a6c8b1d2e4f6a8c0b3d5e7f"
	sha64 := "868e7336d9115bf266504b7bb5e67bd0bded3fd247b9b5e14d2c7b6330da709c"
	cases := map[string]parser.SkillEntry{
		"ref-sha40":    {Source: "o/r", SourceType: "github", Ref: sha40},
		"commit-sha40": {Source: "o/r", SourceType: "github", Ref: "main", Commit: sha40},
		"commit-sha64": {Source: "o/r", SourceType: "github", Ref: "refs/tags/v1", Commit: sha64},
		"computedHash": {Source: "o/r", SourceType: "github", ComputedHash: "515ba75178bd44875812d9a560bdf14651f86709f89cf1d4f209638e879807f3"},
		"integrity":    {Source: "o/r", SourceType: "github", Ref: "refs/tags/v1.26.0", Integrity: "sha256-91bf15bc972ed8192121f6311e3edf814f35365494a4f0db88b80b79333ff624"},
	}
	for name, e := range cases {
		if f := CFG074.Check(skillsLockTarget(map[string]parser.SkillEntry{name: e})); len(f) != 0 {
			t.Errorf("%s: expected no finding (content is pinned), got %+v", name, f)
		}
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
