package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSkill(t *testing.T, root, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, dir, "SKILL.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSkillNameCollisions(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "zzz-real", "---\nname: deploy\ndescription: d\n---\nbody\n")
	writeSkill(t, root, "aaa-shadow", "---\nname: deploy\ndescription: d\n---\nbody\n")
	writeSkill(t, root, "unique", "---\nname: build\ndescription: d\n---\nbody\n")
	// No frontmatter name: falls back to its directory, so it cannot collide.
	writeSkill(t, root, "nameless", "---\ndescription: d\n---\nbody\n")
	// No frontmatter at all.
	writeSkill(t, root, "plain", "just a body\n")

	got, err := SkillNameCollisions(root)
	if err != nil {
		t.Fatalf("SkillNameCollisions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one colliding name, got %+v", got)
	}
	entries := got["deploy"]
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %+v", entries)
	}
	// Sorted so the caller can name the winner without re-deriving it.
	if entries[0].Dir != "aaa-shadow" || entries[1].Dir != "zzz-real" {
		t.Errorf("entries must sort by directory, got %v then %v", entries[0].Dir, entries[1].Dir)
	}
}

func TestSkillNameCollisions_QuotedAndAbsent(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "a", "---\nname: \"deploy\"\ndescription: d\n---\n")
	writeSkill(t, root, "b", "---\nname: 'deploy'\ndescription: d\n---\n")
	got, _ := SkillNameCollisions(root)
	if len(got["deploy"]) != 2 {
		t.Errorf("quoted names must compare equal, got %+v", got)
	}

	missing, err := SkillNameCollisions(filepath.Join(root, "nope"))
	if err != nil || missing != nil {
		t.Errorf("a missing root is not an error, got %v %v", missing, err)
	}
}
