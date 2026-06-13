package parser

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSkillsLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	body := `{
	  "version": 3,
	  "unknownTopLevel": {"ignored": true},
	  "skills": {
	    "code-review": {"source": "vercel-labs/agent-skills", "sourceType": "github", "ref": "main", "skillPath": "review"},
	    "local-helper": {"source": "./skills/helper", "sourceType": "local"},
	    "extra": {"source": "owner/repo", "futureField": 1}
	  }
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sl, err := ParseSkillsLock(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sl.Skills) != 3 {
		t.Fatalf("expected 3 skills, got %d", len(sl.Skills))
	}
	if got := sl.Skills["code-review"]; got.Source != "vercel-labs/agent-skills" || got.SourceType != "github" || got.Ref != "main" {
		t.Errorf("code-review parsed wrong: %+v", got)
	}
	if sl.Skills["local-helper"].SourceType != "local" {
		t.Errorf("local-helper sourceType wrong: %+v", sl.Skills["local-helper"])
	}
}

func TestParseSkillsLock_Missing(t *testing.T) {
	_, err := ParseSkillsLock(filepath.Join(t.TempDir(), "skills-lock.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestParseSkillsLock_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	if err := os.WriteFile(path, []byte(`{"skills": {`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSkillsLock(path); err == nil {
		t.Error("expected parse error for malformed JSON")
	}
}
