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
	    "hashed": {"source": "owner/repo", "sourceType": "github", "computedHash": "515ba75178bd44875812d9a560bdf14651f86709f89cf1d4f209638e879807f3"},
	    "with-commit": {"source": "o/r", "commit": "868e7336d9115bf266504b7bb5e67bd0bded3fd247b9b5e14d2c7b6330da709c", "integrity": "sha256-91bf15bc"},
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
	if len(sl.Skills) != 5 {
		t.Fatalf("expected 5 skills, got %d", len(sl.Skills))
	}
	if got := sl.Skills["code-review"]; got.Source != "vercel-labs/agent-skills" || got.SourceType != "github" || got.Ref != "main" {
		t.Errorf("code-review parsed wrong: %+v", got)
	}
	if got := sl.Skills["hashed"]; got.ComputedHash == "" {
		t.Errorf("computedHash not decoded: %+v", got)
	}
	if got := sl.Skills["with-commit"]; got.Commit == "" || got.Integrity == "" {
		t.Errorf("commit/integrity not decoded: %+v", got)
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
