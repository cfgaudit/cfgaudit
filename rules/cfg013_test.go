package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// projectTarget creates a ScopeProject Target rooted at dir.
func projectTarget(dir string) *Target {
	return &Target{
		SettingsFile: filepath.Join(dir, ".claude", "settings.json"),
		ProjectDir:   dir,
		Scope:        finding.ScopeProject,
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCFG013_NoLocalFiles_NoFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 0 {
		t.Errorf("expected no finding when no local files exist, got %d: %+v", len(f), f)
	}
}

func TestCFG013_LocalSettingsLocal_NotIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, ".claude/settings.local.json") {
		t.Errorf("message should name the file, got: %s", f[0].Message)
	}
}

func TestCFG013_BothLocalFiles_TwoIndependentFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "personal notes")
	writeFile(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (one per local file), got %d", len(f))
	}
}

func TestCFG013_NoGitignoreAtAll(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "personal notes")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when .gitignore is absent, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "CLAUDE.local.md") {
		t.Errorf("message should mention CLAUDE.local.md, got: %s", f[0].Message)
	}
}

func TestCFG013_GitignoreLiteralPath_NoFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), ".claude/settings.local.json\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 0 {
		t.Errorf("expected no finding when literal path is in .gitignore, got: %+v", f)
	}
}

func TestCFG013_GitignoreWildcardPatterns_NoFinding(t *testing.T) {
	cases := map[string]string{
		"trailing-wildcard":      ".claude/settings.local.*",
		"mid-segment-wildcard":   ".claude/*.local.*",
		"basename-wildcard":      "*.local.json",
		"basename-prefix-suffix": "settings.local.*",
	}
	for name, pattern := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
			writeFile(t, filepath.Join(dir, ".gitignore"), pattern+"\n")
			f := CFG013.Check(projectTarget(dir))
			if len(f) != 0 {
				t.Errorf("pattern %q should cover .claude/settings.local.json, got %d findings: %+v",
					pattern, len(f), f)
			}
		})
	}
}

func TestCFG013_GitignoreCoversClaudeLocalMd(t *testing.T) {
	cases := map[string]string{
		"literal":            "CLAUDE.local.md",
		"basename-wildcard":  "*.local.md",
		"prefix-wildcard":    "CLAUDE.local.*",
	}
	for name, pattern := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "x")
			writeFile(t, filepath.Join(dir, ".gitignore"), pattern+"\n")
			f := CFG013.Check(projectTarget(dir))
			if len(f) != 0 {
				t.Errorf("pattern %q should cover CLAUDE.local.md, got %d findings: %+v",
					pattern, len(f), f)
			}
		})
	}
}

func TestCFG013_GitignoreNegation_RefiresFinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".claude", "settings.local.json"), "{}")
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.local.json\n!.claude/settings.local.json\n")
	f := CFG013.Check(projectTarget(dir))
	if len(f) != 1 {
		t.Fatalf("expected negation to override the ignore, got %d findings", len(f))
	}
}

func TestCFG013_OnlyFiresOnProjectScope(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "CLAUDE.local.md"), "x")
	// ProjectLocal: must not fire (avoids double emission when both settings files exist).
	tgt := projectTarget(dir)
	tgt.Scope = finding.ScopeProjectLocal
	if f := CFG013.Check(tgt); len(f) != 0 {
		t.Errorf("CFG013 should not fire on ScopeProjectLocal, got %+v", f)
	}
	// User: must not fire (no project dir concept).
	tgt.Scope = finding.ScopeUser
	if f := CFG013.Check(tgt); len(f) != 0 {
		t.Errorf("CFG013 should not fire on ScopeUser, got %+v", f)
	}
}

func TestCFG013_NoProjectDir_NoFinding(t *testing.T) {
	if f := CFG013.Check(&Target{Scope: finding.ScopeProject}); len(f) != 0 {
		t.Errorf("expected no finding when ProjectDir is empty, got %+v", f)
	}
}
