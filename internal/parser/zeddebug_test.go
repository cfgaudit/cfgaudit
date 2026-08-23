package parser

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The file is JSONC and the top level is an array, like .zed/tasks.json.
func TestParseZedDebug(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.json")
	body := `[
  // a comment, because Zed parses this with parse_json_with_comments
  {"label": "Debug server", "adapter": "CodeLLDB", "program": "./app",
   "build": {"command": "make", "args": ["-j8"], "cwd": "$ZED_WORKTREE_ROOT"}},
  {"label": "Debug tests", "adapter": "CodeLLDB", "build": "my build task"},
  {"adapter": "Delve"},
]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	z, err := ParseZedDebug(path)
	if err != nil {
		t.Fatalf("ParseZedDebug: %v", err)
	}
	if len(z.Scenarios) != 3 || z.Empty() {
		t.Fatalf("expected 3 scenarios, got %+v", z.Scenarios)
	}

	build := z.Scenarios[0].BuildTask()
	if build == nil || build.CommandLine() != "make -j8" {
		t.Errorf("embedded build task = %+v", build)
	}
	if z.Scenarios[0].BuildTaskRef() != "" {
		t.Errorf("the embedded form is not a reference: %q", z.Scenarios[0].BuildTaskRef())
	}

	if got := z.Scenarios[1].BuildTaskRef(); got != "my build task" {
		t.Errorf("reference = %q", got)
	}
	if z.Scenarios[1].BuildTask() != nil {
		t.Errorf("the string form is not an embedded task")
	}

	// Name falls back to the adapter, then to a placeholder.
	if got := z.Scenarios[2].Name(); got != "Delve" {
		t.Errorf("Name() = %q, want the adapter", got)
	}
	if z.Scenarios[2].BuildTask() != nil || z.Scenarios[2].BuildTaskRef() != "" {
		t.Errorf("absent build must yield neither form")
	}
}

func TestParseZedDebug_MissingAndMalformed(t *testing.T) {
	if _, err := ParseZedDebug(filepath.Join(t.TempDir(), "nope.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
	path := filepath.Join(t.TempDir(), "debug.json")
	if err := os.WriteFile(path, []byte(`{"not": "an array"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseZedDebug(path); err == nil {
		t.Errorf("expected a parse error for a non-array top level")
	}
}
