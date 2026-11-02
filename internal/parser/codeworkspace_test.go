// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeWorkspace(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.code-workspace")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseCodeWorkspace988(t *testing.T) {
	w, err := ParseCodeWorkspace(writeWorkspace(t, `{
  // comment
  "settings": { "editor.tabSize": 2, "mcp": { "servers": { "a": { "command": "npx" } } } },
  "tasks": { "version": "2.0.0", "tasks": [ { "label": "t", "command": "make" }, ] },
}`))
	if err != nil {
		t.Fatal(err)
	}
	if w.Settings == nil || w.Tasks == nil || len(w.Tasks.Tasks) != 1 || w.MCPServers["a"].Command != "npx" {
		t.Errorf("unexpected workspace: %+v", w)
	}

	// Blocks that are absent, empty or not objects yield nothing.
	for _, content := range []string{
		"", "  // only a comment\n",
		`{"folders": [{"path": "."}]}`,
		`{"settings": {}, "tasks": {"tasks": []}}`,
		`{"settings": [], "tasks": "x"}`,
		`{"settings": {"mcp": true}}`,
		`{"settings": {"mcp": {"servers": {}}}}`,
	} {
		w, err := ParseCodeWorkspace(writeWorkspace(t, content))
		if err != nil || w.Tasks != nil || len(w.MCPServers) != 0 {
			t.Errorf("%q: got %+v, %v", content, w, err)
		}
	}
}

func TestParseCodeWorkspace988_Errors(t *testing.T) {
	if _, err := ParseCodeWorkspace(filepath.Join(t.TempDir(), "missing.code-workspace")); err == nil {
		t.Error("expected an error for a missing file")
	}
	for _, content := range []string{
		`{"folders": [ {"path": "."} ] {`,
		`{"settings": {"mcp": {"servers": []}}}`,
		`{"tasks": {"tasks": {}}}`,
	} {
		if _, err := ParseCodeWorkspace(writeWorkspace(t, content)); err == nil {
			t.Errorf("%q: expected a parse error", content)
		}
	}
}
