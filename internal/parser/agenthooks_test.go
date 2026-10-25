// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// writeAgentHooks writes a hooks file into a temp dir and returns its path.
func writeAgentHooks(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// #506: a real committed .github/hooks/hooks.json keys the table by hook NAME
// with an object value, rather than by event with an array. A typed map turned
// that file into a scan error, costing it every entry over the one cfgaudit
// cannot read.
func TestParseAgentHooks_UnmodelledEntryDoesNotCostTheFile(t *testing.T) {
	path := writeAgentHooks(t, `{
      "hooks": {
        "toolUseHook": {"event": "toolUse", "matcher": {"tool": "bash"},
                        "permissionDecision": "allow", "command": {"bash": "echo x"}},
        "sessionStart": [{"type": "command", "command": "echo hi"}]
      }
    }`)
	h, err := ParseAgentHooks(path)
	if err != nil {
		t.Fatalf("an unmodelled entry must not fail the parse: %v", err)
	}
	if len(h.Hooks) != 1 {
		t.Fatalf("expected only the modelled entry, got %+v", h.Hooks)
	}
	if got := h.Hooks["sessionStart"]; len(got) != 1 || got[0].Command != "echo hi" {
		t.Errorf("the modelled entry must still decode, got %+v", got)
	}
	if _, ok := h.Hooks["toolUseHook"]; ok {
		t.Errorf("an unmodelled shape must not be guessed at")
	}
}

// A file made entirely of the unmodelled shape yields no hooks and no error.
func TestParseAgentHooks_AllUnmodelled(t *testing.T) {
	path := writeAgentHooks(t, `{"hooks": {"a": {"event": "toolUse"}, "b": {"event": "postToolUse"}}}`)
	h, err := ParseAgentHooks(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(h.Hooks) != 0 {
		t.Errorf("expected no modelled hooks, got %+v", h.Hooks)
	}
}

// #923: CopilotAgentHooks returns nil for every frontmatter that carries no
// decodable hooks block, and the handlers for one that does.
func TestCopilotAgentHooks(t *testing.T) {
	if CopilotAgentHooks(nil) != nil {
		t.Error("nil frontmatter must give nil")
	}
	for _, fm := range []string{
		"---\nname: a\n---\nbody\n",                          // no hooks
		"---\nname: a\nhooks: [x, y]\n---\nbody\n",           // not a map
		"---\nname: a\nhooks: {}\n---\nbody\n",               // empty map
		"---\nname: a\nhooks:\n  PostToolUse: run\n---\nb\n", // event is not a handler list
	} {
		f, ok := InstructionFrontmatter(fm)
		if !ok {
			t.Fatalf("frontmatter did not parse: %q", fm)
		}
		if h := CopilotAgentHooks(f); h != nil {
			t.Errorf("%q: expected nil, got %+v", fm, h.Hooks)
		}
	}
	f, ok := InstructionFrontmatter("---\nname: a\nhooks:\n  PostToolUse:\n    - type: command\n      command: ./x.sh\n      osx: ./x-mac.sh\n---\nbody\n")
	if !ok {
		t.Fatal("frontmatter did not parse")
	}
	h := CopilotAgentHooks(f)
	if h == nil || len(h.Hooks["PostToolUse"]) != 1 {
		t.Fatalf("expected one PostToolUse handler, got %+v", h)
	}
	if got := h.Hooks["PostToolUse"][0].ShellCommands(); len(got) != 2 {
		t.Errorf("expected the command and the osx override, got %v", got)
	}
}
