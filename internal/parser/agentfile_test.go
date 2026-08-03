package parser

import "testing"

func subagentBlocks(t *testing.T, content string) *SubagentBlocks {
	t.Helper()
	fm, ok := InstructionFrontmatter(content)
	if !ok {
		t.Fatalf("frontmatter did not parse:\n%s", content)
	}
	return SubagentFrontmatterBlocks(fm)
}

// The documented hooks: shape is the settings.json one — event → matcher groups
// → {type, command} handlers.
func TestSubagentFrontmatterBlocks_Hooks(t *testing.T) {
	b := subagentBlocks(t, `---
name: code-reviewer
description: Review code changes
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "./scripts/validate-command.sh"
  PostToolUse:
    - matcher: "Edit|Write"
      hooks:
        - type: command
          command: "./scripts/run-linter.sh"
---
body
`)
	if b == nil {
		t.Fatal("expected decoded blocks")
	}
	if len(b.Hooks) != 2 {
		t.Fatalf("expected 2 events, got %d (%v)", len(b.Hooks), b.Hooks)
	}
	pre := b.Hooks["PreToolUse"]
	if len(pre) != 1 || pre[0].Matcher != "Bash" {
		t.Fatalf("PreToolUse group not decoded: %+v", pre)
	}
	if len(pre[0].Hooks) != 1 || pre[0].Hooks[0].Command != "./scripts/validate-command.sh" {
		t.Errorf("PreToolUse command not decoded: %+v", pre[0].Hooks)
	}
	if got := b.Hooks["PostToolUse"][0].Hooks[0].Command; got != "./scripts/run-linter.sh" {
		t.Errorf("PostToolUse command = %q", got)
	}
}

// mcpServers is a LIST of single-key mappings (inline definitions) and bare
// strings (references to servers configured elsewhere). Only the inline
// definitions carry a command/url/headers of their own.
func TestSubagentFrontmatterBlocks_InlineMCPServers(t *testing.T) {
	b := subagentBlocks(t, `---
name: browser-tester
description: Tests features in a real browser
mcpServers:
  - playwright:
      type: stdio
      command: npx
      args: ["-y", "@playwright/mcp@latest"]
  - remote:
      type: http
      url: "http://mcp.example.test/sse"
      headers:
        Authorization: "Bearer token"
  - github
---
body
`)
	if b == nil {
		t.Fatal("expected decoded blocks")
	}
	if len(b.MCPServers) != 2 {
		t.Fatalf("expected 2 inline servers (the bare string is a reference), got %d: %v", len(b.MCPServers), b.MCPServers)
	}
	pw, ok := b.MCPServers["playwright"]
	if !ok {
		t.Fatal("playwright not decoded")
	}
	if pw.Command != "npx" || len(pw.Args) != 2 || pw.Args[1] != "@playwright/mcp@latest" {
		t.Errorf("playwright decoded wrong: %+v", pw)
	}
	rem := b.MCPServers["remote"]
	if rem.URL != "http://mcp.example.test/sse" || rem.Type != "http" {
		t.Errorf("remote decoded wrong: %+v", rem)
	}
	if rem.Headers["Authorization"] != "Bearer token" {
		t.Errorf("remote headers decoded wrong: %+v", rem.Headers)
	}
	if _, ok := b.MCPServers["github"]; ok {
		t.Error("a bare string entry is a reference to a server configured elsewhere and must not become a server definition")
	}
}

// Claude Code 2.1.220 ignores a mapping-shaped mcpServers in agent frontmatter
// (verified by running a subagent declaring a server each way and observing which
// process actually launched). Decoding it would report a server that never
// connects.
func TestSubagentFrontmatterBlocks_MappingShapedMCPServersIgnored(t *testing.T) {
	b := subagentBlocks(t, `---
name: bad
description: mapping shape, not the documented list
mcpServers:
  playwright:
    type: stdio
    command: npx
    args: ["-y", "@playwright/mcp@latest"]
---
body
`)
	if b != nil && len(b.MCPServers) > 0 {
		t.Errorf("mapping-shaped mcpServers must not decode, got %v", b.MCPServers)
	}
}

func TestSubagentFrontmatterBlocks_AbsentAndMalformed(t *testing.T) {
	cases := map[string]string{
		"no blocks": `---
name: plain
description: only flat fields
tools: Read, Grep
---
body
`,
		"empty hooks block": `---
name: empty
description: hooks key with no events
hooks: {}
---
body
`,
		"event with no groups": `---
name: empty-event
description: event key with an empty list
hooks:
  PreToolUse: []
---
body
`,
		"hooks wrong type": `---
name: wrong
description: hooks is a scalar
hooks: "PreToolUse"
---
body
`,
		"mcpServers wrong type": `---
name: wrong
description: mcpServers is a scalar
mcpServers: "github"
---
body
`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			fm, ok := InstructionFrontmatter(content)
			if !ok {
				t.Fatal("frontmatter did not parse")
			}
			if b := SubagentFrontmatterBlocks(fm); b != nil {
				t.Errorf("expected nil blocks, got %+v", b)
			}
		})
	}
}

func TestSubagentFrontmatterBlocks_NilFrontmatter(t *testing.T) {
	if b := SubagentFrontmatterBlocks(nil); b != nil {
		t.Errorf("expected nil for nil frontmatter, got %+v", b)
	}
}
