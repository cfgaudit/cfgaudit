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

// Copilot's custom agents use the kebab-case key and a MAPPING of server name to
// config, the mirror image of Claude Code's camelCase key and list.
func TestCopilotAgentMCPServers(t *testing.T) {
	fm, ok := InstructionFrontmatter(`---
name: evil
description: test
tools: ["*"]
mcp-servers:
  pwn:
    type: local
    command: npx
    args: ["-y", "evil-mcp@latest"]
    env:
      TOKEN: "secret"
  remote:
    type: sse
    url: "http://mcp.example.test/sse"
    headers:
      Authorization: "Bearer token"
---
body
`)
	if !ok {
		t.Fatal("frontmatter did not parse")
	}
	servers := CopilotAgentMCPServers(fm)
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d: %v", len(servers), servers)
	}
	if got := servers["pwn"]; got.Command != "npx" || got.Type != "local" || got.Env["TOKEN"] != "secret" {
		t.Errorf("local server decoded wrong: %+v", got)
	}
	if got := servers["remote"]; got.URL != "http://mcp.example.test/sse" || got.Headers["Authorization"] != "Bearer token" {
		t.Errorf("remote server decoded wrong: %+v", got)
	}
}

// The two agent formats must not bleed into each other: Copilot reads
// `mcp-servers`, Claude Code reads `mcpServers`, and each decoder ignores the
// other's key and shape.
func TestAgentMCPKeysDoNotCrossOver(t *testing.T) {
	claudeShape := `---
name: x
description: x
mcpServers:
  - pwn:
      command: npx
---
body
`
	copilotShape := `---
name: x
description: x
mcp-servers:
  pwn:
    command: npx
---
body
`
	fmClaude, ok := InstructionFrontmatter(claudeShape)
	if !ok {
		t.Fatal("claude frontmatter did not parse")
	}
	if got := CopilotAgentMCPServers(fmClaude); len(got) > 0 {
		t.Errorf("the Copilot decoder must ignore camelCase mcpServers, got %v", got)
	}

	fmCopilot, ok := InstructionFrontmatter(copilotShape)
	if !ok {
		t.Fatal("copilot frontmatter did not parse")
	}
	if b := SubagentFrontmatterBlocks(fmCopilot); b != nil && len(b.MCPServers) > 0 {
		t.Errorf("the Claude decoder must ignore kebab-case mcp-servers, got %v", b.MCPServers)
	}
}

func TestCopilotAgentMCPServers_AbsentAndMalformed(t *testing.T) {
	for name, content := range map[string]string{
		"absent": "---\nname: x\ndescription: x\n---\nbody\n",
		"empty":  "---\nname: x\ndescription: x\nmcp-servers: {}\n---\nbody\n",
		"scalar": "---\nname: x\ndescription: x\nmcp-servers: \"github\"\n---\nbody\n",
	} {
		t.Run(name, func(t *testing.T) {
			fm, ok := InstructionFrontmatter(content)
			if !ok {
				t.Fatal("frontmatter did not parse")
			}
			if got := CopilotAgentMCPServers(fm); got != nil {
				t.Errorf("expected nil, got %v", got)
			}
		})
	}
}

func TestCopilotAgentMCPServers_NilFrontmatter(t *testing.T) {
	if got := CopilotAgentMCPServers(nil); got != nil {
		t.Errorf("expected nil for nil frontmatter, got %v", got)
	}
}

func TestSubagentFrontmatterBlocks_NilFrontmatter(t *testing.T) {
	if b := SubagentFrontmatterBlocks(nil); b != nil {
		t.Errorf("expected nil for nil frontmatter, got %+v", b)
	}
}
