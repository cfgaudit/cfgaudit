// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The fuzz targets below feed arbitrary bytes to every parser. Each one parses
// files committed to a repository the user did not write, so a crafted file
// that panics would abort the scan and hide every other finding. A parse error
// is fine; a panic or a hang is the bug.
//
// Run one locally with, for example:
//
//	go test ./internal/parser -run '^$' -fuzz '^FuzzPathParsers$' -fuzztime 60s
//
// A failing input is written to testdata/fuzz/<Target>/ and replays as a
// regular test case on every `go test` from then on.

// pathParsers lists every parser that reads a whole file. The file name is
// passed through so parsers that branch on it see a realistic one.
var pathParsers = []struct {
	file  string
	parse func(path string)
}{
	{"settings.json", func(p string) { _, _ = ParseSettings(p) }},
	{".mcp.json", func(p string) {
		_, _ = ParseMCPConfig(p)
		_, _ = UnwrappedMCPServers(p)
	}},
	{"hooks.json", func(p string) {
		_, _ = ParseAgentHooks(p)
		_, _ = ParseCodexHooksJSON(p)
		_, _ = ParseContinueHooks(p)
		_, _ = ParseGrokHooks(p)
		_, _ = ParseDevinHooksV1(p)
	}},
	{"config.toml", func(p string) {
		if c, err := ParseCodexConfig(p); err == nil {
			c.ApplyProjectLayerDenylist()
			_ = c.HookEvents()
			_ = c.UsesAutoReviewer()
			_ = c.WorkspaceWriteTableApplies()
			_ = c.PluginMCPApprovals()
			_ = c.MCPServerMap()
			_ = c.AppApprovals()
			_ = c.AppToolApprovals()
			_ = c.AppReviewers()
			_ = c.SelectedPermissionProfiles()
		}
		if c, err := ParseGrokConfig(p); err == nil {
			_ = c.MCPServerMap()
		}
	}},
	{"config.yaml", func(p string) {
		if c, err := ParseContinueConfig(p); err == nil {
			_ = c.MCPServerMap()
		}
	}},
	{"mcpServers.json", func(p string) { _, _ = ParseContinueMCPJSON(p) }},
	{"cli.json", func(p string) { _, _ = ParseCursorCLIConfig(p) }},
	{"sandbox.json", func(p string) { _, _ = ParseCursorSandbox(p) }},
	{"permissions.json", func(p string) { _, _ = ParseCursorPermissions(p) }},
	{"config.json", func(p string) { _, _ = ParseDevinConfig(p) }},
	{".env", func(p string) { _, _ = ParseDotEnv(p) }},
	{"gemini-settings.json", func(p string) { _, _ = ParseGeminiSettings(p) }},
	{"qwen-settings.json", func(p string) { _, _ = ParseQwenSettings(p) }},
	{"copilot-settings.json", func(p string) {
		if c, err := ParseCopilotSettings(p); err == nil {
			_ = c.InlineHooks()
			_ = c.HooksDisabled()
		}
	}},
	{"lsp.json", func(p string) {
		_, _ = ParseGrokLSP(p)
		_, _ = ParseCopilotLSP(p)
	}},
	{"kimi.plugin.json", func(p string) { _, _ = ParseKimiPluginManifest(p) }},
	{"plugin.json", func(p string) {
		if m, err := ParsePluginManifest(p); err == nil && m != nil {
			raw, _ := json.Marshal(m)
			_ = ManifestPaths(raw)
		}
	}},
	{"marketplace.json", func(p string) { _, _ = ParseMarketplace(p) }},
	{"opencode.json", func(p string) {
		if c, err := ParseOpenCodeConfig(p); err == nil {
			_ = c.LSPEntries()
			_ = c.FormatterEntries()
			_ = c.MCPServerMap()
			_ = c.PermissionBlocks()
		}
	}},
	{"scheduled_tasks.json", func(p string) { _, _ = ParseScheduledTasks(p) }},
	{"skills-lock.json", func(p string) { _, _ = ParseSkillsLock(p) }},
	{".claudeignore", func(p string) {
		if lines, err := ParseIgnore(p); err == nil {
			_ = HasPattern(lines, ".env")
		}
	}},
	{"tasks.json", func(p string) {
		_, _ = ParseVSCodeTasks(p)
		_, _ = ParseZedTasks(p)
	}},
	{"vscode-settings.json", func(p string) { _, _ = ParseVSCodeSettings(p) }},
	{"zed-settings.json", func(p string) { _, _ = ParseZedSettings(p) }},
	{"debug.json", func(p string) { _, _ = ParseZedDebug(p) }},
}

// FuzzPathParsers writes the input to a file and runs every file parser on it.
func FuzzPathParsers(f *testing.F) {
	for _, seed := range []string{
		``,
		`{}`,
		"\xEF\xBB\xBF{}",
		`{"mcpServers":{"a":{"command":"npx","args":["-y","x"],"env":{"K":"v"}}}}`,
		`{"servers":{"a":{"type":"http","url":"http://x"}}}`,
		`{"permissions":{"allow":["Bash(*)"],"deny":["Read(.env)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"x"}]}]}}`,
		`{"hooks":{"preToolUse":[{"command":"x"}]},"version":1}`,
		"// c\n{\"a\": [1, 2,], /* b */ \"s\": \"//not a comment\",}",
		"approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n[mcp_servers.a]\ncommand = \"npx\"\n[features]\nhooks = true\n",
		"[guardian]\nmode = \"off\"\n[[hooks.PreToolUse]]\ncommand = \"x\"\n",
		"name: c\nmcpServers:\n  - name: a\n    command: npx\nrules:\n  - plain rule\n  - name: r\n    rule: text\n",
		"KEY=value\nexport TOKEN='x'\n# comment\nMULTI=\"a\\nb\"\n",
		"*.env\n!keep\n# c\n",
		`{"tasks":[{"label":"a","command":"x","runOptions":{"runOn":"folderOpen"}}]}`,
		`[{"label":"a","command":"x","shell":{"program":"bash"}}]`,
		`{"context_servers":{"a":{"command":{"path":"x"}}},"terminal":{"shell":{"with_arguments":{"program":"x"}}}}`,
		`{"name":"p","hooks":"./h.json","mcpServers":{"a":{"command":"x"}},"commands":["./c"]}`,
		`{"plugins":[{"name":"p","source":{"source":"github","repo":"o/r"}}]}`,
		`{"$schema":"https://opencode.ai/config.json","mcp":{"a":{"type":"local","command":["x"]}},"permission":{"bash":"allow"},"agent":{"b":{"permission":{"edit":"allow"}}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		for _, p := range pathParsers {
			path := filepath.Join(dir, p.file)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			p.parse(path)
		}
	})
}

// FuzzStripJSONC checks the hand-written comment stripper beyond not panicking:
// its output is never longer than its input (it only drops bytes, re-emitting
// at most the newline that ended a // comment), and input without comment
// markers or commas passes through unchanged apart from a leading BOM.
func FuzzStripJSONC(f *testing.F) {
	for _, seed := range []string{
		``, `/`, `/*`, `"\`, `"\"`, `//`, "\xEF\xBB\xBF",
		`{"a": 1, // c` + "\n" + `}`,
		`{"a": "/* not */", /* yes */ "b": [1,],}`,
		`{"a": "\\", "b": "\"//\""}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out := stripJSONC(data)
		if len(out) > len(data) {
			t.Fatalf("output grew: %d > %d bytes", len(out), len(data))
		}
		if !bytes.ContainsAny(data, "/,") {
			want := bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
			if !bytes.Equal(out, want) {
				t.Fatalf("input without comments or commas changed:\n in: %q\nout: %q", data, out)
			}
		}
	})
}

// FuzzMarkdownInstructions covers everything that reads a Markdown instruction
// file (SKILL.md, commands, subagents): the frontmatter decoder and the
// helpers built on it, plus the skill shell-command extractor.
func FuzzMarkdownInstructions(f *testing.F) {
	for _, seed := range []string{
		``,
		"---\n---\n",
		"---\nname: a\n",
		"---\nname: a\nallowed-tools: Bash, Read\n---\nbody\n",
		"---\nallowed-tools:\n  - Bash(git:*)\n  - Read\nmodel: x\n---\n",
		"---\nmcpServers:\n  a:\n    command: npx\n  - b\n---\n",
		"---\nkind: remote\nagent_card_url: https://x\nauth:\n  type: apiKey\n  key: k\n---\n",
		"---\npermission:\n  bash: allow\n  edit: {\"*\": ask}\n---\n",
		"---\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: x\n---\n",
		"Run !`git status` then\n```!\nrm -rf /\n```\n",
		"---\n&a [*a]\n---\n",
		"\xEF\xBB\xBF---\r\nname: a\r\n---\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		_ = SkillShellCommands(content)
		_ = OpenCodeAgentPermission(content)
		_ = DevinSkillPermissions(content)
		fm, ok := InstructionFrontmatter(content)
		if !ok {
			return
		}
		_ = fm.StringList("allowed-tools")
		_ = SubagentFrontmatterBlocks(fm)
		_ = CopilotAgentMCPServers(fm)
		_ = ParseSubagentExecutor(fm)
		_ = GeminiAgentMCPServers(fm)
		_ = GeminiAgentRemote(fm)
	})
}

// FuzzTerminalBase covers the Cursor terminal allowlist entry normaliser.
func FuzzTerminalBase(f *testing.F) {
	for _, seed := range []string{``, `ls`, `Shell(git:*)`, `/usr/bin/env bash -c`, `"quoted cmd"`, `a:b:c`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, entry string) {
		_ = TerminalBase(entry)
	})
}
