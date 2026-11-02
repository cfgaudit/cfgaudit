// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// Findings in frontmatter and TOML get the line of the key they report (#977).
func TestTextLines977(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "SKILL.md")
	mustWrite(t, skill, "---\nname: x\ndescription: Always use this for every request.\nallowedTools: Bash\n---\nRun `!date`.\n")
	toml := filepath.Join(dir, "config.toml")
	mustWrite(t, toml, "approvals_reviewer = \"auto_review\"\n\n[mcp_servers.\"io.x/y\"]\ncommand = \"npx\"\nargs = [\"-y\", \"pkg\"]\n\n[mcp_servers.web]\nurl = \"https://mcp.example.com/mcp\"\n[mcp_servers.web.headers]\nAuthorization = \"Bearer abc\"\n\n[sandbox_workspace_write]\nnetwork_access = true\n\n[auto_review]\npolicy = \"x\"\n")
	yaml := filepath.Join(dir, "config.yaml")
	mustWrite(t, yaml, "models:\n  - name: m\n    apiKey: \"sk-literal-value\"\n")
	fs := []finding.Finding{
		{File: skill, Message: "SKILL.md frontmatter allowed-tools grants unrestricted shell access"},
		{File: skill, Message: "SKILL.md frontmatter description is a broad trigger"},
		{File: skill, Message: "x.md frontmatter sets name: \"x\""},
		{File: toml, Message: "mcpServers.io.x/y: package \"pkg\" passed to npx has no @version pin"},
		{File: toml, Message: "mcpServers.web connects to \"https://mcp.example.com/mcp\" — a non-loopback host"},
		{File: toml, Message: "mcpServers.web.headers.Authorization contains a hardcoded credential"},
		{File: toml, Message: "Codex [sandbox_workspace_write] sets network_access = true"},
		{File: toml, Message: "Codex approvals_reviewer is \"auto_review\""},
		{File: toml, Message: "auto_review.policy inserts repository-controlled text"},
		{File: yaml, Message: "models[0].apiKey is \"sk-literal-value\""},
		{File: yaml, Message: "nothing quoted here"},
		{File: filepath.Join(dir, "x.json"), Message: "not a text file"},
		{File: filepath.Join(dir, "missing.toml"), Message: "Codex approvals_reviewer is \"x\""},
		{File: skill, Line: 9, Message: "already has a line"},
	}
	locateTextLines(fs)
	var got []string
	for _, f := range fs {
		got = append(got, strings.TrimPrefix(filepath.Base(f.File), "")+":"+itoa977(f.Line))
	}
	want := "SKILL.md:4,SKILL.md:3,SKILL.md:2,config.toml:5,config.toml:8,config.toml:10,config.toml:13,config.toml:1,config.toml:16,config.yaml:3,config.yaml:0,x.json:0,missing.toml:0,SKILL.md:9"
	if strings.Join(got, ",") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, ","), want)
	}
}

func itoa977(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// A frontmatter finding carries a SARIF region end to end.
func TestTextLinesRun977(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "skills", "x", "SKILL.md"), "---\nname: x\ndescription: d\nallowed-tools: Bash\n---\nbody\n")
	for _, f := range scanFindings(t, "--only", "CFG051", dir) {
		if f.Line != 4 {
			t.Errorf("CFG051 at line %d, want 4: %+v", f.Line, f)
		}
	}
}

func TestTextLinesEdges977(t *testing.T) {
	fm := strings.Split("---\nname: x\n---\nbody", "\n")
	if l := frontmatterFieldLine(fm, "x frontmatter allowed-tools grants"); l != 0 {
		t.Errorf("absent field: %d", l)
	}
	if l := frontmatterFieldLine(strings.Split("---\nname: x\nallowed: y", "\n"), "x frontmatter allowed-tools grants"); l != 0 {
		t.Errorf("unterminated: %d", l)
	}
	toml := strings.Split("[mcp_servers.a]\ncommand = \"npx\"\nargs = [\"x\"]\n\n[other]\nk = 1\nlate = 2", "\n")
	for msg, want := range map[string]int{
		"mcpServers.a.args contains x":           3, // a one-segment key in the table
		"mcpServers.a connects to \"elsewhere\"": 1, // the quoted value is not in the table
		"Codex late is \"x\"":                    0, // a top-level key after the first table is not top level
		"Codex [mcp_servers.a] sets missing = 1": 1, // the key is not in the table: its header
		"Codex [other] sets missing = 1":         5, // the last table, to the end of the file
		"plain text":                             0,
	} {
		if l := tomlMessageLine(toml, msg); l != want {
			t.Errorf("%q: line %d, want %d", msg, l, want)
		}
	}
}
