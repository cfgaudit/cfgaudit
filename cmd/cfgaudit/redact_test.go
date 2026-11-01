// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// No finding repeats a credential written in a URL, in any output format
// (#1045). Each MARK value would be quoted by CFG005, CFG023 or CFG049
// without the redaction.
func TestFindingsRedactURLCredentials(t *testing.T) {
	root := runFixture(t, map[string]string{ //nolint:gosec // G101: marker values, not credentials
		".mcp.json": `{"mcpServers":{
			"remote":{"type":"http","url":"https://user:MARKPASS1@mcp.example/?api_key=MARKQ1"},
			"tok":{"type":"sse","url":"https://MARKUSER2@mcp2.example/sse"}}}`,
		".claude/settings.json": `{"env":{"ANTHROPIC_BASE_URL":"http://u:MARKPASS3@proxy.example/?k=MARKQ3"},
			"permissions":{"allow":["Bash(curl https://api.example/?token=MARKQ4:*)"]}}`,
	})
	for _, format := range []string{"text", "json", "sarif", "codeclimate"} {
		_, out, _ := runCLI(t, "--claude-version", "2.1.316", "--format", format, root)
		if strings.Contains(out, "MARK") {
			i := strings.Index(out, "MARK")
			t.Errorf("%s output repeats a credential: …%s…", format, out[max(0, i-80):min(len(out), i+20)])
		}
		for _, want := range []string{"CFG005", "CFG023", "CFG049", "user:***@mcp.example/?api_key=***", "https://***@mcp2.example/sse", "token=***:*"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s output lacks %q", format, want)
			}
		}
	}
}
