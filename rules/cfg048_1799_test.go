// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// mcpProtoTarget builds a .vscode/mcp.json target from raw JSON (#1799).
func mcpProtoTarget(t *testing.T, src string) *Target {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(src), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &Target{VSCodeMCPRaw: raw, VSCodeMCPRawFile: ".vscode/mcp.json"}
}

// CVE-2026-121662 also applies to .vscode/mcp.json: a __proto__ key there is the
// same prototype-pollution bypass as in the settings file (#1799).
func TestCFG048_MCPProto1799(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{`{"servers":{"s":{"command":"node"}},"__proto__":{"x":1}}`, true},
		{`{"servers":{"s":{"command":"node","__proto__":{"x":1}}}}`, true},
		{`{"servers":{"s":{"command":"node"}}}`, false},
		{`{"servers":{"s":{"command":"node"}},"note":"mentions __proto__ in a string"}`, false},
	} {
		var got bool
		for _, f := range CFG048.Check(mcpProtoTarget(t, tc.src)) {
			if f.RuleID == "CFG048" && strings.Contains(f.Message, "CVE-2026-121662") {
				if f.Severity != finding.Error {
					t.Errorf("%s: severity %v, want error", tc.src, f.Severity)
				}
				if !strings.Contains(f.Message, "MCP configuration") || !strings.Contains(f.Message, "1.145.3") {
					t.Errorf("%s: message not MCP-specific: %q", tc.src, f.Message)
				}
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%s: reported=%v, want %v", tc.src, got, tc.want)
		}
	}
}

// CVE-2026-70094: debug.javascript.terminalOptions runs a program in the JS
// debug terminal, and js-debug took it from the workspace before trust. Reported
// at warn only when it carries an execution vector (command/env/envFile); the
// setting key verified against vscode-js-debug 1a7afe5 (#1799).
func TestCFG048_JSDebugTerminal1799(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{`{"debug.javascript.terminalOptions":{"command":"npm start"}}`, true},
		{`{"debug.javascript.terminalOptions":{"env":{"PATH":"/evil"}}}`, true},
		{`{"debug.javascript.terminalOptions":{"envFile":"${workspaceFolder}/.env"}}`, true},
		{`{"debug.javascript.terminalOptions":{"cwd":"${workspaceFolder}/app"}}`, false},
		{`{"debug.javascript.terminalOptions":{}}`, false},
		{`{}`, false},
	} {
		var got bool
		for _, f := range CFG048.Check(agentHostTarget(t, tc.src)) {
			if f.RuleID == "CFG048" && strings.Contains(f.Message, "CVE-2026-70094") {
				if f.Severity != finding.Warn {
					t.Errorf("%s: severity %v, want warn", tc.src, f.Severity)
				}
				if !strings.Contains(f.Message, "1.145.3") {
					t.Errorf("%s: message missing the fixed-in version: %q", tc.src, f.Message)
				}
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%s: reported=%v, want %v", tc.src, got, tc.want)
		}
	}
}
