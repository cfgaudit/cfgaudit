// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #751: committed chat.agent.sandbox.* values that loosen the sandbox.
func TestCFG133(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      []finding.Severity
		contains  string
	}{
		{"sandbox off", `{"chat.agent.sandbox.enabled": "off"}`, []finding.Severity{finding.Warn}, "is off"},
		{"sandbox false", `{"chat.agent.sandbox.enabled": false}`, []finding.Severity{finding.Warn}, "is off"},
		{"sandbox on", `{"chat.agent.sandbox.enabled": "on"}`, nil, ""},
		{"local network", `{"chat.agent.sandbox.network.allowLocalNetwork": true}`, []finding.Severity{finding.Info}, "Windows needs it"},
		{"local network off", `{"chat.agent.sandbox.network.allowLocalNetwork": false}`, nil, ""},
		{"mcp out", `{"chat.agent.sandbox.mcpServers": false}`, []finding.Severity{finding.Warn}, "MCP servers"},
		{"lsp out", `{"chat.agent.sandbox.lspServers": false}`, []finding.Severity{finding.Warn}, "language servers"},
		{"mcp in", `{"chat.agent.sandbox.mcpServers": true}`, nil, ""},
		{"default unsandboxed", `{"chat.agent.sandbox.allowUnsandboxedCommands": true}`, []finding.Severity{finding.Info}, "stricter value"},
		{"tightened", `{"chat.agent.sandbox.allowUnsandboxedCommands": false, "chat.agent.sandbox.network.allowNetwork": false}`, nil, ""},
		{"nested spelling", `{"chat": {"agent": {"sandbox": {"credentials": {"authenticategh": true}}}}}`, []finding.Severity{finding.Info}, "GitHub CLI"},
		{"fs outside", `{"chat.agent.sandbox.fileSystem.linux": {"allowWrite": ["~/.ssh", "build", "../x"], "allowRead": ["/etc"], "denyRead": ["/"]}}`, []finding.Severity{finding.Warn, finding.Warn, finding.Info}, "may write it"},
		{"fs temp and reads", `{"chat.agent.sandbox.fileSystem.mac": {"allowWrite": ["/tmp/", "/private/tmp"], "allowRead": ["~", "/Users/me", "~/.aws/config", "~/.cargo/bin", "C:\\Users\\me"]}}`, []finding.Severity{finding.Warn, finding.Warn, finding.Warn, finding.Info, finding.Warn}, "may read it"},
		{"fs not an array", `{"chat.agent.sandbox.fileSystem.mac": {"allowWrite": "~"}}`, nil, ""},
		{"user paths", `{"chat.agent.sandbox.fileSystem.userConfiguredPaths": {"readwritePaths": ["/", "/var/tmp"], "readonlyPaths": ["docs", "/opt/sdk"], "deniedPaths": ["~"]}}`, []finding.Severity{finding.Warn, finding.Info}, "lets the agent write it"},
		{"runtime", `{"chat.agent.sandbox.advanced.runtime": {"enableWeakerNestedSandbox": true, "allowPty": true}}`, []finding.Severity{finding.Warn}, "allowPty, enableWeakerNestedSandbox"},
		{"runtime default", `{"chat.agent.sandbox.advanced.runtime": {"enableWeakerNestedSandbox": false}}`, nil, ""},
		{"application scoped", `{"chat.agent.sandbox.network.allowedDomains": ["*"], "chat.agent.networkFilter": false}`, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CFG133.Check(vscodeSettingsTarget(t, tc.raw))
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v", got)
			}
			for i, f := range got {
				if f.Severity != tc.want[i] || f.File != ".vscode/settings.json" {
					t.Errorf("finding %d: %+v", i, f)
				}
			}
			if tc.contains != "" && !strings.Contains(got[0].Message, tc.contains) {
				t.Errorf("message %q lacks %q", got[0].Message, tc.contains)
			}
		})
	}
	if got := CFG133.Check(nil); got != nil {
		t.Errorf("nil target: %v", got)
	}
	user := vscodeSettingsTarget(t, `{"chat.agent.sandbox.enabled": "off"}`)
	user.Scope = finding.ScopeUser
	if got := CFG133.Check(user); got != nil {
		t.Errorf("user scope: %v", got)
	}
}
