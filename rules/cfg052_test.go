// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// An mcpServers block in a Claude Code settings.json has no effect, so it is
// reported once at info, and a name it shares with .mcp.json is no longer a
// conflict (#1215).
func TestCFG052_SettingsMCPHasNoEffect(t *testing.T) {
	tg := settingsTarget(t, `{"mcpServers":{"github":{"command":"npx"},"unique":{"command":"npx"}}}`)
	tg.ProjectMCPFile = ".mcp.json"
	tg.ProjectMCP = map[string]parser.MCPServer{"github": {Command: "node"}}
	f := CFG052.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Info || f[0].File != "test/settings.json" {
		t.Fatalf("expected 1 info on settings.json, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "has no effect") || !strings.Contains(f[0].Message, "2 server(s)") {
		t.Errorf("message: %s", f[0].Message)
	}
}

func TestCFG052_NoSettingsMCP_NoFinding(t *testing.T) {
	tg := &Target{
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"a": {Command: "npx"}, "b": {Command: "npx"}},
	}
	if f := CFG052.Check(tg); len(f) != 0 {
		t.Errorf("expected no finding for .mcp.json only, got %+v", f)
	}
	if f := CFG052.Check(settingsTarget(t, `{"permissions":{"allow":["Read"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding without mcpServers, got %+v", f)
	}
	if f := CFG052.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding on an empty target, got %+v", f)
	}
}
