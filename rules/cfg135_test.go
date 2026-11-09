// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func manifestTarget(t *testing.T, body string) *Target {
	t.Helper()
	var m parser.PluginManifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return &Target{PluginManifest: &m, PluginManifestFile: "p/.claude-plugin/plugin.json"}
}

// #1410: a component path that leaves the plugin root.
func TestCFG135(t *testing.T) {
	f := CFG135.Check(manifestTarget(t, `{"name":"fixture-plugin","commands":"../outside/fixture.prompt.md","skills":["../../outside/fixture-skill"]}`))
	if len(f) != 2 || f[0].Key != "skills" || f[1].Key != "commands" || f[0].Severity != finding.Warn {
		t.Fatalf("CVE fixture: %+v", f)
	}
	if !strings.Contains(f[1].Message, `plugin.json commands names "../outside/fixture.prompt.md", which leaves the plugin root`) {
		t.Errorf("message: %s", f[1].Message)
	}
	for field, body := range map[string]string{
		"agents":     `{"agents":["./agents/a.md","/tmp/cfgaudit-fixture.md"]}`,
		"hooks":      `{"hooks":"~/hooks.json"}`,
		"mcpServers": `{"mcpServers":"..\\..\\servers.json"}`,
		"commands":   `{"commands":"C:\\fixture\\c.md"}`,
		"skills":     `{"skills":"\\\\host\\share\\skills"}`,
	} {
		f := CFG135.Check(manifestTarget(t, body))
		if len(f) != 1 || f[0].Key != field {
			t.Errorf("%s: %+v", field, f)
		}
	}
	if f := CFG135.Check(manifestTarget(t, `{"hooks":"~/.claude/hooks/hooks.json"}`)); len(f) != 1 || f[0].Severity != finding.Error {
		t.Errorf("sensitive: %+v", f)
	}
	// Relative to .claude-plugin/ by mistake: warn, with the hint, also when
	// the path runs through a folder named like a sensitive one.
	for _, body := range []string{`{"hooks":"../hooks/hooks.json"}`, `{"commands":"../.claude/commands"}`, `{"skills":"..\\.claude\\skills"}`} {
		f := CFG135.Check(manifestTarget(t, body))
		if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "not against .claude-plugin/ itself") {
			t.Errorf("%s: %+v", body, f)
		}
	}
	for _, body := range []string{
		`{"name":"fixture-plugin","commands":"commands/review.md","skills":["parts/../skills/reviewer"]}`,
		`{"mcpServers":{"s":{"command":"node","args":["../x.js"]}}}`,
		`{"hooks":{"PreToolUse":[]},"agents":"./agents"}`,
		`{}`,
	} {
		if f := CFG135.Check(manifestTarget(t, body)); len(f) != 0 {
			t.Errorf("%s: %+v", body, f)
		}
	}
	if f := CFG135.Check(&Target{}); f != nil {
		t.Errorf("no manifest: %+v", f)
	}
}
