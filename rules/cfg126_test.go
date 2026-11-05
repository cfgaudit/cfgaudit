// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG126_VulnerablePackagesAcrossRunnerForms(t *testing.T) {
	cases := []struct {
		command string
		args    string
		want    string
	}{
		{"npx", `["-y","mcp-remote@0.0.5","https://example.invalid/mcp"]`, "CVE-2025-6514"},
		{"npm", `["exec","mcp-remote@0.1.15","--","https://example.invalid/mcp"]`, "CVE-2025-6514"},
		{"pnpm", `["--silent","dlx","mcp-remote@0.1.15"]`, "CVE-2025-6514"},
		{"yarn", `["dlx","@modelcontextprotocol/inspector@2.11.0"]`, "GHSA-q978-78c7-phqw"},
		{"bunx", `["--bun","@modelcontextprotocol/inspector@2.0.0"]`, "GHSA-q978-78c7-phqw"},
		{"npx", `["-y","--package=@modelcontextprotocol/inspector@2.5.0","inspector"]`, "GHSA-q978-78c7-phqw"},
		{"npx", `["--yes","--registry","https://registry.example.invalid","mcp-remote@0.1.15"]`, "CVE-2025-6514"},
		{"npm", `["--loglevel","silent","exec","mcp-remote@0.1.15"]`, "CVE-2025-6514"},
		{"npm", `["--registry","https://registry.example.invalid","exec","mcp-remote@0.1.15"]`, "CVE-2025-6514"},
		{"npx.cmd", `["-y","mcp-remote@0.1.15"]`, "CVE-2025-6514"},
		{"cmd", `["/c","npx","-y","mcp-remote@0.1.15"]`, "CVE-2025-6514"},
		{"cmd.exe", `["/C","npx -y @modelcontextprotocol/inspector@2.11.0"]`, "GHSA-q978-78c7-phqw"},
	}
	for _, tc := range cases {
		t.Run(tc.command+tc.want, func(t *testing.T) {
			target := settingsTarget(t, `{"mcpServers":{"s":{"command":"`+tc.command+`","args":`+tc.args+`}}}`)
			f := CFG126.Check(target)
			if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, tc.want) {
				t.Fatalf("expected one Error containing %q, got %+v", tc.want, f)
			}
		})
	}
}

func TestCFG126_FixedOutsideAndUnknownVersions_NoFinding(t *testing.T) {
	for _, spec := range []string{
		"mcp-remote@0.0.4", "mcp-remote@0.1.16", "mcp-remote@1.0.0",
		"@modelcontextprotocol/inspector@1.99.0", "@modelcontextprotocol/inspector@2.11.1", "@modelcontextprotocol/inspector@2.12.0",
		"mcp-remote@latest", "mcp-remote@^0.1.15", "mcp-remote@~0.1.15", "mcp-remote@0.1",
		"mcp-remote@npm:something@0.1.15", "mcp-remote@0.1.15-beta.1", "mcp-remote@broken",
		"unrelated@0.1.15", "mcp-remote@99999999999999999999.0.0",
	} {
		target := settingsTarget(t, `{"mcpServers":{"s":{"command":"npx","args":["-y","`+spec+`"]}}}`)
		if f := CFG126.Check(target); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %+v", spec, f)
		}
	}
}

func TestCFG126_RunnerThatFetchesNoPackage_NoFinding(t *testing.T) {
	for _, tc := range []struct{ command, args string }{
		{"npm", `["run","mcp-remote@0.1.15"]`},
		{"npm", `["--prefix"]`},
		{"npm", `["--silent"]`},
		{"pnpm", `["run","mcp-remote@0.1.15"]`},
		{"yarn", `["mcp-remote@0.1.15"]`},
		{"cmd", `["/c"]`},
		{"cmd", `["mcp-remote@0.1.15"]`},
		{"node", `["mcp-remote@0.1.15"]`},
	} {
		target := settingsTarget(t, `{"mcpServers":{"s":{"command":"`+tc.command+`","args":`+tc.args+`}}}`)
		if f := CFG126.Check(target); len(f) != 0 {
			t.Errorf("%s %s: expected no finding, got %+v", tc.command, tc.args, f)
		}
	}
}

func TestCFG126_ExactVersionGrammar(t *testing.T) {
	for _, spec := range []string{"mcp-remote@0.1.15", "mcp-remote@v0.1.15", "mcp-remote@0.1.15+build.7", "@modelcontextprotocol/inspector@2.11.0"} {
		name, _, _, ok := exactNPMVersion(spec)
		if !ok || name == "" {
			t.Errorf("expected exact version for %q", spec)
		}
	}
}

func TestCFG126_NoTarget_NoFinding(t *testing.T) {
	if f := CFG126.Check(nil); len(f) != 0 {
		t.Fatalf("nil target: %+v", f)
	}
	if f := CFG126.Check(&Target{}); len(f) != 0 {
		t.Fatalf("empty target: %+v", f)
	}
}
