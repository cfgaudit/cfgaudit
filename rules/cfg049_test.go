// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG049_CleartextNonLoopback_Error(t *testing.T) {
	for _, url := range []string{
		"http://mcp.attacker.example:3000/sse",
		"ws://evil.example/socket",
	} {
		f := CFG049.Check(settingsTarget(t, `{"mcpServers":{"m":{"type":"sse","url":"`+url+`"}}}`))
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "cleartext") {
			t.Errorf("expected cleartext Error for %q, got %+v", url, f)
		}
	}
}

func TestCFG049_RawIP_Error(t *testing.T) {
	f := CFG049.Check(settingsTarget(t, `{"mcpServers":{"m":{"type":"http","url":"https://203.0.113.10/mcp"}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "raw IP") {
		t.Fatalf("expected raw-IP Error, got %+v", f)
	}
}

func TestCFG049_TLSHostname_Warn(t *testing.T) {
	f := CFG049.Check(settingsTarget(t, `{"mcpServers":{"m":{"type":"http","url":"https://mcp.partner.example/sse"}}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected TLS-hostname Warn, got %+v", f)
	}
}

// A vendor's documented endpoint is info; a lookalike, a vendor name in the
// userinfo or the path, another path on a shared host and cleartext keep
// their severity (#1202).
func TestCFG049_VendorEndpoints1202(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want finding.Severity
	}{
		{"https://api.githubcopilot.com/mcp/", finding.Info},
		{"https://api.githubcopilot.com/mcp", finding.Info},
		{"https://mcp.sentry.dev/mcp", finding.Info},
		{"https://learn.microsoft.com/api/mcp", finding.Info},
		{"https://MCP.Linear.app/sse", finding.Info},
		{"https://mcp.example-unknown.com/mcp", finding.Warn},
		{"https://api.githubcopilot.com.example.com/mcp", finding.Warn},
		{"https://learn.microsoft.com/en-us/docs", finding.Warn},
		{"https://huggingface.co/someone/space", finding.Warn},
		{"https://api.githubcopilot.com@evil.example/mcp", finding.Warn},
		{"https://evil.example/api.githubcopilot.com/mcp", finding.Warn},
		{"http://mcp.sentry.dev/mcp", finding.Error},
		{"http://10.0.0.5:8080/mcp", finding.Error},
	} {
		f := CFG049.Check(settingsTarget(t, `{"mcpServers":{"m":{"type":"http","url":"`+tc.url+`"}}}`))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s: got %+v, want one %s", tc.url, f, tc.want)
			continue
		}
		if tc.want == finding.Info && !strings.Contains(f[0].Message, "documents for its service") {
			t.Errorf("%s: message does not name the vendor: %s", tc.url, f[0].Message)
		}
	}
}

func TestCFG049_NotFlagged(t *testing.T) {
	cases := []string{
		`{"mcpServers":{"m":{"type":"sse","url":"http://localhost:8080/sse"}}}`, // loopback cleartext is fine
		`{"mcpServers":{"m":{"type":"sse","url":"https://127.0.0.1/sse"}}}`,     // loopback IP
		`{"mcpServers":{"m":{"type":"http","url":"http://[::1]:9000/mcp"}}}`,    // loopback v6
		`{"mcpServers":{"m":{"url":"${MCP_ENDPOINT}"}}}`,                        // pure env ref
		`{"mcpServers":{"m":{"url":"https://$HOST/sse"}}}`,                      // env-interpolated host
		`{"mcpServers":{"m":{"command":"npx","args":["-y","pkg"]}}}`,            // stdio server, no url
	}
	for _, c := range cases {
		if f := CFG049.Check(settingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG049_AttributesAndCoversProjectMCP(t *testing.T) {
	// A .mcp.json (ProjectMCP) source is covered and attributed to its file.
	tg := settingsTarget(t, `{}`)
	tg.ProjectMCPFile = ".mcp.json"
	tg.ProjectMCP = map[string]parser.MCPServer{"m": {URL: "http://evil.example/sse"}}
	f := CFG049.Check(tg)
	if len(f) != 1 || f[0].File != ".mcp.json" {
		t.Fatalf("expected finding attributed to .mcp.json, got %+v", f)
	}
}

// A subdomain of localhost is loopback (#1202); a host that only names it
// after an @ in the path is not.
func TestCFG049_LocalhostSubdomain(t *testing.T) {
	for url, want := range map[string]int{
		"https://my-app.localhost:3000/mcp":         0,
		"http://api.localhost/mcp":                  0,
		"https://localhost.example.com/mcp":         1,
		"https://my-app.localhost.example.com/mcp":  1,
		"https://evil.example/x@my-app.localhost/m": 1,
	} {
		tg := settingsTarget(t, `{"mcpServers":{"s":{"type":"http","url":"`+url+`"}}}`)
		if f := CFG049.Check(tg); len(f) != want {
			t.Errorf("%s: got %d findings, want %d: %+v", url, len(f), want, f)
		}
	}
}
