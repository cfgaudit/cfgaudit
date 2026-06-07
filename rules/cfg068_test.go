package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG068_TemplatedCredToCleartext_Error(t *testing.T) {
	cases := []string{
		`{"mcpServers":{"m":{"url":"http://mcp.example/sse","headers":{"Authorization":"Bearer {{USER_TOKEN}}"}}}}`,
		`{"mcpServers":{"m":{"url":"http://10.0.0.5/mcp","headers":{"X-Api-Key":"${API_KEY}"}}}}`,
		`{"mcpServers":{"m":{"url":"https://203.0.113.9/mcp","headers":{"Authorization":"%{TOKEN}"}}}}`, // raw IP over TLS still raw-IP
		`{"mcpServers":{"m":{"url":"ws://host.example/x","env":{"OPENID_ACCESS_TOKEN":"{{LIBRECHAT_OPENID_ACCESS_TOKEN}}"}}}}`,
	}
	for _, json := range cases {
		f := CFG068.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %s, got %+v", json, f)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, "templated credential") {
			t.Errorf("unexpected message: %q", f[0].Message)
		}
	}
}

func TestCFG068_TemplatedCredToTLSHostname_NoFinding(t *testing.T) {
	// The legitimate hosted-MCP-auth pattern — left to CFG049's warn, not flagged here.
	f := CFG068.Check(settingsTarget(t, `{"mcpServers":{"m":{"url":"https://mcp.trusted.example/mcp","headers":{"Authorization":"Bearer {{TOKEN}}"}}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for templated cred to TLS hostname, got %+v", f)
	}
}

func TestCFG068_NoFinding(t *testing.T) {
	for _, json := range []string{
		`{"mcpServers":{"m":{"url":"http://localhost:8080/sse","headers":{"Authorization":"Bearer {{TOKEN}}"}}}}`,      // loopback
		`{"mcpServers":{"m":{"url":"http://mcp.example/sse","headers":{"User-Agent":"{{VERSION}}"}}}}`,                 // non-auth header
		`{"mcpServers":{"m":{"url":"http://mcp.example/sse","headers":{"Authorization":"Bearer sk-literal-abc123"}}}}`, // literal, not templated (CFG050's job)
		`{"mcpServers":{"m":{"command":"npx","args":["x"],"env":{"TOKEN":"{{T}}"}}}}`,                                  // stdio server, no remote url
	} {
		if f := CFG068.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", json, f)
		}
	}
	if f := CFG068.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}
