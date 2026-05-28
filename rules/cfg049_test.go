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
