package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG058_SSETransport_Warn(t *testing.T) {
	// Fires on the transport choice regardless of host — including a TLS hostname
	// and a loopback URL, which CFG049 would not flag at warn/error.
	for _, cfg := range []string{
		`{"mcpServers":{"m":{"type":"sse","url":"https://mcp.partner.example/sse"}}}`,
		`{"mcpServers":{"m":{"type":"sse","url":"http://localhost:8080/sse"}}}`,
		`{"mcpServers":{"m":{"type":"SSE","url":"https://mcp.example/sse"}}}`, // case-insensitive
	} {
		f := CFG058.Check(settingsTarget(t, cfg))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 warn for %q, got %+v", cfg, f)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, "deprecated") {
			t.Errorf("expected message to flag the transport as deprecated, got %q", f[0].Message)
		}
	}
}

func TestCFG058_OtherTransports_NoFinding(t *testing.T) {
	for _, cfg := range []string{
		`{"mcpServers":{"m":{"type":"http","url":"https://mcp.example/mcp"}}}`,
		`{"mcpServers":{"m":{"command":"npx","args":["server"]}}}`, // stdio server, no type
		`{"mcpServers":{"m":{"type":"streamable-http","url":"https://mcp.example/mcp"}}}`,
	} {
		if f := CFG058.Check(settingsTarget(t, cfg)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cfg, f)
		}
	}
}

func TestCFG058_DotMCPJson_Attribution(t *testing.T) {
	// A server declared in .mcp.json is attributed to that file.
	tgt := mcpJSONTarget(map[string]parser.MCPServer{
		"remote": {Type: "sse", URL: "https://x.example/sse"},
	})
	f := CFG058.Check(tgt)
	if len(f) != 1 || f[0].File != ".mcp.json" {
		t.Fatalf("expected finding attributed to .mcp.json, got %+v", f)
	}
}
