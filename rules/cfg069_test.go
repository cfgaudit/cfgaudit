package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG069_HTTPNoRedaction_Warn(t *testing.T) {
	for _, json := range []string{
		`{"mcpServers":{"m":{"command":"npx","args":["-y","n8n-mcp"],"env":{"MCP_TRANSPORT":"http"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_HTTP_ENABLED":"true"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"SERVER_MODE":"https"}}}}`,
	} {
		f := CFG069.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", json, f)
		}
	}
}

func TestCFG069_HTTPWithSafeLogging_NoFinding(t *testing.T) {
	for _, json := range []string{
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_TRANSPORT":"http","LOG_LEVEL":"warn"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_TRANSPORT":"http","LOG_REDACT":"true"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_HTTP_ENABLED":"true","MCP_LOG_SENSITIVE":"false"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_TRANSPORT":"http","DISABLE_REQUEST_LOGGING":"true"}}}}`,
	} {
		if f := CFG069.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for safe logging %s, got %+v", json, f)
		}
	}
}

func TestCFG069_NotHTTP_NoFinding(t *testing.T) {
	for _, json := range []string{
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_TRANSPORT":"stdio"}}}}`,    // stdio transport
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_HTTP_ENABLED":"false"}}}}`, // explicitly off
		`{"mcpServers":{"m":{"command":"npx","args":["-y","pkg"]}}}`,              // no transport env
	} {
		if f := CFG069.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", json, f)
		}
	}
	if f := CFG069.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}
