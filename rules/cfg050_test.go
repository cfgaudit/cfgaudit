package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG050_EnvSecret(t *testing.T) {
	f := CFG050.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"s","env":{"GITHUB_TOKEN":"ghp_abcdefghij0123456789ABCDEF"}}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "mcpServers.m.env.GITHUB_TOKEN") || !strings.Contains(f[0].Message, "GitHub token") {
		t.Errorf("unexpected message: %s", f[0].Message)
	}
}

func TestCFG050_EnvSecretSuffixName(t *testing.T) {
	f := CFG050.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"s","env":{"DB_PASSWORD":"hunter2hunter2"}}}}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "secret-like name") {
		t.Fatalf("expected secret-name Error, got %+v", f)
	}
}

func TestCFG050_HeaderAuthLiteral(t *testing.T) {
	for _, hdr := range []string{
		`{"Authorization":"Bearer sk-ant-abcdef1234567890"}`,
		`{"X-Api-Key":"a1b2c3d4e5f6g7h8"}`,
		`{"Proxy-Authorization":"Basic dXNlcjpwYXNz"}`,
	} {
		f := CFG050.Check(settingsTarget(t, `{"mcpServers":{"m":{"url":"https://x/sse","headers":`+hdr+`}}}`))
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, ".headers.") {
			t.Errorf("expected header Error for %s, got %+v", hdr, f)
		}
	}
}

func TestCFG050_HeaderVendorPatternNamesVendor(t *testing.T) {
	f := CFG050.Check(settingsTarget(t, `{"mcpServers":{"m":{"url":"https://x/sse","headers":{"Authorization":"Bearer sk-ant-abcdef1234567890"}}}}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "Anthropic API key") {
		t.Fatalf("expected vendor-named credential, got %+v", f)
	}
}

func TestCFG050_NotFlagged(t *testing.T) {
	cases := []string{
		`{"mcpServers":{"m":{"command":"s","env":{"API_TOKEN":"${API_TOKEN}"}}}}`,                        // env shell ref
		`{"mcpServers":{"m":{"command":"s","env":{"GREETING":"hello world"}}}}`,                          // non-secret value/name
		`{"mcpServers":{"m":{"url":"https://x/sse","headers":{"Authorization":"Bearer ${TOKEN}"}}}}`,     // header shell ref
		`{"mcpServers":{"m":{"url":"https://x/sse","headers":{"Authorization":"Bearer <your-token>"}}}}`, // placeholder
		`{"mcpServers":{"m":{"url":"https://x/sse","headers":{"Accept":"application/json"}}}}`,           // non-auth header
		`{"mcpServers":{"m":{"command":"npx","args":["-y","pkg"]}}}`,                                     // stdio, no secrets
		// Template-placeholder references resolve at runtime — not committed secrets (CFG068 covers the
		// endpoint-specific exfil case); CFG050 must not flag them as hardcoded credentials.
		`{"mcpServers":{"m":{"url":"https://x/sse","headers":{"Authorization":"Bearer {{TOKEN}}"}}}}`, // handlebars template
		`{"mcpServers":{"m":{"url":"https://x/sse","headers":{"X-Api-Key":"%{API_KEY}"}}}}`,           // %{} template
		`{"mcpServers":{"m":{"command":"s","env":{"API_TOKEN":"{{LIBRECHAT_TOKEN}}"}}}}`,              // env template ref
	}
	for _, c := range cases {
		if f := CFG050.Check(settingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

// A Copilot http hook's headers are a committed request-credential block, the
// same shape CFG050 already reports for an MCP server.
func TestCFG050_AgentHookHeaders(t *testing.T) {
	tgt := agentHooksTarget("Copilot", map[string][]parser.AgentHook{
		"preToolUse": {{
			Type:    "http",
			URL:     "https://example.com/hook",
			Headers: map[string]string{"Authorization": "Bearer ghp_abcdefghij0123456789ABCDEF"},
		}},
	}, false)
	f := CFG050.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Copilot hooks.preToolUse.headers.Authorization") {
		t.Errorf("unexpected message: %s", f[0].Message)
	}
}

// An environment-variable reference is the recommended form, not a finding.
func TestCFG050_AgentHookHeaderEnvRefSilent(t *testing.T) {
	tgt := agentHooksTarget("Copilot", map[string][]parser.AgentHook{
		"preToolUse": {{
			Type:    "http",
			URL:     "https://example.com/hook",
			Headers: map[string]string{"Authorization": "Bearer $GITHUB_TOKEN"},
		}},
	}, false)
	if f := CFG050.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
}
