package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"gopkg.in/yaml.v3"
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

// #463: extraKnownMarketplaces entries carry a headers block too, and Claude Code
// really sends it. Upstream: those headers ride archive downloads whose URL
// shares the marketplace URL's origin, and 2.1.231 carries the matching guard
// "Fetch of … redirected to a different origin; dropped inherited marketplace
// headers". CFG050 covered MCP servers and agent hooks but not this third source.
func TestCFG050_MarketplaceHeaderCredential(t *testing.T) {
	got := onlyFinding(t, CFG050.Check(settingsTarget(t, `{
      "extraKnownMarketplaces": {
        "acme": {"source": {"source": "url", "url": "https://acme.example/mk.json",
                 "headers": {"Authorization": "Bearer sk-live-9f2c8d1a4b6e"}}}
      }}`)), finding.Error)
	for _, want := range []string{"extraKnownMarketplaces.acme.source.headers.Authorization", "hardcoded"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
}

// The same exemptions the MCP and hook headers get: an environment reference is
// the fix the message asks for, and a placeholder is not a secret.
func TestCFG050_MarketplaceHeaderExemptions(t *testing.T) {
	for _, v := range []string{"Bearer ${MARKETPLACE_TOKEN}", "${TOKEN}", "Bearer <your-token>", "Bearer changeme", ""} {
		body, err := json.Marshal(map[string]any{"extraKnownMarketplaces": map[string]any{
			"acme": map[string]any{"source": map[string]any{"headers": map[string]any{"Authorization": v}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if f := CFG050.Check(settingsTarget(t, string(body))); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", v, f)
		}
	}
}

// A non-auth header is ordinary metadata unless its value looks like a token.
func TestCFG050_MarketplaceNonAuthHeader(t *testing.T) {
	f := CFG050.Check(settingsTarget(t, `{
      "extraKnownMarketplaces": {"acme": {"source": {"headers": {"User-Agent": "acme/1.0"}}}}}`))
	if len(f) != 0 {
		t.Errorf("a plain header must not be flagged, got %+v", f)
	}
}

// Entries with no headers, and shapes this version does not model, stay silent
// rather than breaking the scan.
func TestCFG050_MarketplaceShapesTolerated(t *testing.T) {
	for _, body := range []string{
		`{"extraKnownMarketplaces": {"acme": {"source": {"source": "github", "repo": "acme/mk"}}}}`,
		`{"extraKnownMarketplaces": {"acme": {}}}`,
		`{"extraKnownMarketplaces": {}}`,
		`{"extraKnownMarketplaces": []}`,
		`{"extraKnownMarketplaces": "nonsense"}`,
	} {
		if f := CFG050.Check(settingsTarget(t, body)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", body, f)
		}
	}
}

// Several marketplaces are reported in a stable order, one finding per header.
func TestCFG050_MarketplaceMultipleEntries(t *testing.T) {
	f := CFG050.Check(settingsTarget(t, `{
      "extraKnownMarketplaces": {
        "zeta": {"source": {"headers": {"X-Api-Key": "9f2c8d1a4b6e7c3f"}}},
        "alpha": {"source": {"headers": {"Authorization": "Bearer sk-live-1234abcd"}}}
      }}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "alpha") {
		t.Errorf("expected a stable alphabetical order, got %q first", f[0].Message)
	}
}

// #470: Continue's requestOptions block hangs off models, mcpServers and data
// alike, and it is where the credentials are: 44 occurrences across 108 real
// configs against 1 for the whole data block.
func continueTargetFor(t *testing.T, body string) *Target {
	t.Helper()
	var c parser.ContinueConfig
	if err := yaml.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("bad test YAML: %v", err)
	}
	return &Target{Scope: finding.ScopeProject, Continue: &c, ContinueFile: ".continue/config.yaml"}
}

func TestCFG050_ContinueRequestOptionsHeaders(t *testing.T) {
	got := onlyFinding(t, CFG050.Check(continueTargetFor(t, `
models:
  - name: leaky
    requestOptions:
      headers:
        X-API-Key: sm_live_8f2a7c1b9e4d5a3f6b0c2d8e1a4f7c9b3d0e6a2f
`)), finding.Error)
	if !strings.Contains(got.Message, `Continue models["leaky"].requestOptions.headers.X-API-Key`) {
		t.Errorf("expected the entry named, got %q", got.Message)
	}
}

func TestCFG050_ContinueDataAPIKey(t *testing.T) {
	got := onlyFinding(t, CFG050.Check(continueTargetFor(t, `
data:
  - name: sink
    destination: https://collector.example.net/ingest
    schema: 0.2.0
    apiKey: sk-live-9f2c8d1a4b6e7c3f
`)), finding.Error)
	if !strings.Contains(got.Message, `Continue data["sink"].apiKey`) {
		t.Errorf("expected the data entry named, got %q", got.Message)
	}
}

// The two exemptions the false-positive run earned, both from real values.

// ${{ secrets.NAME }} is CI expression syntax and was 7 of the 15 real header
// values. shellRefRe rejects it because of the second brace.
func TestCFG050_TemplateExpressionIsAReference(t *testing.T) {
	f := CFG050.Check(continueTargetFor(t, `
models:
  - name: ci
    requestOptions:
      headers:
        X-API-Key: ${{ secrets.OLLAMA_API_KEY }}
`))
	if len(f) != 0 {
		t.Errorf("a CI expression is a reference, not a literal, got %+v", f)
	}
}

// An all-caps token naming a credential is an unfilled template. Real value:
// "Bearer TU_API_KEY_AQUI".
func TestCFG050_ScreamingPlaceholder(t *testing.T) {
	for _, v := range []string{"Bearer TU_API_KEY_AQUI", "MY_TOKEN_HERE", "API_KEY", "Bearer YOUR_SECRET"} {
		body, err := yaml.Marshal(map[string]any{"models": []any{map[string]any{
			"name": "m", "requestOptions": map[string]any{"headers": map[string]any{"Authorization": v}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if f := CFG050.Check(continueTargetFor(t, string(body))); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", v, f)
		}
	}
	// A real key that happens to be long must still be reported.
	got := onlyFinding(t, CFG050.Check(continueTargetFor(t, `
models:
  - name: m
    requestOptions:
      headers:
        X-Auth-Token: mdPIpHNt7waLLtDaqVBlFAbP870fSItWYLRBzZjU2lelLvkI1ePh
`)), finding.Error)
	if !strings.Contains(got.Message, "X-Auth-Token") {
		t.Errorf("unexpected message %q", got.Message)
	}
}

// A value that is nothing but an auth scheme word holds no secret, including the
// doubly-quoted spelling a YAML file produces. Real value: 'Basic'.
func TestCFG050_BareSchemeWordIsNotACredential(t *testing.T) {
	for _, v := range []string{"Basic", "'Basic'", "\"Bearer\"", "Token"} {
		body, err := yaml.Marshal(map[string]any{"models": []any{map[string]any{
			"name": "m", "requestOptions": map[string]any{"headers": map[string]any{"Authorization": v}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if f := CFG050.Check(continueTargetFor(t, string(body))); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", v, f)
		}
	}
}

// A quoted credential is still a credential.
func TestCFG050_QuotedCredentialStillReported(t *testing.T) {
	onlyFinding(t, CFG050.Check(continueTargetFor(t, `
models:
  - name: m
    requestOptions:
      headers:
        X-Api-Key: "'sm_live_8f2a7c1b9e4d5a3f6b0c2d8e1a4f7c9b3d0e6a2f'"
`)), finding.Error)
}
