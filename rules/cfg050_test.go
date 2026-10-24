// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		// only a whole reference counts: text around it is still a literal (#821)
		`{"Authorization":"Bearer ${env:X}abc123secret"}`,
		`{"X-Api-Key":"${user_config.a b}"}`,
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
		// Cursor / VS Code ${env:NAME} and a Claude Code plugin's ${user_config.KEY} (#821)
		`{"mcpServers":{"m":{"url":"https://x/mcp","headers":{"Authorization":"Bearer ${env:GITHUB_TOKEN}"}}}}`,
		`{"mcpServers":{"m":{"url":"https://x/mcp","headers":{"X-API-Key":"${user_config.DATACOMMONS_API_KEY}"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"API_TOKEN":"${env:API_TOKEN}"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"BOT_TOKEN":"${user_config.bot_token}"}}}}`,
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

// #521: additionalMarketplaces is an alias Claude Code reads "exactly as if it
// were spelled extraKnownMarketplaces", so the same headers are sent and the
// finding names the spelling the file used.
func TestCFG050_MarketplaceHeaderCredential_AliasSpelling(t *testing.T) {
	got := onlyFinding(t, CFG050.Check(settingsTarget(t, `{
      "additionalMarketplaces": {
        "acme": {"source": {"source": "url", "url": "https://acme.example/mk.json",
                 "headers": {"Authorization": "Bearer sk-live-9f2c8d1a4b6e"}}}
      }}`)), finding.Error)
	for _, want := range []string{"additionalMarketplaces.acme.source.headers.Authorization", "hardcoded"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
}

// A file carrying both spellings is resolved the way Claude Code resolves it:
// the canonical key is read and the alias is ignored. Verified against 2.1.241,
// which reports the same case as "this file sets both; the
// "additionalMarketplaces" value was ignored".
func TestCFG050_MarketplaceHeaders_BothSpellings_CanonicalWins(t *testing.T) {
	got := onlyFinding(t, CFG050.Check(settingsTarget(t, `{
      "extraKnownMarketplaces": {
        "canonical": {"source": {"headers": {"Authorization": "Bearer sk-live-9f2c8d1a4b6e"}}}
      },
      "additionalMarketplaces": {
        "ignored": {"source": {"headers": {"Authorization": "Bearer sk-live-000011112222"}}}
      }}`)), finding.Error)
	if !strings.Contains(got.Message, "extraKnownMarketplaces.canonical") {
		t.Errorf("expected the canonical entry to be reported, got %q", got.Message)
	}
	if strings.Contains(got.Message, "ignored") {
		t.Errorf("the alias entry is ignored by Claude Code and must not be reported: %q", got.Message)
	}
}

// #615: a literal Codex MCP oauth.client_secret, read through the TOML parser.
func TestCFG050_CodexOAuthClientSecret(t *testing.T) {
	dir := t.TempDir()
	write := func(secret string) *Target {
		p := filepath.Join(dir, "config.toml")
		body := "[mcp_servers.remote]\nurl = \"https://example.com/mcp\"\n\n[mcp_servers.remote.oauth]\nclient_id = \"abc\"\nclient_secret = \"" + secret + "\"\n"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := parser.ParseCodexConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return &Target{ProjectMCP: c.MCPServerMap(), ProjectMCPFile: p}
	}
	f := CFG050.Check(write("s3cr3t-live-9f8e7d6c5b4a3210"))
	if len(f) != 1 || !strings.Contains(f[0].Message, "oauth.client_secret") {
		t.Fatalf("expected one finding on oauth.client_secret, got %+v", f)
	}
	for _, v := range []string{"${CLIENT_SECRET}", "<your-secret>", "CLIENT_SECRET"} {
		if f := CFG050.Check(write(v)); len(f) != 0 {
			t.Errorf("%q is a placeholder, got %+v", v, f)
		}
	}
}

// zedTarget parses body as a committed .zed/settings.json, through the same
// JSONC parser the CLI uses.
func zedTarget(t *testing.T, body string) *Target {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	z, err := parser.ParseZedSettings(path)
	if err != nil {
		t.Fatalf("bad test settings: %v", err)
	}
	return &Target{Scope: finding.ScopeProject, ZedSettings: z, ZedSettingsFile: ".zed/settings.json"}
}

// Each environment block Zed passes to a program it launches is checked, by
// value pattern and by secret-like name, and the finding names the block.
func TestCFG050_ZedEnvBlocks(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		loc      string
		what     string
	}{
		{
			name:     "terminal.env, token shape",
			settings: `{"terminal": {"env": {"GH": "ghp_abcdefghij0123456789ABCDEF"}}}`,
			loc:      "Zed terminal.env.GH",
			what:     "GitHub token",
		},
		{
			// The shape of the real config the rule cites.
			name:     "terminal.env, secret-like name",
			settings: `{"terminal": {"env": {"SURREALDB_PASSWORD": "hunter2hunter2"}}}`,
			loc:      "Zed terminal.env.SURREALDB_PASSWORD",
			what:     "secret-like name",
		},
		{
			// With a shell override the site's label is terminal.shell, and its
			// env is still checked.
			name:     "terminal.env next to a shell override",
			settings: `{"terminal": {"shell": {"program": "zsh"}, "env": {"DB_PASSWORD": "hunter2hunter2"}}}`,
			loc:      "Zed terminal.shell.env.DB_PASSWORD",
			what:     "secret-like name",
		},
		{
			name:     "lsp binary env",
			settings: `{"lsp": {"rust-analyzer": {"binary": {"path": "/usr/bin/rust-analyzer", "env": {"API_KEY": "sk-ant-abcdef1234567890"}}}}}`,
			loc:      "Zed lsp.rust-analyzer.binary.env.API_KEY",
			what:     "Anthropic API key",
		},
		{
			// An env with no path still reaches the server Zed downloads itself.
			name:     "lsp binary env without a path",
			settings: `{"lsp": {"pyright": {"binary": {"env": {"PYPI_TOKEN": "s3cr3tvalue123"}}}}}`,
			loc:      "Zed lsp.pyright.binary.env.PYPI_TOKEN",
			what:     "secret-like name",
		},
		{
			name:     "dap env",
			settings: `{"dap": {"CodeLLDB": {"binary": "/opt/codelldb", "env": {"SLACK": "xoxb-1234567890-abcdefghijkl"}}}}`,
			loc:      "Zed dap.CodeLLDB.env.SLACK",
			what:     "Slack token",
		},
		{
			// JSONC, as Zed writes it: a comment and a trailing comma.
			name: "JSONC settings",
			settings: `{
				// project terminal
				"terminal": {"env": {"DB_PASSWORD": "hunter2hunter2",},},
			}`,
			loc:  "Zed terminal.env.DB_PASSWORD",
			what: "secret-like name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := onlyFinding(t, CFG050.Check(zedTarget(t, tt.settings)), finding.Error)
			if !strings.HasPrefix(got.Message, tt.loc+" contains") {
				t.Errorf("message %q does not start with the location %q", got.Message, tt.loc)
			}
			if !strings.Contains(got.Message, tt.what) {
				t.Errorf("message %q does not name %q", got.Message, tt.what)
			}
			if got.File != ".zed/settings.json" {
				t.Errorf("finding file %q, want .zed/settings.json", got.File)
			}
		})
	}
}

func TestCFG050_ZedEnvNotFlagged(t *testing.T) {
	cases := map[string]string{
		"shell reference":       `{"terminal": {"env": {"API_TOKEN": "${API_TOKEN}"}}}`,
		"template reference":    `{"terminal": {"env": {"API_TOKEN": "{{API_TOKEN}}"}}}`,
		"placeholder":           `{"lsp": {"x": {"binary": {"path": "x", "env": {"OPENAI_API_KEY": "YOUR_API_KEY_HERE"}}}}}`,
		"empty value":           `{"dap": {"d": {"binary": "d", "env": {"DB_PASSWORD": ""}}}}`,
		"whitespace value":      `{"dap": {"d": {"binary": "d", "env": {"DB_PASSWORD": "   "}}}}`,
		"ordinary variable":     `{"terminal": {"env": {"EDITOR": "vim", "RUST_LOG": "debug"}}}`,
		"no environment blocks": `{"terminal": {"shell": {"program": "zsh"}}, "lsp": {"x": {"settings": {"token": "abc"}}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if f := CFG050.Check(zedTarget(t, body)); len(f) != 0 {
				t.Errorf("expected no finding, got %+v", f)
			}
		})
	}
}

// Every environment block is reported, in the order CommandSites gives:
// terminal, then lsp and dap entries sorted by name, keys sorted within each.
func TestCFG050_ZedEnvAllBlocksInOrder(t *testing.T) {
	f := CFG050.Check(zedTarget(t, `{
		"terminal": {"env": {"B_PASSWORD": "hunter2hunter2", "A_PASSWORD": "hunter2hunter2"}},
		"lsp": {
			"zls": {"binary": {"path": "zls", "env": {"Z_TOKEN": "s3cr3tvalue123"}}},
			"gopls": {"binary": {"path": "gopls", "env": {"G_TOKEN": "s3cr3tvalue123"}}}
		},
		"dap": {"d": {"binary": "d", "env": {"D_SECRET": "s3cr3tvalue123"}}}
	}`))
	want := []string{
		"Zed terminal.env.A_PASSWORD",
		"Zed terminal.env.B_PASSWORD",
		"Zed lsp.gopls.binary.env.G_TOKEN",
		"Zed lsp.zls.binary.env.Z_TOKEN",
		"Zed dap.d.env.D_SECRET",
	}
	if len(f) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(f), len(want), f)
	}
	for i, loc := range want {
		if !strings.HasPrefix(f[i].Message, loc+" contains") {
			t.Errorf("finding %d: %q, want location %q", i, f[i].Message, loc)
		}
	}
}

// A user-scope Zed settings file carries the user-scope note, like every other
// CFG050 site.
func TestCFG050_ZedEnvUserScope(t *testing.T) {
	tgt := zedTarget(t, `{"terminal": {"env": {"DB_PASSWORD": "hunter2hunter2"}}}`)
	tgt.Scope = finding.ScopeUser
	got := onlyFinding(t, CFG050.Check(tgt), finding.Error)
	if !strings.HasSuffix(got.Message, userScopeNote(tgt)) || userScopeNote(tgt) == "" {
		t.Errorf("user-scope message lacks the user-scope note: %q", got.Message)
	}
}

// ${VAR:-default} references, key-file paths and one-letter placeholders are
// not committed credentials; a literal default or a real token still is (#852).
func TestCFG050_Issue852(t *testing.T) {
	for _, js := range []string{
		`{"mcpServers":{"c7":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer ${CONTEXT7_API_KEY:-}"}}}}`,
		`{"mcpServers":{"c7":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer ${TOKEN-}"}}}}`,
		`{"mcpServers":{"c7":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer ${TOKEN:-${FALLBACK_TOKEN}}"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"API_TOKEN":"${API_TOKEN:-}"}}}}`,
		`{"mcpServers":{"a":{"command":"s","env":{"GOOGLE_APPLICATION_CREDENTIALS":"/Users/me/.secrets/application_default_credentials.json"}}}}`,
		`{"mcpServers":{"a":{"command":"s","env":{"SERVICE_ACCOUNT_CREDENTIALS":"~/keys/sa.json"}}}}`,
		`{"mcpServers":{"a":{"command":"s","env":{"SSL_PRIVATE_KEY":"./certs/dev.key"}}}}`,
		`{"mcpServers":{"g":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer X"}}}}`,
	} {
		if f := CFG050.Check(settingsTarget(t, js)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", js, f)
		}
	}
	for _, js := range []string{
		`{"mcpServers":{"c7":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer ${TOKEN:-sk-live-abcdef0123456789}"}}}}`,
		`{"mcpServers":{"g":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer ghp_abcdefghij0123456789ABCDEF"}}}}`,
		`{"mcpServers":{"g":{"type":"http","url":"https://x.example","headers":{"Authorization":"Bearer abcd1234efgh"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"DB_PASSWORD":"hunter2hunter2"}}}}`,
	} {
		if f := CFG050.Check(settingsTarget(t, js)); len(f) != 1 {
			t.Errorf("expected one finding for %s, got %+v", js, f)
		}
	}
}
