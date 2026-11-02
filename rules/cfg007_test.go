// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG007_AnthropicKey(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"ANTHROPIC_API_KEY":"sk-ant-api03-AAAAAAAAAAAAAAAAAAAA"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "Anthropic API key") {
		t.Errorf("expected message to identify Anthropic key, got: %s", f[0].Message)
	}
}

func TestCFG007_GitHubToken(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"DEPLOY_TOKEN":"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCFG007_GitLabToken(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"CI_TOKEN":"glpat-xxxxxxxxxxxxxxxxxxxx"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for GitLab PAT, got %d", len(f))
	}
}

func TestCFG007_AwsAccessKey(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"AWS_ACCESS_KEY_ID":"AKIAIOSFODNN7EXAMPLE"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for AWS key, got %d", len(f))
	}
}

func TestCFG007_SuspiciousSuffix_LiteralValue(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"JWT_SECRET":"supersecretvalue"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for *_SECRET key with literal value, got %d", len(f))
	}
}

func TestCFG007_ShellReference_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"JWT_SECRET":"$JWT_SECRET","API_TOKEN":"${API_TOKEN}"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for shell-variable references, got %d: %+v", len(f), f)
	}
}

func TestCFG007_EmptyValue_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"JWT_SECRET":""}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for empty value, got %d", len(f))
	}
}

func TestCFG007_BenignValue_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"NODE_ENV":"production","DEBUG":"true","HTTP_PORT":"8080"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for benign env vars, got %d: %+v", len(f), f)
	}
}

func TestCFG007_MultipleSecrets(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"ANTHROPIC_API_KEY":"sk-ant-api03-AAAAAAAAAAAAAAAAAAAA","DEPLOY_TOKEN":"glpat-xxxxxxxxxxxxxxxxxxxx"}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestCFG007_NoEnv_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when env absent, got %d", len(f))
	}
}

func TestCFG007_NoSettings_NoFinding(t *testing.T) {
	f := CFG007.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}

// #612: OpenCode's {env:NAME} / {file:path} substitutions and VS Code's
// ${input:id} prompt resolve at load time, so none is a committed secret.
func TestIsSecretReference_SubstitutionForms(t *testing.T) {
	for _, v := range []string{"{env:GITHUB_TOKEN}", "{file:~/.secrets/openai}", "${input:context7-api-key}", " {env:X} "} {
		if !isSecretReference(v) {
			t.Errorf("%q should count as a reference", v)
		}
	}
	for _, v := range []string{"{env:}", "sk-live-{env:X}", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"} {
		if isSecretReference(v) {
			t.Errorf("%q must not count as a reference", v)
		}
	}
}

// The same reference and path forms in settings.json env (#852).
func TestCFG007_Issue852(t *testing.T) {
	for _, js := range []string{
		`{"env":{"API_TOKEN":"${API_TOKEN:-}"}}`,
		`{"env":{"GOOGLE_APPLICATION_CREDENTIALS":"/home/me/.config/gcloud/application_default_credentials.json"}}`,
	} {
		if f := CFG007.Check(settingsTarget(t, js)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", js, f)
		}
	}
	if f := CFG007.Check(settingsTarget(t, `{"env":{"API_TOKEN":"${API_TOKEN:-abc123secret456}"}}`)); len(f) != 1 {
		t.Errorf("a literal default must still be reported, got %+v", f)
	}
}

// A relative key-file path and a boolean switch under a secret-like name are
// not literal secrets; a token and a word password still are (#891).
func TestCFG007_Issue891(t *testing.T) {
	for _, js := range []string{
		`{"env":{"GOOGLE_APPLICATION_CREDENTIALS":".codex/credentials/firebase-dev-readonly.json"}}`,
		`{"env":{"BRIDGE_PERSISTENT_SECRET":"true"}}`,
		`{"env":{"USE_API_KEY":"off"}}`,
	} {
		if f := CFG007.Check(settingsTarget(t, js)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", js, f)
		}
	}
	for _, js := range []string{
		`{"env":{"OPENAI_API_KEY":"sk-abc123def456ghi789"}}`,
		`{"env":{"DB_PASSWORD":"hunter2"}}`,
		`{"env":{"DB_PASSWORD":"123456"}}`,
		`{"env":{"API_TOKEN":"abc/def+ghi=="}}`,
	} {
		if f := CFG007.Check(settingsTarget(t, js)); len(f) != 1 {
			t.Errorf("expected one finding for %s, got %+v", js, f)
		}
	}
}

// fakeToken joins a vendor prefix and a body, so no complete sample token
// appears in the source for secret scanning to match (#1053).
func fakeToken(prefix, body string, n int) string {
	return prefix + strings.Repeat(body, n/len(body)+1)[:n]
}

func TestMatchSecretPattern_VendorFormats(t *testing.T) {
	hex := "0123456789abcdef"
	alnum := "a1B2c3D4e5F6g7H8"
	cases := []struct {
		value, label string
	}{
		{fakeToken("sk-or-"+"v1-", hex, 64), "OpenRouter API key"},
		{fakeToken("github_"+"pat_", alnum+"_", 82), "GitHub fine-grained token"},
		{fakeToken("gl"+"rt-", alnum, 20), "GitLab runner token"},
		{fakeToken("AS"+"IA", "ABCDEFGH23456789", 16), "AWS temporary access key ID"},
		{fakeToken("AB"+"SK", alnum, 60), "Amazon Bedrock API key"},
		{fakeToken("sk_"+"live_", alnum, 99), "Stripe secret key"},
		{fakeToken("rk_"+"live_", alnum, 40), "Stripe secret key"},
		{fakeToken("h"+"f_", "abcdefghABCDEFGH", 34), "Hugging Face token"},
		{fakeToken("np"+"m_", alnum, 36), "npm token"},
		{fakeToken("pypi-"+"AgEIcHlwaS5vcmc", alnum, 70), "PyPI token"},
		{fakeToken("S"+"G.", alnum, 22) + "." + strings.Repeat("x", 43), "SendGrid API key"},
		{fakeToken("S"+"K", hex, 32), "Twilio API key"},
		{fakeToken("da"+"pi", hex, 32), "Databricks token"},
		{fakeToken("hv"+"s.", alnum, 95), "HashiCorp Vault token"},
		{fakeToken("lin_"+"api_", alnum, 40), "Linear API key"},
		{"nt" + "n_" + "12345678901" + strings.Repeat("aB3", 12)[:35], "Notion token"},
		{fakeToken("gs"+"k_", alnum, 52), "Groq API key"},
		{fakeToken("xa"+"i-", alnum, 80), "xAI API key"},
		{fakeToken("pp"+"lx-", alnum, 48), "Perplexity API key"},
		{fakeToken("r"+"8_", alnum, 37), "Replicate token"},
		{fakeToken("gl"+"sa_", alnum, 32) + "_" + hex[:8], "Grafana service account token"},
		{fakeToken("dckr_"+"pat_", alnum, 27), "Docker Hub token"},
		{fakeToken("shp"+"at_", hex, 32), "Shopify token"},
		{fakeToken("dp.p"+"t.", "abcdefgh12345678", 43), "Doppler token"},
		{fakeToken("AGE-SECRET-"+"KEY-1", "QPZRY9X8GF2TVDW0", 58), "age secret key"},
		{fakeToken("lsv2_"+"pt_", hex, 32) + "_" + hex[:10], "LangSmith API key"},
		{fakeToken("pc"+"sk_", alnum, 6) + "_" + strings.Repeat("Ab1", 20), "Pinecone API key"},
		{"tskey-" + "auth-" + "kAbCdEfGh12" + "-" + strings.Repeat("Zy9", 11), "Tailscale key"},
		{fakeToken("ATAT"+"T3", alnum, 180), "Atlassian API token"},
		{"PM" + "AK-" + strings.Repeat(hex, 2)[:24] + "-" + strings.Repeat(hex, 3)[:34], "Postman API key"},
		{fakeToken("fi"+"gd_", alnum, 40), "Figma token"},
		{fakeToken("sntr"+"ys_", alnum, 60), "Sentry token"},
		{"1234567890" + ":A" + "A" + strings.Repeat("aB3_", 9)[:33], "Telegram bot token"},
		{"-----BEGIN RSA PRIVATE " + "KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "private key"},
		{"https://hooks." + "slack.com/services/" + "T0000000/B0000000/" + strings.Repeat("Xy1", 8), "Slack webhook URL"},
		{"https://discord.com/" + "api/webhooks/123456789012345678/" + strings.Repeat("aB3-", 17), "Discord webhook URL"},
		{"postgres://app:" + "Xk9mQ2vLp7w@db.prod.acme-corp.io:5432/app", "connection string with a password"},
		{"DefaultEndpointsProtocol=https;AccountName=prod;Account" + "Key=" + strings.Repeat("aB3+", 22) + "==", "connection string with a password"},
		{"eyJhbGciOiJIUzI1NiJ9." + "eyJyb2xlIjoic2VydmljZV9yb2xlIn0." + strings.Repeat("sig_", 8), "JSON Web Token"},
	}
	for _, tc := range cases {
		label, ok := matchSecretPattern(tc.value)
		if !ok || label != tc.label {
			t.Errorf("matchSecretPattern(%.24q...) = %q, %v; want %q", tc.value, label, ok, tc.label)
		}
	}
}

// Values the new formats must not catch: local development databases,
// references and placeholders in a connection string, a public Supabase anon
// key, and hex-only strings of the wrong length or prefix.
func TestMatchSecretPattern_NotSecrets(t *testing.T) {
	for _, v := range []string{
		"postgres://postgres:postgres@localhost:5432/dev",
		"postgres://app:secret@db.prod.example.com/app",
		"postgres://app:${DB_PASSWORD}@db.prod.example.com/app",
		"postgres://app:<password>@db.prod.example.com/app",
		"mysql://root:Xk9mQ2vLp7w@127.0.0.1:3306/app",
		"postgres://app:Xk9mQ2vLp7w@db.prod.example.com/app",
		"postgresql://grid_rw:fake-password-123@pg-prod-01.db.internal:5432/app",
		"postgresql://admin:hunter2@db.internal:5432/app",
		"https://example.com/path",
		"eyJhbGciOiJIUzI1NiJ9." + "eyJyb2xlIjoiYW5vbiJ9." + strings.Repeat("sig_", 8),
		"SK0123", // too short for a Twilio key
		"dapi-not-a-token",
		"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
		"https://hooks.slack.com/",
	} {
		if label, ok := matchSecretPattern(v); ok {
			t.Errorf("matchSecretPattern(%q) = %q; want no match", v, label)
		}
	}
}

// Claude Code env variables that hold a list of request headers are split and
// each header checked; a credential without a secret suffix in its name is
// recognised by name (#1053).
func TestCFG007_HeaderEnvAndKnownNames(t *testing.T) {
	sk := "sk-" + "ant-api03-" + strings.Repeat("a1B2c3D4e5", 6)
	cases := []struct {
		env, want string
	}{
		{`"ANTHROPIC_CUSTOM_HEADERS":"X-Team: platform\nAuthorization: Bearer ` + sk + `"`, "env.ANTHROPIC_CUSTOM_HEADERS header Authorization contains a hardcoded Anthropic API key"},
		{`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Basic%20dXNlcjpzM2NyZXRQYXNzMTIz,x-tenant=acme"`, "env.OTEL_EXPORTER_OTLP_HEADERS header Authorization contains a hardcoded credential"},
		{`"OTEL_EXPORTER_OTLP_TRACES_HEADERS":"x-key=Bearer q8Zt3LmW9pXa2RvN"`, "env.OTEL_EXPORTER_OTLP_TRACES_HEADERS header x-key contains a hardcoded credential"},
		{`"OTEL_EXPORTER_OTLP_HEADERS":"dd-api-key=3c7f9a2b4d6e8f0a1b3c5d7e9f1a3b5c"`, "env.OTEL_EXPORTER_OTLP_HEADERS header dd-api-key contains a hardcoded credential"},
		{`"CLAUDE_CODE_CLIENT_KEY_PASSPHRASE":"hunter2-but-longer"`, "env.CLAUDE_CODE_CLIENT_KEY_PASSPHRASE has a secret-like name"},
		{`"AWS_BEARER_TOKEN_BEDROCK":"bedrock-literal-value-123"`, "env.AWS_BEARER_TOKEN_BEDROCK has a secret-like name"},
	}
	for _, tc := range cases {
		f := CFG007.Check(settingsTarget(t, `{"env":{`+tc.env+`}}`))
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, tc.want) {
			t.Errorf("env %s: findings %+v, want one error containing %q", tc.env, f, tc.want)
			continue
		}
		if strings.Contains(f[0].Message, "q8Zt3LmW9pXa2RvN") || strings.Contains(f[0].Message, sk) {
			t.Errorf("message quotes the credential: %s", f[0].Message)
		}
	}
	for _, env := range []string{
		`"ANTHROPIC_CUSTOM_HEADERS":"X-Team: platform\nX-Trace: on"`,
		`"OTEL_EXPORTER_OTLP_HEADERS":"x-honeycomb-team=${HONEYCOMB_KEY}"`,
		`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer%20X"`,
		`"CLAUDE_CODE_CLIENT_KEY":"./certs/client.key"`,
		`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer REDACTED,x-source=claudecode"`,
		`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=ApiKey TESTKEY"`,
		`"AWS_BEARER_TOKEN_BEDROCK":"xxxx-yyyy-zzzz-0123"`,
		`"AWS_BEARER_TOKEN_BEDROCK":"<ENTER YOUR AWS BEDROCK_TOKEN HERE>"`,
	} {
		if f := CFG007.Check(settingsTarget(t, `{"env":{`+env+`}}`)); len(f) != 0 {
			t.Errorf("env %s: unexpected findings %+v", env, f)
		}
	}
}

// A credential in a permission entry, recorded from an approved command, is
// reported; references, placeholders and plain values are not (#1168).
func TestCFG007_PermissionEntries1168(t *testing.T) {
	sk := "sk-" + strings.Repeat("aB3dE5fG7h", 5)[:48]
	ghp := "ghp_" + strings.Repeat("Ab1Cd2Ef3G", 4)[:36]
	entry := func(list, e string) string {
		b, _ := json.Marshal(map[string]any{"permissions": map[string]any{list: []string{"Bash(npm run build:*)", e}}})
		return string(b)
	}
	for _, tc := range []struct{ list, entry string }{
		{"allow", `Bash(export MY_TOOL_TOKEN="` + sk + `")`},
		{"allow", `Bash(curl -H "Authorization: Bearer ` + ghp + `" https://api.github.com/user)`},
		{"ask", `Bash(curl -H "Authorization: Bearer ` + ghp + `" https://api.github.com/user)`},
		{"deny", `Bash(export MY_TOOL_TOKEN=` + sk + `)`},
		{"allow", `Bash(export DEPLOY_API_KEY="d8f7a6s5d4f3g2h1")`},
	} {
		f := CFG007.Check(settingsTarget(t, entry(tc.list, tc.entry)))
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "permissions."+tc.list+"[1]") || !strings.Contains(f[0].Message, "Rotate the key") {
			t.Errorf("%s %q: got %+v", tc.list, tc.entry, f)
			continue
		}
		if strings.Contains(f[0].Message, sk) || strings.Contains(f[0].Message, ghp) {
			t.Errorf("message quotes the secret: %s", f[0].Message)
		}
	}
	for _, e := range []string{
		`Bash(export MY_TOOL_TOKEN="$MY_TOOL_TOKEN")`,
		`Bash(export MY_TOOL_TOKEN=<your-token>)`,
		`Bash(export NODE_ENV=production)`,
		`Bash(npm run build:*)`,
		`Read(./secrets/**)`,
	} {
		if f := CFG007.Check(settingsTarget(t, entry("allow", e))); len(f) != 0 {
			t.Errorf("%q: want no finding, got %+v", e, f)
		}
	}
}
