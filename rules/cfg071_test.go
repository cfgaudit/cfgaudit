// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG071_ContinueCleartextAPIBase_Error(t *testing.T) {
	cc := &parser.ContinueConfig{Models: []parser.ContinueModel{
		{Name: "gpt", Provider: "openai", APIBase: "http://gateway.example/v1"},
	}}
	tg := &Target{Scope: finding.ScopeProject, Continue: cc, ContinueFile: ".continue/config.yaml"}
	f := CFG071.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for cleartext apiBase, got %+v", f)
	}
}

func TestCFG071_CodexCleartextBaseURLs_Error(t *testing.T) {
	cdx := &parser.CodexConfig{
		ChatGPTBaseURL: "http://chat.example/api",
		ModelProviders: map[string]parser.CodexProvider{
			"custom": {BaseURL: "ws://provider.example/v1"},
		},
	}
	tg := &Target{Scope: finding.ScopeUser, Codex: cdx, CodexFile: "~/.codex/config.toml"}
	if f := CFG071.Check(tg); len(f) != 2 {
		t.Fatalf("expected 2 Errors (chatgpt_base_url + provider), got %+v", f)
	}
}

func TestCFG071_NoFinding(t *testing.T) {
	// https / loopback / env-ref / default are all fine.
	cont := func(base string) *Target {
		return &Target{Scope: finding.ScopeProject, ContinueFile: ".continue/config.yaml",
			Continue: &parser.ContinueConfig{Models: []parser.ContinueModel{{Name: "m", APIBase: base}}}}
	}
	for _, base := range []string{
		"https://gateway.example/v1", // TLS custom endpoint — legit
		"http://localhost:11434/v1",  // local Ollama
		"http://127.0.0.1:1234/v1",   // loopback
		"${OPENAI_API_BASE}",         // env reference
		"",                           // unset
	} {
		if f := CFG071.Check(cont(base)); len(f) != 0 {
			t.Errorf("expected no finding for apiBase %q, got %+v", base, f)
		}
	}
	if f := CFG071.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}

// #779: an OpenCode provider or model base URL over cleartext to a remote host.
func TestCFG071_OpenCodeProviderURLs(t *testing.T) {
	oc := &parser.OpenCodeConfig{ProviderURLs: []parser.OpenCodeProviderURL{
		{Where: "provider.anthropic.options.baseURL", URL: "http://203.0.113.5/v1"},
		{Where: "providers.anthropic.settings.baseURL", URL: "http://gateway.example/v1"},
		{Where: "providers.a.models.m.settings.baseURL", URL: "https://gateway.example/v1"},
		{Where: "provider.ollama.options.baseURL", URL: "http://localhost:11434/v1"},
		{Where: "provider.env.options.baseURL", URL: "{env:BASE_URL}"},
	}}
	f := CFG071.Check(&Target{Scope: finding.ScopeProject, OpenCode: oc, OpenCodeFile: "opencode.json"})
	if len(f) != 2 || f[0].File != "opencode.json" || f[0].Severity != finding.Error {
		t.Fatalf("got %+v", f)
	}
	if want := `OpenCode provider.anthropic.options.baseURL base URL "http://203.0.113.5/v1"`; len(f[0].Message) < len(want) || f[0].Message[:len(want)] != want {
		t.Errorf("message: %s", f[0].Message)
	}
}

// A host on a private network is a warning; a placeholder host is not read
// (#779).
func TestCFG071_PrivateNetworkAndPlaceholders(t *testing.T) {
	for url, want := range map[string]finding.Severity{
		"http://192.168.0.78:8080/v1":            finding.Warn,
		"http://100.82.243.94:11434/v1":          finding.Warn,
		"http://[fd00::1]:8080/v1":               finding.Warn,
		"http://host.docker.internal:11434/v1":   finding.Warn,
		"http://llama_server:8080/v1":            finding.Warn,
		"http://llm.home.arpa:8000/v1":           finding.Warn,
		"http://litellm.ns.svc.cluster.local/v1": finding.Warn,
		"http://mac-studio.local.:11434":         finding.Warn,
		"http://203.0.113.5/v1":                  finding.Error,
		"http://gateway.example.com/v1":          finding.Error,
		"http://{env:OLLAMA_HOST}/v1":            "",
		"http://<lm-studio-host>:1234/v1":        "",
		"http://__IP_ADDRESS__:8080/v1":          "",
	} {
		oc := &parser.OpenCodeConfig{ProviderURLs: []parser.OpenCodeProviderURL{{Where: "provider.p.options.baseURL", URL: url}}}
		f := CFG071.Check(&Target{Scope: finding.ScopeProject, OpenCode: oc, OpenCodeFile: "opencode.json"})
		switch {
		case want == "" && len(f) != 0:
			t.Errorf("%s: want none, got %+v", url, f)
		case want != "" && (len(f) != 1 || f[0].Severity != want):
			t.Errorf("%s: want %s, got %+v", url, want, f)
		}
	}
}
