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
