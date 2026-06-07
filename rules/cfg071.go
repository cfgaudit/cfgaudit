package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg071 struct{}

var CFG071 = &cfg071{}

func init() { All = append(All, CFG071) }

func (r *cfg071) ID() string { return "CFG071" }

// Check flags a model/provider base URL — Continue models[].apiBase, Codex
// chatgpt_base_url and [model_providers.*].base_url — that uses cleartext
// (http/ws) to a non-loopback host. The provider API key is then sent in
// plaintext to a remote endpoint (the multi-provider analogue of CFG005).
//
// Unlike CFG005, a *non-default* endpoint is not itself flagged: Continue and
// Codex are multi-provider by design (Azure, OpenRouter, internal gateways, local
// Ollama are all legitimate custom endpoints over https/loopback). Only the
// unambiguous cleartext-to-remote case — where the key travels unencrypted — is
// reported, to keep false positives down.
func (r *cfg071) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	add := func(file, where, url string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG071",
			Severity: finding.Error,
			File:     file,
			Message: where + " base URL \"" + strings.TrimSpace(url) +
				"\" uses cleartext http:// to a non-loopback host — the API key is sent unencrypted to a remote endpoint. Use https:// (or a loopback address)" + userScopeNote(t),
		})
	}

	if t.Continue != nil {
		for _, m := range t.Continue.Models {
			if urlCleartextNonLoopback(m.APIBase) {
				label := "Continue model"
				if n := strings.TrimSpace(m.Name); n != "" {
					label = "Continue model \"" + n + "\""
				}
				add(t.ContinueFile, label+" apiBase", m.APIBase)
			}
		}
	}

	if t.Codex != nil {
		if urlCleartextNonLoopback(t.Codex.ChatGPTBaseURL) {
			add(t.CodexFile, "Codex chatgpt_base_url", t.Codex.ChatGPTBaseURL)
		}
		names := make([]string, 0, len(t.Codex.ModelProviders))
		for n := range t.Codex.ModelProviders {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if p := t.Codex.ModelProviders[n]; urlCleartextNonLoopback(p.BaseURL) {
				add(t.CodexFile, "Codex model_providers."+n+".base_url", p.BaseURL)
			}
		}
	}
	return findings
}

// urlCleartextNonLoopback reports whether rawURL is an http/ws (cleartext) URL to
// a non-loopback host. https/wss, loopback, env-interpolated, and reference
// values return false.
func urlCleartextNonLoopback(rawURL string) bool {
	v := strings.TrimSpace(rawURL)
	if v == "" || proxyShellRefRe.MatchString(v) {
		return false
	}
	host := endpointHost(v)
	if host == "" || strings.Contains(host, "$") {
		return false
	}
	if proxyTargetsLoopback(v) {
		return false
	}
	scheme := ""
	if i := strings.Index(v, "://"); i >= 0 {
		scheme = strings.ToLower(v[:i])
	}
	return scheme == "http" || scheme == "ws"
}
