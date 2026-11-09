// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg071 struct{}

var CFG071 = &cfg071{}

func init() { All = append(All, CFG071) }

func (r *cfg071) ID() string { return "CFG071" }

// Check flags a model/provider base URL — Continue models[].apiBase, Codex
// chatgpt_base_url and [model_providers.*].base_url, OpenCode provider and
// model base URLs — that uses cleartext
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
		sev := finding.Error
		msg := where + " base URL \"" + strings.TrimSpace(url) +
			"\" uses cleartext http:// to a non-loopback host — the API key is sent unencrypted to a remote endpoint. Use https:// (or a loopback address)"
		if privateNetworkHost(endpointHost(strings.TrimSpace(url))) {
			// Mostly a model server on the author's own network (Ollama, LM
			// Studio, a cluster gateway), often without a key at all (#779).
			sev = finding.Warn
			msg = where + " base URL \"" + strings.TrimSpace(url) +
				"\" uses cleartext http:// to a host on a private network — an API key, if the server takes one, crosses that network unencrypted, and so does every prompt. Use https:// (or a loopback address)"
		}
		findings = append(findings, finding.Finding{RuleID: "CFG071", Severity: sev, File: file, Message: msg + userScopeNote(t)})
	}

	if t.Junie != nil {
		for _, p := range t.Junie.Proxies {
			if urlCleartextNonLoopback(p.APIURL) {
				add(t.JunieFile, "Junie proxies api-url", p.APIURL)
			}
		}
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
		// A data entry's destination is where session content is sent, so the same
		// cleartext test applies: what travels is the session rather than the API
		// key, which is worse rather than better.
		//
		// Only cleartext-to-remote is reported, for the reason the rest of this
		// rule gives and one more from measurement: the single real data block in a
		// 108-config sample points at a file:// path on the author's own machine.
		// A finding on any non-default destination would have been wrong on the
		// only occurrence there is.
		for _, d := range t.Continue.Data {
			if !urlCleartextNonLoopback(d.Destination) {
				continue
			}
			label := "Continue data"
			if n := strings.TrimSpace(d.Name); n != "" {
				label = "Continue data \"" + n + "\""
			}
			if strings.EqualFold(strings.TrimSpace(d.Level), "all") {
				label += " (level: all, so the session content includes code)"
			}
			add(t.ContinueFile, label+" destination", d.Destination)
		}
	}

	// OpenCode provider and model base URLs (#779). The provider's API key goes
	// with every request to that host.
	if t.OpenCode != nil {
		for _, u := range t.OpenCode.ProviderURLs {
			if urlCleartextNonLoopback(u.URL) {
				add(t.OpenCodeFile, "OpenCode "+u.Where, u.URL)
			}
		}
	}

	// qwen modelProviders entries (#1565): the API key from envKey goes to
	// baseUrl with every request.
	if t.Qwen != nil && t.Scope != finding.ScopeUser {
		for _, p := range t.Qwen.ModelProviderEntries() {
			if urlCleartextNonLoopback(p.BaseURL) {
				add(t.QwenFile, "qwen modelProviders."+p.AuthType+"["+p.ID+"]", p.BaseURL)
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
	// $NAME, OpenCode's {env:NAME}, and a placeholder such as <host> or
	// __HOST__ are filled in on the reader's machine (#779).
	if host == "" || strings.ContainsAny(host, "${<") || strings.HasPrefix(host, "__") {
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

// cgnat is the shared address space of RFC 6598, which Tailscale and carriers
// hand out.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// privateNetworkSuffixes are name suffixes that resolve only inside a local or
// cluster network.
var privateNetworkSuffixes = []string{".local", ".lan", ".internal", ".home.arpa", ".localdomain", ".intranet", ".home", ".consul", ".cluster.local"}

// privateNetworkHost reports whether host names a machine on a private
// network: a private, shared (CGNAT) or link-local address, a name without a
// dot (a container or LAN host name), or a name under a local-only suffix.
func privateNetworkHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsPrivate() || addr.IsLinkLocalUnicast() || cgnat.Contains(addr)
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h != "" && !strings.Contains(h, ".") {
		return true
	}
	for _, suf := range privateNetworkSuffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}
