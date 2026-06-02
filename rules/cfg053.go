package rules

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg053 struct{}

var CFG053 = &cfg053{}

func init() { All = append(All, CFG053) }

func (r *cfg053) ID() string { return "CFG053" }

// enabledMcpSizeThreshold mirrors CFG011's alwaysAllow threshold: auto-approving
// this many .mcp.json servers is rarely a deliberate per-server decision.
const enabledMcpSizeThreshold = 10

// Check flags blanket MCP-trust settings beyond CFG003's enableAllProjectMcpServers:
//   - allowAllClaudeAiMcps: true — loads every Claude.ai MCP server (managed).
//   - enabledMcpjsonServers containing "*" — auto-approves all .mcp.json servers
//     (error); an unusually long explicit list is a softer signal (warn).
//   - allowedMcpServers with a wildcard serverUrl (e.g. "*", "https://*") — the
//     enterprise allowlist matches everything, so it restricts nothing (warn).
//
// All presence-based: absent keys produce nothing (no Claude version gating, #192).
func (r *cfg053) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	raw := t.Settings.Raw
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID: "CFG053", Severity: sev, File: t.SettingsFile, Message: msg + userScopeNote(t),
		})
	}

	if b, ok := raw["allowAllClaudeAiMcps"]; ok && string(b) == "true" {
		add(finding.Error, "allowAllClaudeAiMcps: true loads every Claude.ai MCP server with no per-server trust decision — same blanket-trust risk as enableAllProjectMcpServers (CFG003). Remove it and approve servers individually")
	}

	if enabled := decodeStringList(raw["enabledMcpjsonServers"]); len(enabled) > 0 {
		switch {
		case containsWildcard(enabled):
			add(finding.Error, "enabledMcpjsonServers contains \"*\" — auto-approves every server in .mcp.json, so a repo can add an MCP server that runs without a prompt. List only the specific servers you trust")
		case len(enabled) >= enabledMcpSizeThreshold:
			add(finding.Warn, "enabledMcpjsonServers auto-approves a large number of .mcp.json servers ("+strconv.Itoa(len(enabled))+") — review that each is intended; auto-approving this many is rarely deliberate")
		}
	}

	for _, u := range allowedServerURLs(raw["allowedMcpServers"]) {
		if isWildcardURL(u) {
			add(finding.Warn, "allowedMcpServers has a wildcard serverUrl (\""+u+"\") — the enterprise allowlist matches every server, so it restricts nothing; scope it to specific hosts")
			break
		}
	}

	return findings
}

func decodeStringList(b json.RawMessage) []string {
	if len(b) == 0 {
		return nil
	}
	var out []string
	_ = json.Unmarshal(b, &out)
	return out
}

func containsWildcard(list []string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == "*" {
			return true
		}
	}
	return false
}

// allowedServerURLs extracts the serverUrl values from an allowedMcpServers array.
func allowedServerURLs(b json.RawMessage) []string {
	if len(b) == 0 {
		return nil
	}
	var entries []struct {
		ServerURL string `json:"serverUrl"`
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil
	}
	var urls []string
	for _, e := range entries {
		if e.ServerURL != "" {
			urls = append(urls, e.ServerURL)
		}
	}
	return urls
}

// isWildcardURL reports whether a serverUrl allowlist pattern matches essentially
// any host (e.g. "*", "*://*", "https://*", "https://*/*"). A pattern scoped to a
// domain such as "https://*.example.com/*" is not considered wildcard.
func isWildcardURL(u string) bool {
	s := strings.TrimSpace(u)
	if s == "*" || s == "*://*" {
		return true
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	host := s
	if j := strings.IndexAny(host, "/:?"); j >= 0 {
		host = host[:j]
	}
	return host == "*" || host == ""
}
