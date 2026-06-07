package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg069 struct{}

var CFG069 = &cfg069{}

func init() { All = append(All, CFG069) }

func (r *cfg069) ID() string { return "CFG069" }

// httpTransportTruthyKeys enable HTTP transport when set truthy; transportModeKeys
// enable it when their value names http(s). An HTTP-transport MCP server logs full
// request bodies — Bearer tokens, API keys — at default log levels.
var (
	httpTransportTruthyKeys = map[string]bool{
		"MCP_HTTP_ENABLED": true, "HTTP_ENABLED": true, "USE_HTTP": true,
		"HTTP_SERVER": true, "ENABLE_HTTP": true,
	}
	transportModeKeys = map[string]bool{
		"MCP_TRANSPORT": true, "TRANSPORT": true, "SERVER_MODE": true, "MCP_MODE": true,
	}

	// Signals that request logging is redacted or quiet.
	redactTruthyKeys      = map[string]bool{"LOG_REDACT": true, "REDACT_LOGS": true, "DISABLE_REQUEST_LOGGING": true, "NO_REQUEST_LOGGING": true, "REDACT": true}
	sensitiveLogFalsyKeys = map[string]bool{"MCP_LOG_SENSITIVE": true, "LOG_SENSITIVE": true, "REQUEST_LOGGING": true, "LOG_REQUESTS": true, "LOG_REQUEST_BODY": true}
	logLevelKeys          = map[string]bool{"LOG_LEVEL": true, "MCP_LOG_LEVEL": true, "LOGLEVEL": true}
	quietLogLevels        = map[string]bool{"warn": true, "warning": true, "error": true, "err": true, "fatal": true, "critical": true, "crit": true, "silent": true, "off": true, "none": true}
)

// Check flags an MCP server whose env enables HTTP transport without configuring
// log redaction or a low-verbosity log level. Such servers log full request
// bodies — including credentials in headers/bodies — at default levels, exposing
// them in log files (CVE-2026-42282 / CVE-2026-41495). Covers settings.json
// mcpServers and .mcp.json.
func (r *cfg069) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		key := httpTransportEnabledKey(ref.Server.Env)
		if key == "" || safeLoggingConfigured(ref.Server.Env) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG069",
			Severity: finding.Warn,
			File:     ref.File,
			Message: "mcpServers." + ref.Name + ".env enables HTTP transport (" + key +
				") without a log-redaction or low-verbosity setting — an HTTP-transport MCP server logs full request bodies, including Bearer tokens and API keys, at default log levels (CVE-2026-42282/41495). Set LOG_LEVEL to warn/error, enable request-log redaction, or use stdio transport" + userScopeNote(t),
		})
	}
	return findings
}

// httpTransportEnabledKey returns the (sorted-first) env key that enables HTTP
// transport, or "".
func httpTransportEnabledKey(env map[string]string) string {
	var keys []string
	for k, v := range env {
		up := strings.ToUpper(strings.TrimSpace(k))
		if httpTransportTruthyKeys[up] && isTruthy(v) {
			keys = append(keys, k)
		} else if transportModeKeys[up] && strings.Contains(strings.ToLower(v), "http") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return keys[0]
}

// safeLoggingConfigured reports whether the env constrains request logging — a
// redaction flag, a "don't log sensitive" flag set false, or a quiet log level.
func safeLoggingConfigured(env map[string]string) bool {
	for k, v := range env {
		up := strings.ToUpper(strings.TrimSpace(k))
		switch {
		case redactTruthyKeys[up] && isTruthy(v):
			return true
		case sensitiveLogFalsyKeys[up] && isFalsy(v):
			return true
		case logLevelKeys[up] && quietLogLevels[strings.ToLower(strings.TrimSpace(v))]:
			return true
		}
	}
	return false
}
