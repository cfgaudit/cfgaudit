package rules

import (
	"net"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg046 struct{}

var CFG046 = &cfg046{}

func init() { All = append(All, CFG046) }

func (r *cfg046) ID() string { return "CFG046" }

// Check flags OpenTelemetry exporter endpoint env vars that point at a non-local
// collector. Claude Code telemetry can include prompts, file paths, and usage
// metadata, so a repo-controlled settings.json redirecting it off-host is an
// exfiltration channel (the OTEL analogue of CFG005's ANTHROPIC_BASE_URL).
func (r *cfg046) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Env == nil {
		return nil
	}
	keys := make([]string, 0, len(t.Settings.Env))
	for k := range t.Settings.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []finding.Finding
	for _, k := range keys {
		if !isOTELEndpointKey(k) {
			continue
		}
		v := strings.TrimSpace(t.Settings.Env[k])
		if v == "" || proxyShellRefRe.MatchString(v) || proxyTargetsLoopback(v) {
			continue
		}
		sev := finding.Warn
		detail := "a non-local collector; ensure it is trusted, or point it at a loopback address"
		if host := endpointHost(v); host != "" && net.ParseIP(host) != nil {
			sev = finding.Error
			detail = "a raw IP — a hardcoded external collector; verify it is trusted or remove it"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG046",
			Severity: sev,
			File:     t.SettingsFile,
			Message: "env." + k + " sends OpenTelemetry telemetry (which can include prompts, file paths, and usage metadata) to \"" + v +
				"\" — " + detail + userScopeNote(t),
		})
	}
	return findings
}

func isOTELEndpointKey(k string) bool {
	return strings.HasPrefix(k, "OTEL_EXPORTER_OTLP_") && strings.HasSuffix(k, "ENDPOINT")
}

// endpointHost extracts the host from an endpoint URL or host:port string.
func endpointHost(v string) string {
	h := v
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") { // [ipv6] or [ipv6]:port
		if j := strings.Index(h, "]"); j >= 0 {
			return h[1:j]
		}
	}
	if strings.Count(h, ":") == 1 { // host:port (single colon → not bare IPv6)
		h = h[:strings.IndexByte(h, ':')]
	}
	return h
}
