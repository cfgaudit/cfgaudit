package rules

import (
	"net"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

// telemetryIgnoredMinVersion is the release whose own diagnostics state that a
// project's settings file cannot configure telemetry. `claude doctor` on 2.1.282
// reports, for a repository .claude/settings.json carrying them:
//
//	Claude Code ignores these telemetry variables in .claude/settings.json:
//	CLAUDE_CODE_ENABLE_TELEMETRY, OTEL_METRICS_EXPORTER,
//	OTEL_EXPORTER_OTLP_ENDPOINT. A project's settings files can only turn
//	telemetry off: set OTEL_LOGS_EXPORTER, OTEL_METRICS_EXPORTER, or
//	OTEL_TRACES_EXPORTER to none, or a content variable such as
//	OTEL_LOG_USER_PROMPTS to 0 [...] If you set them on purpose, set them in
//	your shell, your user settings (~/.claude/settings.json), or managed
//	settings instead.
//
// So an exporter endpoint, which is never the "turn it off" direction, cannot
// open from a committed file on that release, while the same block at user or
// managed scope is live. That is the whole scope split this rule needs.
//
// The notice and the doctor entry are new in 2.1.282 (absent from the 2.1.273
// and 2.1.278 bundles); whether the filter itself is older was not established,
// so the gate sits where the evidence is. Below it, and for an undetected
// version, the finding keeps its full severity, because a repository is audited
// for the installations that will read it.
var telemetryIgnoredMinVersion = version.Version{Major: 2, Minor: 1, Patch: 282}

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
		if ignored, ver := repoScopeIgnoredFrom(t, telemetryIgnoredMinVersion); ignored {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG046",
				Severity: finding.Info,
				File:     t.SettingsFile,
				Message: "env." + k + " names an OpenTelemetry collector (\"" + v + "\"), but a repository settings file cannot switch telemetry on: Claude Code " + ver +
					" ignores telemetry variables set there, and `claude doctor` lists them, saying \"a project's settings files can only turn telemetry off\". The redirect is not in force from this file. It is reported because the intent is committed and because the same block is live at user or managed scope, which is where upstream tells people to move it — so remove it rather than copying it upward",
			})
			continue
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
