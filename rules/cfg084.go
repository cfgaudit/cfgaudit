package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg084 struct{}

var CFG084 = &cfg084{}

func init() { All = append(All, CFG084) }

func (r *cfg084) ID() string { return "CFG084" }

// Container image trust is the registry-side sibling of CFG075's TLS
// verification: same shape — turn off the check that makes the channel
// trustworthy — for a different channel. With trust disabled, `docker pull`
// accepts an unsigned or substituted image and runs it.
var (
	// disableTrustFlagRe matches the CLI flags that skip image verification.
	// --tls-verify=false is deliberately absent: CFG075 already covers TLS
	// verification, and including it here would double-report one line.
	disableTrustFlagRe = regexp.MustCompile(`(?i)(?:^|\s)--(?:disable-content-trust(?:=true)?|insecure-registry(?:=\S+)?)\b`)

	// contentTrustAssignRe captures a DOCKER_CONTENT_TRUST assignment, inline in a
	// command or as an env-block entry.
	contentTrustAssignRe = regexp.MustCompile(`(?i)\bDOCKER_CONTENT_TRUST=("[^"]*"|'[^']*'|\S*)`)
)

// contentTrustOff reports whether a DOCKER_CONTENT_TRUST value disables image
// verification. The variable is opt-in: 1/true enables it, and anything else —
// including 0, false, and empty — leaves it off. Only an explicit disabling
// value is flagged, so an empty or templated value is not a finding.
func contentTrustOff(v string) bool {
	v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`))
	if v == "" || proxyShellRefRe.MatchString(v) {
		return false
	}
	return v == "0" || v == "false" || v == "no" || v == "off"
}

// Check flags configuration that turns off container image trust: a
// DOCKER_CONTENT_TRUST kill switch, or a --disable-content-trust /
// --insecure-registry flag, in a command site, the settings.json env block, or an
// MCP server's env.
func (r *cfg084) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(file, loc, what string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG084",
			Severity: finding.Warn,
			File:     file,
			Message: loc + " " + what + " — image signature verification is skipped, so `docker pull` accepts an unsigned or substituted image and runs it." +
				" This is the registry-side counterpart to disabling TLS verification (CFG075). Leave content trust on and pull by digest" + userScopeNote(t),
		})
	}

	if t.Settings != nil {
		if v, ok := t.Settings.Env["DOCKER_CONTENT_TRUST"]; ok && contentTrustOff(v) {
			add(t.SettingsFile, "env.DOCKER_CONTENT_TRUST", "is set to \""+strings.TrimSpace(v)+"\"")
		}
	}

	for _, ref := range t.mcpServerRefs() {
		for _, k := range sortedKeys(ref.Server.Env) {
			if strings.EqualFold(k, "DOCKER_CONTENT_TRUST") && contentTrustOff(ref.Server.Env[k]) {
				add(ref.File, "mcpServers."+ref.Name+".env."+k, "is set to \""+strings.TrimSpace(ref.Server.Env[k])+"\"")
			}
		}
	}

	for _, site := range commandSites(t) {
		if m := contentTrustAssignRe.FindStringSubmatch(site.Command); m != nil && contentTrustOff(m[1]) {
			add(site.File, site.Label, "sets DOCKER_CONTENT_TRUST="+strings.Trim(m[1], `"'`))
			continue // one finding per site; the flag check below would duplicate it
		}
		if f := disableTrustFlagRe.FindString(site.Command); f != "" {
			add(site.File, site.Label, "passes "+strings.TrimSpace(f))
		}
	}
	return findings
}
