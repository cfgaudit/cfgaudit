// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// The SSH counterpart of the TLS kill switches (#1684). An MCP server started
// on another machine over ssh, or a hook that runs ssh or git against a remote
// host, trusts whatever key answers when host-key checking is off, so anyone
// in the network path can impersonate the host.
var (
	// sshStrictOffRe matches StrictHostKeyChecking set to no, off or
	// accept-new, as `-o StrictHostKeyChecking=no`, `-oStrictHostKeyChecking no`
	// or inside GIT_SSH_COMMAND. ssh reads option names and values without
	// regard to case.
	sshStrictOffRe = regexp.MustCompile(`(?i)StrictHostKeyChecking\s*(?:=\s*|\s+)["']?(no|off|accept-new)\b`)
	// sshKnownHostsNullRe matches UserKnownHostsFile=/dev/null, which forgets
	// every key it is shown.
	sshKnownHostsNullRe = regexp.MustCompile(`(?i)UserKnownHostsFile\s*(?:=\s*|\s+)["']?/dev/null\b`)
	// sshKeyscanTrustRe matches ssh-keyscan output appended or written to a
	// known_hosts file, directly or through tee, which trusts the key that
	// answers at that moment. ssh-keyscan printed to stdout is not a match.
	sshKeyscanTrustRe = regexp.MustCompile(`\bssh-keyscan\b[^;&|\n]*(?:>>?|\|\s*(?:sudo\s+)?tee\b[^;&|\n]*?)\s*["']?[^\s;&|"']*known_hosts\b`)
)

// sshHostKeyOff returns what in s turns off SSH host-key checking, or "".
func sshHostKeyOff(s string) string {
	var what []string
	if m := sshStrictOffRe.FindStringSubmatch(s); m != nil {
		what = append(what, "StrictHostKeyChecking="+strings.ToLower(m[1]))
	}
	if sshKnownHostsNullRe.MatchString(s) {
		what = append(what, "UserKnownHostsFile=/dev/null")
	}
	if sshKeyscanTrustRe.MatchString(s) {
		what = append(what, "ssh-keyscan output written to known_hosts")
	}
	return strings.Join(what, " and ")
}

const sshHostKeyTail = " — SSH then accepts whatever host key answers, so anyone in the network path can impersonate the host and serve the agent's tools or receive what is sent to it; pin the host key in a committed known_hosts file instead"

// checkSSHHostKey reports MCP launches, an MCP server's env GIT_SSH_COMMAND,
// and command sites (hooks, helpers and the settings env GIT_SSH_COMMAND among
// them) that turn off SSH host-key checking, at warn.
func (r *cfg075) checkSSHHostKey(t *Target) []finding.Finding {
	var findings []finding.Finding
	add := func(file string, line int, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG075",
			Severity: finding.Warn,
			File:     file,
			Line:     line,
			Message:  msg + sshHostKeyTail + userScopeNote(t),
		})
	}
	for _, ref := range t.mcpServerRefs() {
		loc := "mcpServers." + ref.Name
		launch := strings.TrimSpace(ref.Server.Command + " " + strings.Join(ref.Server.Args, " "))
		if what := sshHostKeyOff(launch); what != "" {
			add(ref.File, 0, loc+" is launched with "+what)
		}
		for _, k := range sortedKeys(ref.Server.Env) {
			if !strings.EqualFold(k, "GIT_SSH_COMMAND") || isSecretReference(ref.Server.Env[k]) {
				continue
			}
			if what := sshHostKeyOff(ref.Server.Env[k]); what != "" {
				add(ref.File, 0, loc+".env sets "+k+" with "+what)
			}
		}
	}
	for _, site := range commandSites(t) {
		if what := sshHostKeyOff(site.Command); what != "" {
			add(site.File, site.Line, site.Label+" runs with "+what)
		}
	}
	return findings
}
