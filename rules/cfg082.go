package rules

import (
	"net"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg082 struct{}

var CFG082 = &cfg082{}

func init() { All = append(All, CFG082) }

func (r *cfg082) ID() string { return "CFG082" }

var (
	// dockerRemoteScheme matches the docker daemon transports that reach off the
	// local host — tcp:// and ssh://. unix://, npipe:// and fd:// are local IPC and
	// are never a redirect.
	dockerRemoteScheme = regexp.MustCompile(`(?i)^(?:tcp|ssh)://`)

	// dockerHostAssignRe captures a DOCKER_HOST=<value> assignment, either in a
	// settings.json env block or inline in a command line (DOCKER_HOST=… docker …).
	dockerHostAssignRe = regexp.MustCompile(`(?i)\bDOCKER_HOST=("[^"]*"|'[^']*'|\S+)`)

	// dockerInvocationRe reports that a command actually invokes the docker CLI.
	// Required before a -H/--host value is trusted, since -H is also curl's header
	// flag: "curl -H tcp://…" must not be mistaken for a daemon redirect.
	dockerInvocationRe = regexp.MustCompile(`(?i)(?:^|[|;&(]|\s)docker(?:-compose)?(?:\s|$)`)

	// dockerHostFlagRe captures the value of a docker -H / --host flag.
	dockerHostFlagRe = regexp.MustCompile(`(?i)(?:^|\s)(?:-H|--host)[=\s]+("[^"]*"|'[^']*'|\S+)`)
)

// Check flags a Docker daemon redirect: a DOCKER_HOST env var, or a docker
// -H/--host flag, that points the CLI at a non-local daemon over tcp:// or ssh://.
// Claude Code 2.1.214 added a permission prompt for exactly this class — a
// repo-controlled config that redirects the daemon off-host builds and runs
// containers on, and can read images and build context from, a machine the user
// may not control. Same "trusted tool redirected off-host" family as CFG005
// (ANTHROPIC_BASE_URL) and CFG046 (OTEL endpoint). Scans the settings.json env
// block and every command site (hooks and command-running helpers). Local
// transports (unix/npipe/fd), loopback hosts, and pure $VAR values are not flagged.
func (r *cfg082) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding

	if t.Settings != nil {
		if v, ok := t.Settings.Env["DOCKER_HOST"]; ok {
			if host, remote := dockerRemoteDaemon(v); remote {
				findings = append(findings, r.finding(t.SettingsFile, "env.DOCKER_HOST", strings.Trim(strings.TrimSpace(v), `"'`), host, t))
			}
		}
	}

	for _, site := range commandSites(t) {
		if host, value, ok := dockerRedirectInCommand(site.Command); ok {
			findings = append(findings, r.finding(site.File, site.Label, value, host, t))
		}
	}
	return findings
}

// dockerRemoteDaemon returns the off-host daemon host a DOCKER_HOST / docker -H
// value points at, or ""/false when the value is local (unix/npipe/fd socket,
// loopback, empty) or a pure shell-variable reference.
func dockerRemoteDaemon(v string) (host string, ok bool) {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if v == "" || proxyShellRefRe.MatchString(v) {
		return "", false
	}
	if !dockerRemoteScheme.MatchString(v) {
		return "", false // unix://, npipe://, fd://, or bare — not a remote redirect
	}
	h := endpointHost(v)
	if h == "" || isLoopbackHost(h) {
		return "", false
	}
	return h, true
}

// dockerRedirectInCommand reports a daemon redirect inside a single command
// string — an inline DOCKER_HOST=… assignment, or a docker -H/--host flag — and
// returns the off-host daemon host and the raw value it saw.
func dockerRedirectInCommand(cmd string) (host, value string, ok bool) {
	if m := dockerHostAssignRe.FindStringSubmatch(cmd); m != nil {
		if h, remote := dockerRemoteDaemon(m[1]); remote {
			return h, strings.Trim(m[1], `"'`), true
		}
	}
	if dockerInvocationRe.MatchString(cmd) {
		for _, m := range dockerHostFlagRe.FindAllStringSubmatch(cmd, -1) {
			if h, remote := dockerRemoteDaemon(m[1]); remote {
				return h, strings.Trim(m[1], `"'`), true
			}
		}
	}
	return "", "", false
}

// finding builds the CFG082 finding: error when the daemon host is a raw IP (a
// hardcoded remote), warn for a hostname — mirroring CFG046's severity split.
func (r *cfg082) finding(file, loc, value, host string, t *Target) finding.Finding {
	sev := finding.Warn
	tail := "a host you may not control; point DOCKER_HOST at the local socket or remove it"
	if net.ParseIP(host) != nil {
		sev = finding.Error
		tail = "a raw IP — a hardcoded remote daemon; verify you control it or remove it"
	}
	return finding.Finding{
		RuleID:   "CFG082",
		Severity: sev,
		File:     file,
		Message: loc + " points the Docker CLI at a remote daemon (\"" + value + "\") — containers then build and run on, and images and build context can be read from, " + tail +
			". A repo-controlled config has no business redirecting the Docker daemon off-host" + userScopeNote(t),
	}
}
