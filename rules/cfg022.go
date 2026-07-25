package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg022 struct{}

var CFG022 = &cfg022{}

func init() { All = append(All, CFG022) }

func (r *cfg022) ID() string { return "CFG022" }

// Check flags sandbox settings that weaken or hijack Claude Code's execution
// sandbox:
//
//   - bwrapPath / socatPath are honored only from managed settings; their presence
//     in any file cfgaudit scans (project, project-local, user) is an attempt to
//     point the sandbox's bubblewrap binary or network proxy at an attacker path.
//   - excludedCommands lists commands that run outside the sandbox. Excluding "*"
//     or a shell interpreter hands arbitrary code execution outside the sandbox
//     (error); other exclusions are surfaced for review (warn).
//   - allowAppleEvents (macOS) lets sandboxed commands launch other apps
//     unsandboxed and drive them via AppleScript, removing code-execution
//     isolation. It is honored only from user/managed/CLI settings — project
//     settings cannot enable it — so this fires only for user-scope targets
//     (the inverse of bwrapPath/socatPath, which are anomalous in any scanned
//     file); in a project settings file the key is inert and not flagged (warn).
func (r *cfg022) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	sb := t.Settings.Sandbox()
	if sb == nil {
		return nil
	}

	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG022",
			Severity: sev,
			File:     t.SettingsFile,
			Message:  msg + userScopeNote(t),
		})
	}

	if sb.BwrapPath != "" {
		add(finding.Error, "sandbox.bwrapPath is set to \""+sb.BwrapPath+"\" — this key is honored only from admin-managed settings; in a project/user settings file it repoints the sandbox's bubblewrap binary at an attacker-controlled path")
	}
	if sb.SocatPath != "" {
		add(finding.Error, "sandbox.socatPath is set to \""+sb.SocatPath+"\" — this key is honored only from admin-managed settings; in a project/user settings file it repoints the sandbox's network proxy (socat) at an attacker-controlled binary")
	}

	var broad, other []string
	for _, c := range sb.ExcludedCommands {
		if isBroadExclusion(c) {
			broad = append(broad, c)
		} else if strings.TrimSpace(c) != "" {
			other = append(other, c)
		}
	}
	if len(broad) > 0 {
		add(finding.Error, "sandbox.excludedCommands runs "+strings.Join(quotedList(broad), ", ")+
			" outside the sandbox — excluding a wildcard or a shell interpreter effectively disables sandboxing for arbitrary commands")
	}
	if len(other) > 0 {
		add(finding.Warn, "sandbox.excludedCommands runs "+strings.Join(quotedList(other), ", ")+
			" outside the sandbox — confirm each command genuinely needs to bypass the sandbox")
	}

	// allowAppleEvents is honored only from user/managed/CLI settings; Claude Code
	// ignores it in project/project-local settings. Flag it only where it takes
	// effect (user scope) so a committed .claude/settings.json carrying an inert
	// copy does not produce a false positive.
	if sb.AllowAppleEvents && t.Scope == finding.ScopeUser {
		add(finding.Warn, "sandbox.allowAppleEvents is true — sandboxed commands can launch other applications unsandboxed with no prompt and drive them via AppleScript, removing the sandbox's code-execution isolation (the macOS automation-consent prompt (TCC) still gates each target). Scope the specific tool with excludedCommands instead of this blanket opt-in")
	}

	// network.allowUnixSockets / allowAllUnixSockets — array/merge keys honored
	// from every scope, so a committed value applies. A privileged socket
	// (docker.sock and friends) grants host access and a full sandbox bypass.
	if sb.Network != nil {
		if sb.Network.AllowAllUnixSockets {
			add(finding.Error, "sandbox.network.allowAllUnixSockets is true — every Unix domain socket is reachable from the sandbox; a socket such as /var/run/docker.sock grants access to the host system, a full sandbox bypass. List only the specific non-privileged sockets you need in allowUnixSockets")
		}
		for _, s := range sb.Network.AllowUnixSockets {
			if privilegedUnixSocket(s) {
				add(finding.Error, "sandbox.network.allowUnixSockets grants the sandbox access to \""+strings.TrimSpace(s)+"\" — a privileged daemon socket; reaching it (e.g. the Docker socket) grants control of the host system, a sandbox bypass")
			}
		}
	}

	// filesystem.allowWrite — merged across scopes. A path covering an executable
	// search dir, a system dir, or a shell startup file lets a sandboxed command
	// plant code that later runs unsandboxed (privilege escalation).
	if sb.Filesystem != nil {
		for _, p := range sb.Filesystem.AllowWrite {
			if reason := dangerousSandboxWritePath(p); reason != "" {
				add(finding.Error, "sandbox.filesystem.allowWrite grants sandboxed commands write access to \""+strings.TrimSpace(p)+"\" ("+reason+") — a command inside the sandbox can plant code there that later runs unsandboxed, escaping the boundary. Grant write access only to specific project paths")
			}
		}
		// filesystem.disabled turns the whole filesystem-isolation layer off. It is
		// honored ONLY from user/managed/CLI settings; a project value is ignored,
		// so flag it only at user scope (the allowAppleEvents pattern).
		if sb.Filesystem.Disabled && t.Scope == finding.ScopeUser {
			add(finding.Error, "sandbox.filesystem.disabled is true — the sandbox's filesystem-isolation layer is off, so sandboxed commands get unrestricted read/write to the host filesystem (including shell-rc and $PATH) while still auto-allowed. Keep filesystem isolation on and scope specific paths with filesystem.allowWrite instead")
		}
	}

	// enableWeakerNestedSandbox / enableWeakerNetworkIsolation — booleans honored
	// from a project/user file absent a managed override. Both are documented
	// legitimate escape valves (unprivileged Docker; macOS TLS via MITM proxy), so
	// a committed one warrants review (warn) rather than an assertion of malice.
	if sb.EnableWeakerNestedSandbox {
		add(finding.Warn, "sandbox.enableWeakerNestedSandbox is true — this considerably weakens the Linux sandbox (it bind-mounts the container's existing /proc instead of a fresh one) and should only be set when an outer container already provides isolation. Remove it unless that condition holds")
	}
	if sb.EnableWeakerNetworkIsolation {
		add(finding.Warn, "sandbox.enableWeakerNetworkIsolation is true — this opens the macOS system TLS trust service to the sandbox, which the docs note reduces security by opening a potential data-exfiltration channel. Remove it unless a MITM proxy with a custom CA genuinely requires it")
	}
	return findings
}

// privilegedUnixSocket reports whether a Unix-socket path is a privileged daemon
// socket whose exposure to the sandbox grants host control (a sandbox bypass).
// The Docker socket is the canonical example the Claude Code docs call out.
func privilegedUnixSocket(p string) bool {
	base := strings.ToLower(strings.TrimSpace(p))
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "docker.sock", "dockershim.sock", "containerd.sock", "containerd.sock.ttrpc",
		"crio.sock", "podman.sock", "libvirt-sock", "libvirt-sock-ro":
		return true
	}
	// containerd/podman variants and the systemd private socket.
	return strings.Contains(base, "docker") && strings.HasSuffix(base, ".sock") ||
		strings.Contains(strings.ToLower(p), "/run/systemd/private")
}

// dangerousSandboxWritePath reports why a sandbox.filesystem.allowWrite path is a
// privilege-escalation risk, or "" when it is a safe, specific path. Dangerous:
// a broad filesystem root, an executable search directory, a system directory,
// or a shell startup file — writing to any of these lets a sandboxed command
// plant code that a later command or login runs unsandboxed.
func dangerousSandboxWritePath(p string) string {
	e := strings.TrimSpace(p)
	if e == "" {
		return ""
	}
	if isBroadSandboxPath(e) {
		return "a broad filesystem root"
	}
	lower := strings.ToLower(strings.TrimRight(e, "/"))
	// Executable search / system directories.
	for _, d := range []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/etc", "/usr/lib", "/lib", "~/.local/bin", "$home/.local/bin",
	} {
		if lower == d || strings.HasPrefix(lower, d+"/") {
			return "a system or executable-search directory"
		}
	}
	// Shell startup files.
	base := lower
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case ".bashrc", ".bash_profile", ".bash_login", ".profile",
		".zshrc", ".zshenv", ".zprofile", ".zlogin", ".kshrc", ".cshrc", ".config":
		return "a shell startup file"
	}
	return ""
}

// isBroadExclusion reports whether an excludedCommands entry hands arbitrary code
// execution outside the sandbox: the catch-all "*", or a shell interpreter
// (optionally with arguments, e.g. "bash", "bash *", "/bin/sh -c …").
func isBroadExclusion(entry string) bool {
	e := strings.TrimSpace(entry)
	if e == "*" {
		return true
	}
	fields := strings.Fields(e)
	if len(fields) == 0 {
		return false
	}
	return shellInterpreterName(fields[0]) != ""
}
