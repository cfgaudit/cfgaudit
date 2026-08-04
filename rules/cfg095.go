package rules

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg095 struct{}

var CFG095 = &cfg095{}

func init() { All = append(All, CFG095) }

func (r *cfg095) ID() string { return "CFG095" }

// credentialGrantPaths are directories whose whole content is secret material.
// Granting the agent's sandbox access to one is a credential-exposure finding
// whether the grant is read-write or read-only, because reading is all an
// exfiltration path needs.
var credentialGrantPaths = []string{
	".ssh", ".aws", ".gnupg", ".gcloud", ".config/gcloud", ".kube", ".docker",
	".netrc", ".npmrc", ".config/gh", ".azure", ".config/op",
}

// systemGrantPaths are directories where a *write* grant escapes the workspace
// into machine state: PATH contents, service definitions, package roots. They are
// not flagged for a read-only grant, where reading /usr or /bin is unremarkable.
var systemGrantPaths = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/opt", "/var", "/boot", "/root", "/sys", "/proc",
}

// Check flags a committed Cursor .cursor/sandbox.json that weakens the agent's
// execution sandbox.
//
// Cursor merges `~/.cursor/sandbox.json` with `<workspace>/.cursor/sandbox.json`
// "with per-repo settings taking priority", so a committed file overrides the
// isolation a teammate chose for themselves. This is the sandbox-weakening family
// CFG022 covers for Claude Code, CFG061 for Gemini and CFG064 for Codex, reached
// through Cursor's file.
//
// Flagged:
//   - `type: "insecure_none"` (error) — documented as "disables the sandbox
//     entirely", the direct analogue of Codex's danger-full-access (CFG064).
//   - `networkPolicy.default: "allow"` (error) — Cursor's documented default is
//     deny, so this inverts the posture and opens outbound egress to anything not
//     explicitly denied. An exfiltration path for whatever the agent can read.
//   - an unbounded `networkPolicy.allow` entry (warn) — "*" or a
//     whole-internet CIDR re-opens egress while leaving `default` alone.
//   - a write grant to a credential directory or a system directory, or to the
//     home directory or filesystem root (error); any other write grant outside
//     the workspace (warn).
//   - a read grant to a credential directory, home or root (error) — reading is
//     enough to exfiltrate.
//
// `enableSharedBuildCache` is NOT flagged. It was, briefly. A false-positive run
// over 432 real repositories (2026-08-04, pre-v1.11.0) made it the single most
// common finding in the whole set, on roughly a third of the repositories that
// ship a .cursor/sandbox.json. Cursor documents it as a build-performance
// feature and makes no isolation claim either way, so a finding on that rate was
// reporting ordinary use of a documented option. The cache is still a channel
// across the boundary by construction; that is an argument for Cursor to
// document, not for this rule to warn on every build that uses it.
//
// Deliberately NOT flagged, because both make the sandbox *stricter*:
// `type: "workspace_readonly"`, and `disableTmpWrite: true`, which "removes
// default write access to /tmp and system temp directories". The issue that
// requested this rule listed disableTmpWrite as a footgun; the reference says the
// opposite, so flagging it would report hardening as a weakness.
//
// A grant that stays inside the workspace is not reported at all: that is the
// sandbox's own scope, and flagging it would make the rule noise in any repo that
// legitimately widens a build directory.
func (r *cfg095) Check(t *Target) []finding.Finding {
	if t == nil || t.CursorSandbox == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	s := t.CursorSandbox
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG095",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CursorSandboxFile,
			Message:  msg,
		})
	}

	if strings.EqualFold(strings.TrimSpace(s.Type), "insecure_none") {
		add(finding.Error, "committed .cursor/sandbox.json sets type \"insecure_none\", which Cursor documents as disabling the sandbox entirely — agent commands then run unconfined on every teammate who opened this repo, and the per-repo file takes priority over their own ~/.cursor/sandbox.json. Use \"workspace_readwrite\" and widen it with the specific paths the project needs")
	}

	if np := s.NetworkPolicy; np != nil {
		if strings.EqualFold(strings.TrimSpace(np.Default), "allow") {
			add(finding.Error, "committed .cursor/sandbox.json sets networkPolicy.default to \"allow\" — Cursor's documented default is \"deny\", so this inverts the sandbox's network posture and lets agent commands reach any host not explicitly listed in networkPolicy.deny, which is an outbound path for anything the agent can read. Keep default \"deny\" and name the hosts the project needs in networkPolicy.allow")
		}
		if broad := unboundedNetworkPatterns(np.Allow); len(broad) > 0 {
			add(finding.Warn, "committed .cursor/sandbox.json networkPolicy.allow contains the unbounded pattern "+quoteList(broad)+
				" — this re-opens outbound egress to everything while leaving networkPolicy.default alone. List the specific domains, wildcards or CIDR ranges the project needs")
		}
	}

	workspace := sandboxWorkspaceDir(t.CursorSandboxFile)
	rwCred, rwSystem, rwOutside := classifyGrants(s.AdditionalReadwritePaths, workspace, true)
	if len(rwCred) > 0 {
		add(finding.Error, "committed .cursor/sandbox.json additionalReadwritePaths grants the agent write access to "+quoteList(rwCred)+
			" — these hold credentials or are the home directory / filesystem root, so the grant reaches secrets and machine state well outside the workspace the sandbox exists to bound. Remove them; a path the project genuinely needs should name that path, not its parent")
	}
	if len(rwSystem) > 0 {
		add(finding.Error, "committed .cursor/sandbox.json additionalReadwritePaths grants the agent write access to the system path "+quoteList(rwSystem)+
			" — writing there changes machine state outside the workspace (binaries on PATH, service definitions, package roots) for every teammate who opened this repo. Scope the grant to a directory inside the workspace")
	}
	if len(rwOutside) > 0 {
		add(finding.Warn, "committed .cursor/sandbox.json additionalReadwritePaths grants write access outside the workspace: "+quoteList(rwOutside)+
			" — the per-repo file takes priority over a teammate's own, so this widens their sandbox without their say. Confirm each path is one the project genuinely needs")
	}

	roCred, _, _ := classifyGrants(s.AdditionalReadonlyPaths, workspace, false)
	if len(roCred) > 0 {
		add(finding.Error, "committed .cursor/sandbox.json additionalReadonlyPaths grants the agent read access to "+quoteList(roCred)+
			" — read access is all an exfiltration path needs, and these hold credentials or are the home directory / filesystem root. Remove them")
	}

	return findings
}

// sandboxWorkspaceDir derives the workspace root from the path of the sandbox
// file itself (<workspace>/.cursor/sandbox.json), so the rule can tell an inside
// grant from an outside one without the target carrying a project directory.
// Returns "" when the path does not have that shape, in which case grants are
// only classified by their own sensitivity.
func sandboxWorkspaceDir(path string) string {
	if path == "" {
		return ""
	}
	cursorDir := filepath.Dir(path)
	if filepath.Base(cursorDir) != ".cursor" {
		return ""
	}
	return filepath.Dir(cursorDir)
}

// classifyGrants sorts path grants into credential/home/root grants, system-path
// grants and merely-outside-the-workspace grants. Grants that stay inside the
// workspace are returned in none of the three: that is the sandbox's own scope.
// includeSystem is false for read-only grants, where reading /usr or /bin is
// unremarkable and flagging it would be noise.
//
// The inside-workspace check comes FIRST, before the credential and system
// classifiers. A repository can legitimately live under one of the system
// prefixes — /var on macOS (where the temp tree is /var/folders/…), /opt or
// /usr/local for a service checkout — and a grant to a directory inside such a
// workspace is not an escape from it. Classifying by path shape first reported
// those as system-path escapes.
func classifyGrants(paths []string, workspace string, includeSystem bool) (cred, system, outside []string) {
	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if isInsideWorkspace(p, workspace) {
			continue
		}
		switch {
		case isRootOrHomeGrant(p), matchesCredentialPath(p):
			cred = append(cred, p)
		case includeSystem && matchesSystemPath(p):
			system = append(system, p)
		case isOutsideWorkspace(p, workspace):
			outside = append(outside, p)
		}
	}
	sort.Strings(cred)
	sort.Strings(system)
	sort.Strings(outside)
	return cred, system, outside
}

// normalizeGrant lower-cases and strips a trailing separator so "/etc/" and
// "/etc" compare equal. Backslashes are folded to forward slashes so a Windows
// spelling is classified the same way.
func normalizeGrant(p string) string {
	n := strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	n = strings.TrimSuffix(n, "/")
	return strings.ToLower(n)
}

// isRootOrHomeGrant reports whether the grant is the filesystem root or the whole
// home directory — the two grants that make every other consideration moot.
func isRootOrHomeGrant(p string) bool {
	switch normalizeGrant(p) {
	case "", "/", "~", "$home", "${home}", "%userprofile%":
		return true
	}
	return false
}

// matchesCredentialPath reports whether the grant names a directory whose content
// is secret material, at any position in the path (so "~/.ssh", "/home/me/.ssh"
// and "/Users/me/.aws/" all match).
func matchesCredentialPath(p string) bool {
	n := normalizeGrant(p)
	for _, c := range credentialGrantPaths {
		if n == c || strings.HasSuffix(n, "/"+c) || strings.Contains(n, "/"+c+"/") {
			return true
		}
	}
	return false
}

// matchesSystemPath reports whether the grant is a system directory or something
// beneath one.
func matchesSystemPath(p string) bool {
	n := normalizeGrant(p)
	for _, s := range systemGrantPaths {
		if n == s || strings.HasPrefix(n, s+"/") {
			return true
		}
	}
	return false
}

// isInsideWorkspace reports whether a grant resolves within the workspace root.
// A relative path always does: the sandbox resolves it against the workspace. An
// absolute path does when it is the root itself or sits beneath it. A home- or
// variable-anchored path (~, $HOME, %USERPROFILE%) never counts as inside, since
// where it lands is not knowable from the file. With no derivable workspace root
// nothing can be placed inside it.
func isInsideWorkspace(p, workspace string) bool {
	n := normalizeSlashes(p)
	if n == "" || strings.HasPrefix(n, "~") || strings.HasPrefix(n, "$") || strings.HasPrefix(n, "%") {
		return false
	}
	if !strings.HasPrefix(n, "/") {
		return true // relative: resolved against the workspace
	}
	if workspace == "" {
		return false
	}
	root := strings.TrimSuffix(normalizeSlashes(workspace), "/")
	clean := strings.TrimSuffix(n, "/")
	return clean == root || strings.HasPrefix(clean, root+"/")
}

// isOutsideWorkspace reports whether an absolute grant falls outside the
// workspace root. With no known workspace, an absolute path cannot be placed, so
// it is not reported as outside.
func isOutsideWorkspace(p, workspace string) bool {
	n := normalizeSlashes(p)
	if strings.HasPrefix(n, "~") || strings.HasPrefix(n, "$") || strings.HasPrefix(n, "%") {
		return true
	}
	if !strings.HasPrefix(n, "/") || workspace == "" {
		return false
	}
	return !isInsideWorkspace(p, workspace)
}

// normalizeSlashes folds a Windows path spelling onto forward slashes so the
// workspace comparison behaves the same on every platform.
func normalizeSlashes(p string) string {
	return strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
}

// unboundedNetworkPatterns returns the allow entries that grant the whole
// internet rather than a named destination.
func unboundedNetworkPatterns(allow []string) []string {
	var out []string
	for _, raw := range allow {
		switch strings.TrimSpace(raw) {
		case "*", "*.*", "*:*", "0.0.0.0/0", "::/0":
			out = append(out, strings.TrimSpace(raw))
		}
	}
	sort.Strings(out)
	return out
}
