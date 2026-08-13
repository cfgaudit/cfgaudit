package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg064 struct{}

var CFG064 = &cfg064{}

func init() { All = append(All, CFG064) }

func (r *cfg064) ID() string { return "CFG064" }

// Check flags an OpenAI Codex CLI config.toml that weakens the sandbox.
//
// sandbox_mode "danger-full-access" disables it outright — tools run with full
// filesystem and network access, the Codex analog of weakening Claude Code's
// sandbox (CFG022). Combined with approval_policy: never (CFG063) that is a fully
// unattended, unsandboxed agent.
//
// Short of disabling it, the [sandbox_workspace_write] table widens what the
// workspace-write sandbox permits:
//
//   - network_access = true re-enables outbound network from inside the sandbox,
//     which otherwise runs restricted. That is an exfiltration path for anything
//     the agent can read, and it is what makes the sandbox more than a
//     filesystem guard.
//   - writable_roots adds directories the sandbox may write outside the
//     workspace. Judged like CFG095's Cursor grants: a credential directory,
//     system path, home or / is an error, anything else outside the workspace is
//     a warn, and a path inside the workspace is silent.
//
// The table is only consulted under workspace-write, so the findings are skipped
// when sandbox_mode explicitly says otherwise (see WorkspaceWriteTableApplies).
// An unset mode counts as applying, because Codex resolves it to workspace-write
// for a directory carrying a trust decision.
//
// exclude_tmpdir_env_var and exclude_slash_tmp are deliberately NOT flagged.
// Codex builds the writable set as "workdir, then /tmp unless exclude_slash_tmp,
// then $TMPDIR unless exclude_tmpdir_env_var", so setting either to true removes
// a writable location: they harden. The issue that requested this rule listed
// them as looseners to bundle, the same trap Cursor's disableTmpWrite set in
// CFG095.
func (r *cfg064) Check(t *Target) []finding.Finding {
	if t == nil || t.Codex == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG064",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CodexFile,
			Message:  msg + userScopeNote(t),
		})
	}

	fullAccess := strings.EqualFold(strings.TrimSpace(t.Codex.SandboxMode), "danger-full-access")
	findings = append(findings, r.checkPermissionProfiles(t, fullAccess)...)

	if fullAccess {
		add(finding.Error, "Codex sandbox_mode is \"danger-full-access\" — tools run with no sandbox (full filesystem and network access), analogous to weakening Claude Code's sandbox (CFG022). Use \"read-only\" or \"workspace-write\"")
		// Everything below describes the workspace-write sandbox, which this mode
		// bypasses entirely; reporting it would add noise about settings Codex
		// never reaches.
		return findings
	}

	sww := t.Codex.SandboxWorkspaceWrite
	if sww == nil || !t.Codex.WorkspaceWriteTableApplies() {
		return findings
	}

	if sww.NetworkAccess {
		add(finding.Error, "Codex [sandbox_workspace_write] sets network_access = true — the workspace-write sandbox otherwise blocks outbound network, so this re-opens an egress path for anything the agent can read, from a file every teammate inherits. Leave it unset and allow the specific network step another way")
	}

	// The user-global ~/.codex/config.toml has no workspace to be outside of, and
	// "outside the workspace" would be meaningless there, so it is classified by
	// path sensitivity alone. A credential or system grant still matters wherever
	// it is written; a merely-unusual directory is the user's own business.
	workspace := ""
	if t.Scope != finding.ScopeUser {
		workspace = codexWorkspaceDir(t.CodexFile)
	}
	cred, system, outside := classifyGrants(sww.WritableRoots, workspace, true)
	if len(cred) > 0 {
		add(finding.Error, "Codex [sandbox_workspace_write] writable_roots grants sandbox write access to "+quoteList(cred)+
			" — these hold credentials or are the home directory / filesystem root, well outside the workspace the sandbox exists to bound. Remove them")
	}
	if len(system) > 0 {
		add(finding.Error, "Codex [sandbox_workspace_write] writable_roots grants sandbox write access to the system path "+quoteList(system)+
			" — writing there changes machine state outside the workspace (binaries on PATH, service definitions, package roots). Scope the grant to a directory inside the workspace")
	}
	if len(outside) > 0 {
		add(finding.Warn, "Codex [sandbox_workspace_write] writable_roots grants sandbox write access outside the workspace: "+quoteList(outside)+
			" — confirm each path is one the project genuinely needs, since a committed entry widens the sandbox for everyone who opens the repo")
	}
	return findings
}

// checkPermissionProfiles inspects Codex's named permission profiles, the second
// permission mechanism next to sandbox_mode and [sandbox_workspace_write].
//
// Only a profile the file actually reaches is reported: the one
// default_permissions selects, plus whatever it inherits through extends. A
// dormant profile definition is not a finding, the same restraint that keeps the
// workspace-write table inert under an explicit read-only mode.
//
// networkRedundant carries the danger-full-access case. Where the sandbox is off
// entirely, a profile that opens the network adds nothing to report, so that one
// finding is suppressed as redundant. The proxy and unix-socket findings are not:
// they say where traffic goes and what it can reach, which an absent sandbox does
// not already state.
func (r *cfg064) checkPermissionProfiles(t *Target, networkRedundant bool) []finding.Finding {
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG064",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CodexFile,
			Message:  msg + userScopeNote(t),
		})
	}

	// The user-global file has no workspace to be outside of, matching how the
	// [sandbox_workspace_write] grants are classified below.
	workspace := ""
	if t.Scope != finding.ScopeUser {
		workspace = codexWorkspaceDir(t.CodexFile)
	}

	for _, sel := range t.Codex.SelectedPermissionProfiles() {
		where := "Codex permission profile \"" + sel.Name + "\""
		if sel.Name != strings.TrimSpace(t.Codex.DefaultPermissions) {
			where += " (inherited by \"" + strings.TrimSpace(t.Codex.DefaultPermissions) + "\" through extends)"
		}

		findings = append(findings, r.checkProfileFilesystem(t, sel, where, workspace)...)

		net := sel.Profile.Network
		if net == nil {
			continue
		}

		for _, p := range []struct{ field, value string }{
			{"proxy_url", net.ProxyURL},
			{"socks_url", net.SocksURL},
		} {
			if strings.TrimSpace(p.value) == "" {
				continue
			}
			add(finding.Error, where+" routes the agent's network through network."+p.field+" = \""+strings.TrimSpace(p.value)+
				"\", and default_permissions selects that profile. Every request the agent makes, and every credential header on it, goes through a host this repository picked. Codex's own project-layer denylist exists so a repo cannot \"choose where a user's credentials are sent\", and this key is not on it. Remove the proxy, or set it from your user config instead")
		}

		if net.DangerouslyAllowAllUnixSockets {
			add(finding.Error, where+" sets network.dangerously_allow_all_unix_sockets = true, which upstream names dangerous itself."+
				" It hands the agent every unix socket on the machine, including the container and service sockets that are equivalent to a root shell. Remove it")
		}

		if net.DangerouslyAllowNonLoopbackProxy {
			if strings.TrimSpace(net.ProxyURL) != "" || strings.TrimSpace(net.SocksURL) != "" {
				add(finding.Error, where+" sets network.dangerously_allow_non_loopback_proxy = true alongside a proxy URL, which upstream names dangerous itself."+
					" It is what makes the remote proxy in the same profile usable rather than rejected. Remove both")
			} else {
				add(finding.Warn, where+" sets network.dangerously_allow_non_loopback_proxy = true, which upstream names dangerous itself."+
					" On its own it proxies nothing, but it lifts the loopback restriction under any proxy URL another layer supplies. Leave it unset")
			}
		}

		if sel.Profile.NetworkOpened() && !networkRedundant {
			mode := strings.TrimSpace(net.Mode)
			if mode == "" {
				mode = "unset"
			}
			opened := where + " sets network.enabled = true (mode: " + mode + "), and default_permissions selects that profile." +
				" Measured against codex-cli 0.147.0, that flips the effective sandbox from \"restricted network\" to \"enabled network\" for anyone who trusts this directory"

			// How far the opened network reaches is decided by the [.network.domains]
			// allowlist, so it decides the severity too. Reporting a profile that
			// names its hosts as if it opened everything is the overreach CFG048
			// avoids when a terminal auto-approve map names specific commands.
			hosts, catchAll := net.EgressAllowlist()
			switch {
			case len(hosts) == 0:
				add(finding.Error, opened+", with no [.network.domains] allowlist to scope it."+
					" That is an egress path for anything the agent can read. Leave it unset and allow the specific network step another way")
			case catchAll:
				add(finding.Error, opened+". The [.network.domains] allowlist looks like a restriction but allows the catch-all "+quoteList(catchAllsIn(hosts))+
					", so it scopes nothing and the egress is open. Name the hosts the project actually needs")
			default:
				add(finding.Warn, opened+", scoped by a [.network.domains] allowlist to "+quoteList(hosts)+
					". Egress is bounded rather than open, so this is for review rather than removal: confirm every host is one the project needs, since a committed entry applies to everyone who opens the repo")
			}
		}
	}
	return findings
}

// checkProfileFilesystem inspects a selected profile's filesystem block, the most
// used part of the permission mechanism (39 of 69 real configs carry one).
//
// The block is a map of scope key or path to a decision. Only the granting
// decisions matter: real-world use is overwhelmingly hardening, with `.env`,
// `*.pem` and `~/.ssh` denials far outnumbering grants, so reporting the block's
// presence would flag people for locking things down.
//
// Path grants are classified exactly like [sandbox_workspace_write] writable_roots
// and Cursor's grants in CFG095, so `.` and `.git` stay silent while `~/.ssh`
// does not.
func (r *cfg064) checkProfileFilesystem(t *Target, sel parser.NamedCodexProfile, where, workspace string) []finding.Finding {
	rootScopes, allPaths, writePaths := sel.Profile.FilesystemGrants()
	if len(rootScopes) == 0 && len(allPaths) == 0 {
		return nil
	}
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG064",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CodexFile,
			Message:  msg + userScopeNote(t),
		})
	}

	if len(rootScopes) > 0 {
		add(finding.Error, where+" grants filesystem access over the whole machine: "+quoteList(rootScopes)+
			". The \":root\" scope is every path the process can reach, so this undoes the bound the profile exists to set. Grant the specific directories the project needs instead")
	}

	// A read of a credential path is already an exfiltration channel, so both
	// grant kinds count here. Public keys are excluded: an id_*.pub is meant to be
	// handed out, and the corpus contains a profile granting exactly that.
	cred, _, _ := classifyGrants(dropPublicKeys(allPaths), workspace, false)
	if len(cred) > 0 {
		add(finding.Error, where+" grants filesystem access to "+quoteList(cred)+
			" — these hold credentials or are the home directory / filesystem root, and a read is enough to exfiltrate them. A profile that reaches them is not bounded by the workspace at all. Remove the entries")
	}

	// System paths are judged on writes alone. Every system-path grant in the
	// corpus is a read of /bin, /usr/bin or the command line tools, which is how
	// the agent reaches its own toolchain rather than a weakening.
	_, system, _ := classifyGrants(writePaths, workspace, true)
	if len(system) > 0 {
		add(finding.Error, where+" grants filesystem write access to the system path "+quoteList(system)+
			" — writing there changes machine state outside the workspace (binaries on PATH, service definitions, package roots). Scope the grant to a directory inside the workspace")
	}

	// The plain "outside the workspace" class is deliberately NOT reported for
	// this block. It is what people name their build caches with: in the corpus it
	// fires on ~/.cargo, ~/.rustup, ~/.cache/go-build, go/pkg/mod, ~/Library/Caches
	// and an application's own support directory, 9 of the 10 files it would flag.
	// #459 removed CFG095's build-cache warn for the same reason, at a comparable
	// rate. writable_roots keeps its outside-warn because a sandbox writable root
	// is a narrower thing than a profile's read map.
	return findings
}

// dropPublicKeys removes .pub entries from a grant list. A public key is meant to
// be published, so reporting a read of one as credential exposure is a false
// positive; the corpus contains a profile granting read to ~/.ssh/id_ed25519.pub.
func dropPublicKeys(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(p)), ".pub") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// catchAllsIn returns the catch-all entries of an allowlist, so the finding can
// quote the ones that make it meaningless rather than the whole list.
func catchAllsIn(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if h == "*" || h == "**" {
			out = append(out, h)
		}
	}
	return out
}

// codexWorkspaceDir derives the workspace root from the path of the config file
// (<workspace>/.codex/config.toml), so writable_roots can be told inside from
// outside. Returns "" for the user-global file, whose parent is not a workspace;
// grants there are then judged only by their own sensitivity.
func codexWorkspaceDir(path string) string {
	if path == "" {
		return ""
	}
	codexDir := filepath.Dir(path)
	if filepath.Base(codexDir) != ".codex" {
		return ""
	}
	return filepath.Dir(codexDir)
}
