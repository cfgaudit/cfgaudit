package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
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

	if strings.EqualFold(strings.TrimSpace(t.Codex.SandboxMode), "danger-full-access") {
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
