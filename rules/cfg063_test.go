package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func codexTarget(cc *parser.CodexConfig) *Target {
	return &Target{Scope: finding.ScopeUser, Codex: cc, CodexFile: "~/.codex/config.toml"}
}

func TestCFG063_Never_Error(t *testing.T) {
	f := CFG063.Check(codexTarget(&parser.CodexConfig{ApprovalPolicy: "never"}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for approval_policy=never, got %+v", f)
	}
}

func TestCFG063_OnFailure_Warn(t *testing.T) {
	f := CFG063.Check(codexTarget(&parser.CodexConfig{ApprovalPolicy: "on-failure"}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for approval_policy=on-failure, got %+v", f)
	}
}

func TestCFG063_SafeAndAbsent_NoFinding(t *testing.T) {
	for _, p := range []string{"untrusted", "on-request", ""} {
		if f := CFG063.Check(codexTarget(&parser.CodexConfig{ApprovalPolicy: p})); len(f) != 0 {
			t.Errorf("expected no finding for approval_policy=%q, got %+v", p, f)
		}
	}
	if f := CFG063.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Codex target, got %+v", f)
	}
}

func TestCFG064_DangerFullAccess_Error(t *testing.T) {
	f := CFG064.Check(codexTarget(&parser.CodexConfig{SandboxMode: "danger-full-access"}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for sandbox_mode=danger-full-access, got %+v", f)
	}
}

func TestCFG064_SafeAndAbsent_NoFinding(t *testing.T) {
	for _, m := range []string{"read-only", "workspace-write", ""} {
		if f := CFG064.Check(codexTarget(&parser.CodexConfig{SandboxMode: m})); len(f) != 0 {
			t.Errorf("expected no finding for sandbox_mode=%q, got %+v", m, f)
		}
	}
	if f := CFG064.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Codex target, got %+v", f)
	}
}

// codexProjectTarget is the committed-file counterpart of codexTarget, with a
// path CFG064 can derive a workspace root from.
func codexProjectTarget(cc *parser.CodexConfig) *Target {
	return &Target{
		Scope:     finding.ScopeProject,
		Codex:     cc,
		CodexFile: filepath.Join(testWorkspace, ".codex", "config.toml"),
	}
}

// approvals_reviewer decides who answers the prompts approval_policy still
// raises, so it is a second way to empty the loop (#432).
func TestCFG063_ApprovalsReviewer_AutoReview(t *testing.T) {
	f := CFG063.Check(codexProjectTarget(&parser.CodexConfig{ApprovalsReviewer: "auto_review"}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for approvals_reviewer=auto_review, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "approvals_reviewer") {
		t.Errorf("message should name the key, got %q", f[0].Message)
	}
}

// Codex still accepts the legacy spelling, so a file using it must not slip
// through.
func TestCFG063_ApprovalsReviewer_LegacyAlias(t *testing.T) {
	f := CFG063.Check(codexProjectTarget(&parser.CodexConfig{ApprovalsReviewer: "guardian_subagent"}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for the guardian_subagent alias, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "guardian_subagent") {
		t.Errorf("message should quote the value actually written, got %q", f[0].Message)
	}
}

func TestCFG063_ApprovalsReviewer_UserIsDefault(t *testing.T) {
	for _, v := range []string{"", "user", "  USER  "} {
		t.Run("value="+v, func(t *testing.T) {
			if f := CFG063.Check(codexProjectTarget(&parser.CodexConfig{ApprovalsReviewer: v})); len(f) != 0 {
				t.Errorf("expected no findings for %q, got %+v", v, f)
			}
		})
	}
}

// A file can be safe-looking on one key and hollow on the other; both fire and
// each names its own key.
func TestCFG063_BothKeysFire(t *testing.T) {
	f := CFG063.Check(codexProjectTarget(&parser.CodexConfig{
		ApprovalPolicy:    "never",
		ApprovalsReviewer: "auto_review",
	}))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %+v", f)
	}
	sev := severities(f)
	if sev[finding.Error] != 1 || sev[finding.Warn] != 1 {
		t.Errorf("expected 1 Error + 1 Warn, got %+v", f)
	}
}

// #432: short of disabling the sandbox, [sandbox_workspace_write] widens it.
func TestCFG064_NetworkAccess(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode:           "workspace-write",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{NetworkAccess: true},
	}))
	got := onlyFinding(t, f, finding.Error)
	if !strings.Contains(got.Message, "network_access") {
		t.Errorf("message should name the key, got %q", got.Message)
	}
}

// An unset sandbox_mode resolves to workspace-write for a directory with a trust
// decision, which is the ordinary project case, so the table still applies.
func TestCFG064_NetworkAccessWithUnsetMode(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{NetworkAccess: true},
	}))
	onlyFinding(t, f, finding.Error)
}

// Codex reads the table only under workspace-write, so an explicit read-only
// makes everything in it inert.
func TestCFG064_TableInertUnderReadOnly(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode: "read-only",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{
			NetworkAccess: true,
			WritableRoots: []string{"/etc"},
		},
	}))
	if len(f) != 0 {
		t.Errorf("the table is inert under read-only and must not be reported, got %+v", f)
	}
}

// danger-full-access bypasses the workspace-write sandbox entirely, so only that
// error is reported rather than a pile of settings Codex never reaches.
func TestCFG064_DangerFullAccessReportedAlone(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode: "danger-full-access",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{
			NetworkAccess: true,
			WritableRoots: []string{"/etc"},
		},
	}))
	got := onlyFinding(t, f, finding.Error)
	if !strings.Contains(got.Message, "danger-full-access") {
		t.Errorf("expected the sandbox-disabled finding, got %q", got.Message)
	}
}

// Both flags REMOVE a writable location, so they harden and must stay silent.
// The issue that requested this rule listed them as looseners.
func TestCFG064_ExcludeFlagsAreHardeningNotFlagged(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode: "workspace-write",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{
			ExcludeTmpdirEnvVar: true,
			ExcludeSlashTmp:     true,
		},
	}))
	if len(f) != 0 {
		t.Errorf("exclude_* flags harden the sandbox and must not be flagged, got %+v", f)
	}
}

func TestCFG064_WritableRootsClassification(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode: "workspace-write",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{
			WritableRoots: []string{
				"~/.ssh",                 // credential  → error
				"/etc",                   // system      → error
				"/srv/artifacts",         // outside     → warn
				testWorkspace + "/build", // inside      → silent
				"./cache",                // relative    → silent
			},
		},
	}))
	sev := severities(f)
	if sev[finding.Error] != 2 || sev[finding.Warn] != 1 {
		t.Fatalf("expected 2 Error + 1 Warn, got %+v", f)
	}
}

func TestCFG064_WritableRootsInsideWorkspaceSilent(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode: "workspace-write",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{
			WritableRoots: []string{testWorkspace, testWorkspace + "/target", "build/out"},
		},
	}))
	if len(f) != 0 {
		t.Errorf("grants inside the workspace must not be flagged, got %+v", f)
	}
}

// The user-global file has no workspace to compare against, so an absolute path
// is not reported as outside; a credential path still is, on its own merits.
func TestCFG064_UserFileHasNoWorkspace(t *testing.T) {
	target := codexTarget(&parser.CodexConfig{
		SandboxMode: "workspace-write",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{
			WritableRoots: []string{"/srv/shared", "~/.aws"},
		},
	})
	got := onlyFinding(t, CFG064.Check(target), finding.Error)
	if !strings.Contains(got.Message, ".aws") {
		t.Errorf("expected the credential grant, got %q", got.Message)
	}
}

func TestCFG064_EmptyTableIsSilent(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode:           "workspace-write",
		SandboxWorkspaceWrite: &parser.CodexSandboxWorkspaceWrite{},
	}))
	if len(f) != 0 {
		t.Errorf("an empty table must not be flagged, got %+v", f)
	}
}
