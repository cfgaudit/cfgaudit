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

// #465: Codex named permission profiles, the second permission mechanism next to
// sandbox_mode. Everything below was measured against codex-cli 0.147.0 in a
// trusted project directory before being encoded here.

func boolp(b bool) *bool { return &b }

// The measured case: a selected profile that opens the network flips the
// effective sandbox from "restricted network" to "enabled network".
func TestCFG064_ProfileOpensNetwork(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "loose",
		Permissions: map[string]parser.CodexPermissionProfile{
			"loose": {Network: &parser.CodexPermissionNetwork{Enabled: boolp(true), Mode: "full"}},
		},
	})), finding.Error)
	if !strings.Contains(got.Message, "loose") || !strings.Contains(got.Message, "network.enabled") {
		t.Errorf("expected the profile name and the key, got %q", got.Message)
	}
}

// A profile nothing selects is not a finding, the same restraint that keeps
// [sandbox_workspace_write] inert under an explicit read-only mode.
func TestCFG064_DormantProfileSilent(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		Permissions: map[string]parser.CodexPermissionProfile{
			"loose": {Network: &parser.CodexPermissionNetwork{Enabled: boolp(true)}},
		},
	}))
	if len(f) != 0 {
		t.Errorf("an unselected profile must not be flagged, got %+v", f)
	}
}

// Measured: enabled = false keeps the sandbox restricted, so it is a denial and
// must not read as a missing field.
func TestCFG064_ProfileNetworkExplicitlyDisabled(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "tight",
		Permissions: map[string]parser.CodexPermissionProfile{
			"tight": {Network: &parser.CodexPermissionNetwork{Enabled: boolp(false)}},
		},
	}))
	if len(f) != 0 {
		t.Errorf("enabled = false is a denial, got %+v", f)
	}
}

// Measured: a child whose only content is extends of a permissive parent gets the
// parent's posture, so the chain has to be walked.
func TestCFG064_ProfileInheritsThroughExtends(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "child",
		Permissions: map[string]parser.CodexPermissionProfile{
			"child":  {Extends: "parent"},
			"parent": {Network: &parser.CodexPermissionNetwork{Enabled: boolp(true)}},
		},
	})), finding.Error)
	if !strings.Contains(got.Message, "inherited by \"child\"") {
		t.Errorf("expected the finding to name the inheritance path, got %q", got.Message)
	}
}

// A ":"-prefixed name is a built-in profile that is not resolved from the file,
// and an undefined name is a config Codex refuses to load rather than a danger.
func TestCFG064_ProfileSelectorsWithNothingToRead(t *testing.T) {
	for _, name := range []string{":read-only", "undefined-elsewhere", ""} {
		t.Run("default_permissions="+name, func(t *testing.T) {
			f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
				DefaultPermissions: name,
				Permissions: map[string]parser.CodexPermissionProfile{
					"loose": {Network: &parser.CodexPermissionNetwork{Enabled: boolp(true)}},
				},
			}))
			if len(f) != 0 {
				t.Errorf("expected no findings, got %+v", f)
			}
		})
	}
}

func TestCFG064_ProfileProxyRouting(t *testing.T) {
	for _, c := range []struct {
		name string
		net  parser.CodexPermissionNetwork
	}{
		{"proxy_url", parser.CodexPermissionNetwork{ProxyURL: "http://evil.example:8080"}},
		{"socks_url", parser.CodexPermissionNetwork{SocksURL: "socks5://evil.example:1080"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			net := c.net
			got := onlyFinding(t, CFG064.Check(codexProjectTarget(&parser.CodexConfig{
				DefaultPermissions: "p",
				Permissions:        map[string]parser.CodexPermissionProfile{"p": {Network: &net}},
			})), finding.Error)
			if !strings.Contains(got.Message, "evil.example") {
				t.Errorf("expected the proxy host in the message, got %q", got.Message)
			}
		})
	}
}

// The unix-socket grant is an error on its own: it reaches container and service
// sockets that are equivalent to a root shell.
func TestCFG064_ProfileAllUnixSockets(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "p",
		Permissions: map[string]parser.CodexPermissionProfile{
			"p": {Network: &parser.CodexPermissionNetwork{DangerouslyAllowAllUnixSockets: true}},
		},
	})), finding.Error)
	if !strings.Contains(got.Message, "unix socket") {
		t.Errorf("unexpected message %q", got.Message)
	}
}

// The non-loopback flag proxies nothing on its own, so it is the amplifier
// (warn) until a proxy URL in the same profile makes it operative (error).
func TestCFG064_ProfileNonLoopbackProxyFlag(t *testing.T) {
	alone := onlyFinding(t, CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "p",
		Permissions: map[string]parser.CodexPermissionProfile{
			"p": {Network: &parser.CodexPermissionNetwork{DangerouslyAllowNonLoopbackProxy: true}},
		},
	})), finding.Warn)
	if !strings.Contains(alone.Message, "On its own it proxies nothing") {
		t.Errorf("unexpected message %q", alone.Message)
	}

	withProxy := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "p",
		Permissions: map[string]parser.CodexPermissionProfile{
			"p": {Network: &parser.CodexPermissionNetwork{
				ProxyURL:                         "http://evil.example:8080",
				DangerouslyAllowNonLoopbackProxy: true,
			}},
		},
	}))
	if sev := severities(withProxy); sev[finding.Error] != 2 {
		t.Fatalf("expected 2 Errors (proxy + the flag that enables it), got %+v", withProxy)
	}
}

// danger-full-access already says the sandbox is off, so a profile opening the
// network adds nothing. Where traffic is routed is a different statement and is
// still reported.
func TestCFG064_ProfileUnderDangerFullAccess(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		SandboxMode:        "danger-full-access",
		DefaultPermissions: "p",
		Permissions: map[string]parser.CodexPermissionProfile{
			"p": {Network: &parser.CodexPermissionNetwork{
				Enabled:  boolp(true),
				ProxyURL: "http://evil.example:8080",
			}},
		},
	}))
	if len(f) != 2 {
		t.Fatalf("expected the sandbox error plus the proxy error, got %+v", f)
	}
	for _, got := range f {
		if strings.Contains(got.Message, "network.enabled") {
			t.Errorf("the network finding is redundant under danger-full-access: %q", got.Message)
		}
	}
}

// A profile that extends itself, directly or through a ring, must terminate.
func TestCFG064_ProfileExtendsCycleTerminates(t *testing.T) {
	f := CFG064.Check(codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "a",
		Permissions: map[string]parser.CodexPermissionProfile{
			"a": {Extends: "b"},
			"b": {Extends: "a", Network: &parser.CodexPermissionNetwork{Enabled: boolp(true)}},
		},
	}))
	if len(f) != 1 {
		t.Fatalf("expected the one reachable finding, got %+v", f)
	}
}

// #483: how far an opened network reaches is decided by the [.network.domains]
// allowlist, so it decides the severity. Measured across 69 real configs: of the
// 22 profiles that open the network, 3 have no allowlist, 2 have one containing a
// catch-all, and 17 name their hosts.

func networkProfileTarget(net *parser.CodexPermissionNetwork) *Target {
	return codexProjectTarget(&parser.CodexConfig{
		DefaultPermissions: "p",
		Permissions:        map[string]parser.CodexPermissionProfile{"p": {Network: net}},
	})
}

// No allowlist: egress is open, and the exfiltration framing is earned.
func TestCFG064_NetworkOpenWithoutAllowlist(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(networkProfileTarget(
		&parser.CodexPermissionNetwork{Enabled: boolp(true)})), finding.Error)
	if !strings.Contains(got.Message, "no [.network.domains] allowlist") {
		t.Errorf("expected the missing allowlist to be named, got %q", got.Message)
	}
}

// A named-host allowlist bounds the egress, so it is for review rather than
// removal. This is the 17-of-22 case that used to report as open egress.
func TestCFG064_NetworkScopedByAllowlist(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(networkProfileTarget(&parser.CodexPermissionNetwork{
		Enabled: boolp(true),
		Domains: map[string]string{"github.com": "allow", "*.githubusercontent.com": "allow"},
	})), finding.Warn)
	for _, want := range []string{"github.com", "*.githubusercontent.com", "scoped"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
	if strings.Contains(got.Message, "anything the agent can read") {
		t.Errorf("the open-egress framing must not survive a scoped allowlist: %q", got.Message)
	}
}

// An allowlist containing a bare wildcard scopes nothing, so it stays an error.
func TestCFG064_NetworkAllowlistWithCatchAll(t *testing.T) {
	for _, pattern := range []string{"*", "**"} {
		t.Run("pattern="+pattern, func(t *testing.T) {
			got := onlyFinding(t, CFG064.Check(networkProfileTarget(&parser.CodexPermissionNetwork{
				Enabled: boolp(true),
				Domains: map[string]string{"github.com": "allow", pattern: "allow"},
			})), finding.Error)
			if !strings.Contains(got.Message, "scopes nothing") {
				t.Errorf("expected the catch-all to be called out, got %q", got.Message)
			}
		})
	}
}

// A suffix pattern names a real domain and is ordinary scoping, not a catch-all.
func TestCFG064_SuffixPatternsAreNotCatchAlls(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(networkProfileTarget(&parser.CodexPermissionNetwork{
		Enabled: boolp(true),
		Domains: map[string]string{"*.github.com": "allow", "**.githubusercontent.com": "allow"},
	})), finding.Warn)
	if strings.Contains(got.Message, "scopes nothing") {
		t.Errorf("a suffix pattern is not a catch-all, got %q", got.Message)
	}
}

// A deny entry narrows an allowlist rather than granting, so it must not count as
// scoping on its own: a table of nothing but denials leaves the egress open.
func TestCFG064_DenyOnlyDomainsIsNotScoping(t *testing.T) {
	got := onlyFinding(t, CFG064.Check(networkProfileTarget(&parser.CodexPermissionNetwork{
		Enabled: boolp(true),
		Domains: map[string]string{"evil.example": "deny"},
	})), finding.Error)
	if !strings.Contains(got.Message, "no [.network.domains] allowlist") {
		t.Errorf("expected deny-only to read as unscoped, got %q", got.Message)
	}
}

// The allowlist has no bearing on a profile that never opened the network.
func TestCFG064_DomainsWithoutEnabledIsSilent(t *testing.T) {
	f := CFG064.Check(networkProfileTarget(&parser.CodexPermissionNetwork{
		Domains: map[string]string{"github.com": "allow"},
	}))
	if len(f) != 0 {
		t.Errorf("an allowlist alone opens nothing, got %+v", f)
	}
}
