package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// The sandbox file path is what the rule derives the workspace root from, so
// tests use a realistic <workspace>/.cursor/sandbox.json shape.
const testWorkspace = "/home/dev/proj"

func cursorSandboxTarget(s *parser.CursorSandbox) *Target {
	return &Target{
		Scope:             finding.ScopeProject,
		CursorSandbox:     s,
		CursorSandboxFile: filepath.Join(testWorkspace, ".cursor", "sandbox.json"),
	}
}

func onlyFinding(t *testing.T, f []finding.Finding, sev finding.Severity) finding.Finding {
	t.Helper()
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding, got %+v", f)
	}
	if f[0].Severity != sev {
		t.Fatalf("expected severity %v, got %v (%q)", sev, f[0].Severity, f[0].Message)
	}
	return f[0]
}

func TestCFG095_InsecureNoneDisablesSandbox(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{Type: "insecure_none"}))
	got := onlyFinding(t, f, finding.Error)
	if !strings.Contains(got.Message, "disabling the sandbox entirely") {
		t.Errorf("message should quote what Cursor documents, got %q", got.Message)
	}
}

// workspace_readonly is stricter than the default and must stay silent.
func TestCFG095_StricterTypesNotFlagged(t *testing.T) {
	for _, typ := range []string{"workspace_readonly", "workspace_readwrite", ""} {
		t.Run("type="+typ, func(t *testing.T) {
			if f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{Type: typ})); len(f) != 0 {
				t.Errorf("expected no findings for %q, got %+v", typ, f)
			}
		})
	}
}

// The issue that requested this rule listed disableTmpWrite as a footgun. The
// reference says it removes write access, i.e. it hardens, so flagging it would
// report hardening as a weakness.
func TestCFG095_DisableTmpWriteIsHardeningNotFlagged(t *testing.T) {
	if f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{DisableTmpWrite: true})); len(f) != 0 {
		t.Errorf("disableTmpWrite makes the sandbox stricter and must not be flagged, got %+v", f)
	}
}

func TestCFG095_NetworkDefaultAllow(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		NetworkPolicy: &parser.CursorNetworkPolicy{Default: "allow"},
	}))
	got := onlyFinding(t, f, finding.Error)
	if !strings.Contains(got.Message, "\"deny\"") {
		t.Errorf("message should name Cursor's documented default, got %q", got.Message)
	}
}

func TestCFG095_NetworkDefaultDenyAndDenyListNotFlagged(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		NetworkPolicy: &parser.CursorNetworkPolicy{
			Default: "deny",
			Allow:   []string{"registry.npmjs.org", "*.githubusercontent.com", "10.0.0.0/8"},
			Deny:    []string{"evil.example.com"},
		},
	}))
	if len(f) != 0 {
		t.Errorf("a bounded allow list plus a deny list only tightens; got %+v", f)
	}
}

func TestCFG095_UnboundedAllowPattern(t *testing.T) {
	for _, pat := range []string{"*", "0.0.0.0/0", "::/0", "*.*"} {
		t.Run(pat, func(t *testing.T) {
			f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
				NetworkPolicy: &parser.CursorNetworkPolicy{Allow: []string{pat}},
			}))
			onlyFinding(t, f, finding.Warn)
		})
	}
}

func TestCFG095_CredentialWriteGrant(t *testing.T) {
	for _, p := range []string{"~/.ssh", "/home/dev/.aws/", "~/.gnupg", "/Users/me/.kube", "~/.config/gcloud", "~/.docker"} {
		t.Run(p, func(t *testing.T) {
			f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
				AdditionalReadwritePaths: []string{p},
			}))
			got := onlyFinding(t, f, finding.Error)
			if !strings.Contains(got.Message, "credentials") {
				t.Errorf("message should say why the path matters, got %q", got.Message)
			}
		})
	}
}

// Read access is enough to exfiltrate, so a credential dir is an error in the
// read-only list too.
func TestCFG095_CredentialReadGrant(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		AdditionalReadonlyPaths: []string{"~/.ssh"},
	}))
	got := onlyFinding(t, f, finding.Error)
	if !strings.Contains(got.Message, "read access") {
		t.Errorf("message should be about read access, got %q", got.Message)
	}
}

// Reading /usr is unremarkable; only write grants there are system findings.
func TestCFG095_SystemPathReadGrantNotFlagged(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		AdditionalReadonlyPaths: []string{"/usr/share/dict", "/etc/ssl/certs"},
	}))
	if len(f) != 0 {
		t.Errorf("a read-only system path must not be flagged, got %+v", f)
	}
}

func TestCFG095_SystemPathWriteGrant(t *testing.T) {
	for _, p := range []string{"/etc", "/usr/local/bin", "/var/lib/thing", "/root"} {
		t.Run(p, func(t *testing.T) {
			f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
				AdditionalReadwritePaths: []string{p},
			}))
			onlyFinding(t, f, finding.Error)
		})
	}
}

func TestCFG095_RootAndHomeGrant(t *testing.T) {
	for _, p := range []string{"/", "~", "$HOME", "%USERPROFILE%"} {
		t.Run(p, func(t *testing.T) {
			f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
				AdditionalReadwritePaths: []string{p},
			}))
			onlyFinding(t, f, finding.Error)
		})
	}
}

// A grant inside the workspace is the sandbox's own scope and must stay silent,
// whether it is spelled relatively or absolutely.
func TestCFG095_InsideWorkspaceGrantsSilent(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		AdditionalReadwritePaths: []string{
			"./build-cache", "build/out", testWorkspace, testWorkspace + "/target",
		},
	}))
	if len(f) != 0 {
		t.Errorf("grants inside the workspace must not be flagged, got %+v", f)
	}
}

func TestCFG095_OutsideWorkspaceWriteGrantIsWarn(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		AdditionalReadwritePaths: []string{"/srv/shared-artifacts"},
	}))
	got := onlyFinding(t, f, finding.Warn)
	if !strings.Contains(got.Message, "outside the workspace") {
		t.Errorf("message should say the grant leaves the workspace, got %q", got.Message)
	}
}

// A sibling directory must not be mistaken for an inside grant by a plain string
// prefix check.
func TestCFG095_SiblingDirectoryIsOutside(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		AdditionalReadwritePaths: []string{testWorkspace + "-other"},
	}))
	onlyFinding(t, f, finding.Warn)
}

// Without a derivable workspace root an absolute path cannot be placed, so it is
// not reported as outside; a credential path still is, on its own merits.
func TestCFG095_UnknownWorkspaceStillCatchesCredentialPaths(t *testing.T) {
	target := cursorSandboxTarget(&parser.CursorSandbox{
		AdditionalReadwritePaths: []string{"/srv/shared", "~/.ssh"},
	})
	target.CursorSandboxFile = "sandbox.json" // not <workspace>/.cursor/sandbox.json
	f := CFG095.Check(target)
	got := onlyFinding(t, f, finding.Error)
	if !strings.Contains(got.Message, ".ssh") {
		t.Errorf("expected the credential grant, got %q", got.Message)
	}
}

func TestCFG095_SharedBuildCache(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{EnableSharedBuildCache: true}))
	got := onlyFinding(t, f, finding.Warn)
	if !strings.Contains(got.Message, "share the same caches") {
		t.Errorf("message should quote the documented behaviour, got %q", got.Message)
	}
}

func TestCFG095_MultipleWeakenings(t *testing.T) {
	f := CFG095.Check(cursorSandboxTarget(&parser.CursorSandbox{
		Type:                     "insecure_none",
		NetworkPolicy:            &parser.CursorNetworkPolicy{Default: "allow", Allow: []string{"*"}},
		AdditionalReadwritePaths: []string{"~/.ssh", "/etc", "/srv/out"},
		AdditionalReadonlyPaths:  []string{"~/.aws"},
		EnableSharedBuildCache:   true,
	}))
	sev := severities(f)
	if sev[finding.Error] != 5 || sev[finding.Warn] != 3 {
		t.Fatalf("expected 5 Error + 3 Warn, got %+v", f)
	}
}

func TestCFG095_NoFindings(t *testing.T) {
	cases := map[string]*Target{
		"no sandbox file": {Scope: finding.ScopeProject},
		"empty sandbox":   cursorSandboxTarget(&parser.CursorSandbox{}),
		"blank paths": cursorSandboxTarget(&parser.CursorSandbox{
			AdditionalReadwritePaths: []string{"", "  "},
			AdditionalReadonlyPaths:  []string{"\t"},
		}),
		"hardened": cursorSandboxTarget(&parser.CursorSandbox{
			Type:            "workspace_readonly",
			DisableTmpWrite: true,
			NetworkPolicy:   &parser.CursorNetworkPolicy{Default: "deny"},
		}),
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			if f := CFG095.Check(target); len(f) != 0 {
				t.Errorf("expected no findings, got %+v", f)
			}
		})
	}
	t.Run("nil target", func(t *testing.T) {
		if f := CFG095.Check(nil); len(f) != 0 {
			t.Errorf("expected no findings, got %+v", f)
		}
	})
}

func TestCFG095_UserScopeSkipped(t *testing.T) {
	target := cursorSandboxTarget(&parser.CursorSandbox{Type: "insecure_none"})
	target.Scope = finding.ScopeUser
	if f := CFG095.Check(target); len(f) != 0 {
		t.Errorf("expected no findings at user scope, got %+v", f)
	}
}
