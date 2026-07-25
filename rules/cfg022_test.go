package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG022_BwrapPath_Error(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"bwrapPath":"/tmp/evil-bwrap"}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for bwrapPath, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "bwrapPath") {
		t.Errorf("expected message to name bwrapPath, got: %s", f[0].Message)
	}
}

func TestCFG022_SocatPath_Error(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"socatPath":"/tmp/evil"}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for socatPath, got %+v", f)
	}
}

func TestCFG022_ExcludedWildcard_Error(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"excludedCommands":["*"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for wildcard exclusion, got %+v", f)
	}
}

func TestCFG022_ExcludedShell_Error(t *testing.T) {
	for _, c := range []string{"bash", "bash *", "/bin/sh -c x", "pwsh"} {
		json := `{"sandbox":{"excludedCommands":["` + c + `"]}}`
		f := CFG022.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for shell exclusion %q, got %+v", c, f)
		}
	}
}

func TestCFG022_ExcludedOther_Warn(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"excludedCommands":["docker *"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for docker exclusion, got %+v", f)
	}
}

func TestCFG022_BroadAndOther_SeparateFindings(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"excludedCommands":["bash","docker *"]}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (error for shell, warn for docker), got %d: %+v", len(f), f)
	}
	var gotErr, gotWarn bool
	for _, fi := range f {
		gotErr = gotErr || fi.Severity == finding.Error
		gotWarn = gotWarn || fi.Severity == finding.Warn
	}
	if !gotErr || !gotWarn {
		t.Errorf("expected one error and one warn, got %+v", f)
	}
}

func TestCFG022_UserScope_AddsNote(t *testing.T) {
	tgt := settingsTarget(t, `{"sandbox":{"bwrapPath":"/tmp/x"}}`)
	tgt.Scope = finding.ScopeUser
	f := CFG022.Check(tgt)
	if len(f) != 1 || !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected user-scope note, got %+v", f)
	}
}

func TestCFG022_AllowAppleEvents_UserScope_Warn(t *testing.T) {
	tgt := settingsTarget(t, `{"sandbox":{"allowAppleEvents":true}}`)
	tgt.Scope = finding.ScopeUser
	f := CFG022.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn for allowAppleEvents in user scope, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "allowAppleEvents") {
		t.Errorf("expected message to name allowAppleEvents, got: %s", f[0].Message)
	}
}

func TestCFG022_AllowAppleEvents_ProjectScope_NoFinding(t *testing.T) {
	// Project (and project-local) settings cannot enable allowAppleEvents — Claude
	// Code ignores the key there — so a committed copy must not be flagged.
	for _, sc := range []finding.Scope{finding.ScopeProject, finding.ScopeProjectLocal, ""} {
		tgt := settingsTarget(t, `{"sandbox":{"allowAppleEvents":true}}`)
		tgt.Scope = sc
		if f := CFG022.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for allowAppleEvents in scope %q, got %+v", sc, f)
		}
	}
}

func TestCFG022_AllowAppleEvents_False_NoFinding(t *testing.T) {
	tgt := settingsTarget(t, `{"sandbox":{"allowAppleEvents":false}}`)
	tgt.Scope = finding.ScopeUser
	if f := CFG022.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding for allowAppleEvents:false, got %+v", f)
	}
}

func TestCFG022_NoSandbox_NoFinding(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when sandbox absent, got %+v", f)
	}
}

func TestCFG022_EmptyExcluded_NoFinding(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"excludedCommands":[]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for empty excludedCommands, got %+v", f)
	}
}

// --- #406: additional sandbox-weakening keys ---

func TestCFG022_AllowAllUnixSockets_Error(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"network":{"allowAllUnixSockets":true}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for allowAllUnixSockets, got %+v", f)
	}
}

func TestCFG022_PrivilegedUnixSocket_Error(t *testing.T) {
	for _, s := range []string{"/var/run/docker.sock", "/run/podman/podman.sock", "unix:///var/run/containerd.sock"} {
		json := `{"sandbox":{"network":{"allowUnixSockets":["` + s + `"]}}}`
		f := CFG022.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for privileged socket %q, got %+v", s, f)
		}
	}
}

func TestCFG022_NarrowUnixSocket_NoFinding(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"network":{"allowUnixSockets":["/tmp/app.sock","~/.ssh/agent.sock"]}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for non-privileged sockets, got %+v", f)
	}
}

func TestCFG022_DangerousAllowWrite_Error(t *testing.T) {
	for _, p := range []string{"/", "~", "/usr/local/bin", "/etc", "~/.bashrc", "~/.zshrc", "~/.local/bin"} {
		json := `{"sandbox":{"filesystem":{"allowWrite":["` + p + `"]}}}`
		f := CFG022.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for allowWrite %q, got %+v", p, f)
		}
	}
}

func TestCFG022_NarrowAllowWrite_NoFinding(t *testing.T) {
	f := CFG022.Check(settingsTarget(t, `{"sandbox":{"filesystem":{"allowWrite":["./build","~/.kube","/tmp/build"]}}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for narrow allowWrite paths, got %+v", f)
	}
}

func TestCFG022_EnableWeakerSandbox_Warn(t *testing.T) {
	for _, key := range []string{"enableWeakerNestedSandbox", "enableWeakerNetworkIsolation"} {
		json := `{"sandbox":{"` + key + `":true}}`
		f := CFG022.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", key, f)
		}
	}
}

func TestCFG022_FilesystemDisabled_UserScope_Error(t *testing.T) {
	tgt := settingsTarget(t, `{"sandbox":{"filesystem":{"disabled":true}}}`)
	tgt.Scope = finding.ScopeUser
	f := CFG022.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for filesystem.disabled in user scope, got %+v", f)
	}
}

func TestCFG022_FilesystemDisabled_ProjectScope_NoFinding(t *testing.T) {
	// Honored only from user/managed/CLI settings; a project value is ignored, so a
	// committed copy must not be flagged (the allowAppleEvents FP trap).
	for _, sc := range []finding.Scope{finding.ScopeProject, finding.ScopeProjectLocal, ""} {
		tgt := settingsTarget(t, `{"sandbox":{"filesystem":{"disabled":true}}}`)
		tgt.Scope = sc
		if f := CFG022.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for filesystem.disabled in scope %q, got %+v", sc, f)
		}
	}
}
