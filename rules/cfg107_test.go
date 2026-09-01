package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func shellEnvTarget(set map[string]string) *Target {
	return &Target{
		Scope:     finding.ScopeProject,
		Codex:     &parser.CodexConfig{ShellEnvironmentPolicy: &parser.CodexShellEnvironmentPolicy{Set: set}},
		CodexFile: ".codex/config.toml",
	}
}

// The presence vars run code with any non-empty value.
func TestCFG107_PresenceVars(t *testing.T) {
	for _, k := range []string{"BASH_ENV", "ZDOTDIR", "PYTHONSTARTUP", "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"} {
		f := CFG107.Check(shellEnvTarget(map[string]string{k: ".codex/x"}))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Fatalf("%s: expected 1 error, got %+v", k, f)
		}
		if !strings.Contains(f[0].Message, k) {
			t.Errorf("%s: message does not name the variable: %q", k, f[0].Message)
		}
	}
}

// An empty value sets nothing, so it is not a finding.
func TestCFG107_EmptyValueIgnored(t *testing.T) {
	if f := CFG107.Check(shellEnvTarget(map[string]string{"BASH_ENV": "  "})); len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
}

// The interpreter flag vars only count when the value carries a load flag, the
// same gate CFG020 applies.
func TestCFG107_FlagGatedVars(t *testing.T) {
	if f := CFG107.Check(shellEnvTarget(map[string]string{"NODE_OPTIONS": "--max-old-space-size=4096"})); len(f) != 0 {
		t.Errorf("a memory flag is not code loading: %+v", f)
	}
	if f := CFG107.Check(shellEnvTarget(map[string]string{"NODE_OPTIONS": "--require ./evil.js"})); len(f) != 1 {
		t.Errorf("--require must be reported: %+v", f)
	}
}

// The measured false positive: an absolute CUDA library path is what real
// configs carry, and it must stay silent.
func TestCFG107_AbsoluteSearchPathIsNotReported(t *testing.T) {
	for _, k := range []string{"LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"} {
		f := CFG107.Check(shellEnvTarget(map[string]string{k: "/usr/local/cuda/lib64:/.singularity.d/libs"}))
		if len(f) != 0 {
			t.Errorf("%s: absolute entries must not be reported, got %+v", k, f)
		}
	}
}

// A relative entry points the loader at a directory the repository controls,
// and an empty entry is the working directory spelled another way.
func TestCFG107_RelativeSearchPathIsReported(t *testing.T) {
	for _, v := range []string{".codex/lib", "/usr/lib:./lib", "/usr/lib:", "lib"} {
		f := CFG107.Check(shellEnvTarget(map[string]string{"LD_LIBRARY_PATH": v}))
		if len(f) != 1 {
			t.Errorf("LD_LIBRARY_PATH=%q must be reported, got %+v", v, f)
		}
	}
}

// The keys real configs actually set are not findings.
func TestCFG107_OrdinaryVarsIgnored(t *testing.T) {
	f := CFG107.Check(shellEnvTarget(map[string]string{
		"PATH": "/usr/local/bin:/usr/bin", "CI": "1", "NODE_ENV": "development",
		"HF_HOME": "/home/agent/hf_cache", "UV_CACHE_DIR": "/tmp/uv-cache",
	}))
	if len(f) != 0 {
		t.Errorf("expected no finding, got %+v", f)
	}
}

// Findings are sorted by key so output is deterministic.
func TestCFG107_DeterministicOrder(t *testing.T) {
	f := CFG107.Check(shellEnvTarget(map[string]string{"ZDOTDIR": "a", "BASH_ENV": "b"}))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "BASH_ENV") || !strings.Contains(f[1].Message, "ZDOTDIR") {
		t.Errorf("not sorted: %q then %q", f[0].Message, f[1].Message)
	}
}

// A config without the table, or with an empty set, is silent.
func TestCFG107_AbsentIsSilent(t *testing.T) {
	if f := CFG107.Check(&Target{Codex: &parser.CodexConfig{}}); len(f) != 0 {
		t.Errorf("no table: %+v", f)
	}
	if f := CFG107.Check(shellEnvTarget(map[string]string{})); len(f) != 0 {
		t.Errorf("empty set: %+v", f)
	}
	if f := CFG107.Check(&Target{}); len(f) != 0 {
		t.Errorf("no codex config: %+v", f)
	}
}
