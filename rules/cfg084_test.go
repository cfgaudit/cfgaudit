package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG084_CommandSites(t *testing.T) {
	for _, cmd := range []string{
		"DOCKER_CONTENT_TRUST=0 docker pull alpine:3.24",
		"DOCKER_CONTENT_TRUST=false docker pull myimage",
		"docker pull --disable-content-trust myimage",
		"docker --insecure-registry=10.0.0.1:5000 pull x",
		"podman pull --disable-content-trust x",
	} {
		f := CFG084.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG084_SettingsEnv(t *testing.T) {
	for _, v := range []string{"0", "false", "no", "off", "FALSE"} {
		json := `{"env":{"DOCKER_CONTENT_TRUST":"` + v + `"}}`
		f := CFG084.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s, got %+v", v, f)
		}
	}
}

func TestCFG084_MCPServerEnv(t *testing.T) {
	f := CFG084.Check(mcpTarget(t, `{"builder":{"command":"x","env":{"DOCKER_CONTENT_TRUST":"0"}}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding on an MCP server env, got %+v", f)
	}
}

// The variable is opt-in: only an explicit disabling value is a finding, so the
// enabled value, an empty one and a runtime template all stay silent.
func TestCFG084_TrustOnOrUnknown_NoFinding(t *testing.T) {
	for _, json := range []string{
		`{"env":{"DOCKER_CONTENT_TRUST":"1"}}`,
		`{"env":{"DOCKER_CONTENT_TRUST":"true"}}`,
		`{"env":{"DOCKER_CONTENT_TRUST":""}}`,
		`{"env":{"DOCKER_CONTENT_TRUST":"$TRUST"}}`,
		`{"env":{"DOCKER_CONTENT_TRUST":"${TRUST}"}}`,
		`{"env":{"NODE_ENV":"production"}}`,
	} {
		if f := CFG084.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", json, f)
		}
	}
}

func TestCFG084_OrdinaryPulls_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		"DOCKER_CONTENT_TRUST=1 docker pull alpine:3.24",
		"docker pull alpine@sha256:abc123",
		"docker build -t app .",
	} {
		if f := CFG084.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

// A line carrying both signals is one finding, not two.
func TestCFG084_OneFindingPerSite(t *testing.T) {
	f := CFG084.Check(hookTarget(t, "DOCKER_CONTENT_TRUST=0 docker pull x --disable-content-trust"))
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(f), f)
	}
}

func TestCFG084_NoSettings_NoFinding(t *testing.T) {
	if f := CFG084.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}
