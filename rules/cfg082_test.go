package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG082_EnvDockerHost_RemoteHostname_Warn(t *testing.T) {
	for _, v := range []string{"tcp://build.internal:2375", "ssh://deploy@prod.example"} {
		json := `{"env":{"DOCKER_HOST":"` + v + `"}}`
		f := CFG082.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %q, got %+v", v, f)
		}
	}
}

func TestCFG082_EnvDockerHost_RawIP_Error(t *testing.T) {
	for _, v := range []string{"tcp://203.0.113.10:2375", "tcp://[2001:db8::1]:2375"} {
		json := `{"env":{"DOCKER_HOST":"` + v + `"}}`
		f := CFG082.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected Error for raw IP %q, got %+v", v, f)
		}
	}
}

func TestCFG082_EnvDockerHost_LocalOrLoopback_NoFinding(t *testing.T) {
	for _, v := range []string{
		"unix:///var/run/docker.sock", // default local socket
		"npipe:////./pipe/docker_engine",
		"fd://",
		"tcp://127.0.0.1:2375",
		"tcp://localhost:2375",
		"tcp://[::1]:2375",
		"tcp://0.0.0.0:2375",
		"",
		"$DOCKER_HOST",
		"${REMOTE_DOCKER}",
	} {
		json := `{"env":{"DOCKER_HOST":"` + v + `"}}`
		if f := CFG082.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", v, f)
		}
	}
}

func TestCFG082_CommandFlag_RawIP_Error(t *testing.T) {
	for _, cmd := range []string{
		"docker -H tcp://10.0.0.5:2375 run --rm alpine id",
		"docker --host=tcp://10.0.0.5:2375 ps",
	} {
		f := CFG082.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG082_CommandInlineEnv_Warn(t *testing.T) {
	f := CFG082.Check(hookTarget(t, "DOCKER_HOST=ssh://deploy@prod.example docker compose up -d"))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
}

func TestCFG082_ScansHelperCommands(t *testing.T) {
	f := CFG082.Check(settingsTarget(t, `{"apiKeyHelper":"docker -H tcp://198.51.100.9:2375 run keyminter"}`))
	if len(f) != 1 {
		t.Fatalf("expected CFG082 on apiKeyHelper helper, got %+v", f)
	}
}

func TestCFG082_LocalDockerCommand_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		"docker build -t app .",
		"docker -H unix:///var/run/docker.sock ps",
		"docker --host tcp://127.0.0.1:2375 ps",
		// -H belongs to curl, not docker: not a daemon redirect.
		`curl -H "Authorization: Bearer x" https://api.example/v1`,
		// -H with a header value even alongside a docker invocation must not fire
		// (value is not a tcp/ssh daemon URL).
		`docker build . && curl -H "X-Trace: 1" https://api.example`,
	} {
		if f := CFG082.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG082_OneFindingPerSite(t *testing.T) {
	// A command carrying both an inline DOCKER_HOST and a -H flag yields one finding.
	f := CFG082.Check(hookTarget(t, "DOCKER_HOST=tcp://10.0.0.1:2375 docker -H tcp://10.0.0.2:2375 ps"))
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(f), f)
	}
}

func TestCFG082_NoSettings_NoFinding(t *testing.T) {
	if f := CFG082.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}
