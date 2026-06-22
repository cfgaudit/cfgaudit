package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// mcpTarget builds a Target whose .mcp.json carries the given servers JSON.
func mcpTarget(t *testing.T, serversJSON string) *Target {
	t.Helper()
	return settingsTarget(t, `{"mcpServers":`+serversJSON+`}`)
}

func TestCFG075_NodeTLSReject_Error(t *testing.T) {
	f := CFG075.Check(mcpTarget(t, `{"s":{"command":"node","env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "NODE_TLS_REJECT_UNAUTHORIZED") || !strings.Contains(f[0].Message, "MITM") {
		t.Errorf("message should name the key and MITM risk, got: %s", f[0].Message)
	}
}

func TestCFG075_EnvKillSwitches(t *testing.T) {
	cases := []struct {
		key, val string
		flag     bool
	}{
		{"NODE_TLS_REJECT_UNAUTHORIZED", "0", true},
		{"NODE_TLS_REJECT_UNAUTHORIZED", "1", false}, // 1 = verification ON
		{"PYTHONHTTPSVERIFY", "0", true},
		{"GIT_SSL_NO_VERIFY", "true", true},
		{"GIT_SSL_NO_VERIFY", "false", false},
		{"SSL_VERIFY", "false", true},
		{"NPM_CONFIG_STRICT_SSL", "false", true},
		{"PGSSLMODE", "disable", true},
		{"PGSSLMODE", "require", false},
		{"REQUESTS_CA_BUNDLE", "", true},             // empty bundle
		{"REQUESTS_CA_BUNDLE", "/etc/ca.pem", false}, // a real bundle
		{"VERIFY_SSL", "false", true},                // generic key form
		{"HTTPX_SSL_VERIFY", "0", true},              // generic key form
		{"SSL_VERIFY", "true", false},
	}
	for _, c := range cases {
		j := `{"s":{"env":{"` + c.key + `":"` + c.val + `"}}}`
		f := CFG075.Check(mcpTarget(t, j))
		if c.flag && len(f) != 1 {
			t.Errorf("%s=%q: expected 1 finding, got %d", c.key, c.val, len(f))
		}
		if !c.flag && len(f) != 0 {
			t.Errorf("%s=%q: expected no finding, got %+v", c.key, c.val, f)
		}
	}
}

func TestCFG075_SslmodeDisable_InConnectionString(t *testing.T) {
	// A password in the connection string must NOT be echoed into the finding.
	j := `{"s":{"env":{"DATABASE_URL":"postgres://u:secretpw@host/db?sslmode=disable"}}}` //nolint:gosec // G101: test fixture credential, asserting it is NOT echoed into the finding
	f := CFG075.Check(mcpTarget(t, j))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error for sslmode=disable, got %+v", f)
	}
	if strings.Contains(f[0].Message, "secretpw") {
		t.Errorf("finding must not echo the connection-string password: %s", f[0].Message)
	}
}

func TestCFG075_Args_Insecure_And_NoCheckCert(t *testing.T) {
	for _, arg := range []string{"--insecure", "--no-check-certificate"} {
		j := `{"s":{"command":"sh","args":["-c","x ` + arg + `","` + arg + `"]}}`
		f := CFG075.Check(mcpTarget(t, j))
		if len(f) < 1 {
			t.Errorf("arg %q: expected a finding, got none", arg)
		}
	}
}

func TestCFG075_DashK_GatedOnCurlWget(t *testing.T) {
	// -k with a curl command → flagged.
	f := CFG075.Check(mcpTarget(t, `{"s":{"command":"curl","args":["-k","https://x"]}}`))
	if len(f) != 1 {
		t.Errorf("expected -k flagged for curl, got %+v", f)
	}
	// -k with a non-curl command (e.g. kustomize) → not flagged (too ambiguous).
	f = CFG075.Check(mcpTarget(t, `{"s":{"command":"kubectl","args":["apply","-k","./overlay"]}}`))
	if len(f) != 0 {
		t.Errorf("expected -k NOT flagged for kubectl, got %+v", f)
	}
}

func TestCFG075_TemplatedValue_Skipped(t *testing.T) {
	for _, v := range []string{"${TLS_VERIFY}", "$(get_flag)", "{{INSECURE}}"} {
		j := `{"s":{"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"` + v + `"}}}`
		if f := CFG075.Check(mcpTarget(t, j)); len(f) != 0 {
			t.Errorf("templated value %q should be skipped, got %+v", v, f)
		}
	}
}

func TestCFG075_Benign_NoFinding(t *testing.T) {
	benign := []string{
		`{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-git"]}}`,
		`{"s":{"env":{"NODE_ENV":"production","LOG_LEVEL":"warn"}}}`,
		`{"s":{"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"1","PGSSLMODE":"require"}}}`,
		`{"s":{"command":"node","args":["server.js","--port","8080"]}}`,
	}
	for _, j := range benign {
		if f := CFG075.Check(mcpTarget(t, j)); len(f) != 0 {
			t.Errorf("benign config %s should produce no finding, got %+v", j, f)
		}
	}
}

func TestCFG075_NoServers_NoFinding(t *testing.T) {
	if f := CFG075.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding without MCP servers, got %+v", f)
	}
}

func TestCFG075_UserScope_AddsNote(t *testing.T) {
	tgt := mcpTarget(t, `{"s":{"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}}`)
	tgt.Scope = finding.ScopeUser
	f := CFG075.Check(tgt)
	if len(f) != 1 || !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected user-scope note, got %+v", f)
	}
}
