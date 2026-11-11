// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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
	// Use the libpq key/value DSN form (not a user:pass@ URL) so the fixture does
	// not trip gosec's "password in URL" heuristic.
	j := `{"s":{"env":{"PG_DSN":"host=h dbname=db password=hunter2pw sslmode=disable"}}}`
	f := CFG075.Check(mcpTarget(t, j))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error for sslmode=disable, got %+v", f)
	}
	if strings.Contains(f[0].Message, "hunter2pw") {
		t.Errorf("finding must not echo the connection-string password: %s", f[0].Message)
	}
}

func TestCFG075_SslmodeDisable_LoopbackSkipped(t *testing.T) {
	// sslmode=disable against a loopback DB is conventional local-dev config and
	// must NOT be flagged (no network path to MITM).
	for _, v := range []string{
		"postgresql://user:pw@localhost:5432/db?sslmode=disable",
		"postgres://app@127.0.0.1/db?sslmode=disable",
		"postgresql://[::1]:5432/db?sslmode=disable",
		"host=localhost dbname=db sslmode=disable",
	} {
		j := `{"s":{"env":{"DATABASE_URL":` + `"` + v + `"` + `}}}`
		if f := CFG075.Check(mcpTarget(t, j)); len(f) != 0 {
			t.Errorf("loopback %q should be skipped, got %+v", v, f)
		}
	}
}

func TestCFG075_SslmodeDisable_RemoteHost_Flagged(t *testing.T) {
	for _, v := range []string{
		"postgresql://user:pw@db.example.com:5432/db?sslmode=disable",
		"host=prod-db.internal dbname=db sslmode=disable",
	} {
		j := `{"s":{"env":{"DATABASE_URL":` + `"` + v + `"` + `}}}`
		if f := CFG075.Check(mcpTarget(t, j)); len(f) != 1 {
			t.Errorf("remote %q should be flagged, got %+v", v, f)
		}
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

// #744: the TLS kill switches and a CA bundle in the Claude Code settings env.
func TestCFG075_SettingsEnv(t *testing.T) {
	f := CFG075.Check(settingsTarget(t, `{"env":{"HTTPS_PROXY":"http://203.0.113.7:8080","NODE_TLS_REJECT_UNAUTHORIZED":"0"}}`))
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "NODE_TLS_REJECT_UNAUTHORIZED=0") {
		t.Fatalf("expected one error for the TLS switch, got %+v", f)
	}
	f = CFG075.Check(settingsTarget(t, `{"env":{"NODE_EXTRA_CA_CERTS":"./certs/proxy-ca.pem","SSL_CERT_FILE":"/etc/ssl/corp.pem","GIT_SSL_NO_VERIFY":"true"}}`))
	sev := map[finding.Severity]int{}
	for _, x := range f {
		sev[x.Severity]++
	}
	if sev[finding.Warn] != 2 || sev[finding.Error] != 1 {
		t.Fatalf("expected two CA-bundle warnings and one error, got %+v", f)
	}
	user := settingsTarget(t, `{"env":{"NODE_EXTRA_CA_CERTS":"/etc/ssl/corp.pem"}}`)
	user.Scope = finding.ScopeUser
	if f := CFG075.Check(user); len(f) != 1 || !strings.Contains(f[0].Message, "2.1.307") {
		t.Errorf("expected the user-scope wording, got %+v", f)
	}
	for _, env := range []string{
		`{"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"1"}}`,
		`{"env":{"NODE_EXTRA_CA_CERTS":"${CORP_CA}"}}`,
		`{"env":{"NODE_EXTRA_CA_CERTS":""}}`,
	} {
		if f := CFG075.Check(settingsTarget(t, env)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", env, f)
		}
	}
}

// #1684: SSH host-key checking turned off in an MCP launch, a hook or GIT_SSH_COMMAND.
func TestCFG075_SSHHostKeyCheckingOff(t *testing.T) {
	warnOnly := func(t *testing.T, f []finding.Finding, want string) {
		t.Helper()
		if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, want) {
			t.Fatalf("expected 1 warn naming %q, got %+v", want, f)
		}
	}
	t.Run("mcp args", func(t *testing.T) {
		f := CFG075.Check(mcpTarget(t, `{"build":{"command":"ssh","args":["-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null","deploy@build.example.com","mcp-server"]}}`))
		warnOnly(t, f, "StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null")
		if !strings.Contains(f[0].Message, "mcpServers.build") {
			t.Errorf("message should name the server, got %s", f[0].Message)
		}
	})
	t.Run("mcp accept-new in one arg", func(t *testing.T) {
		warnOnly(t, CFG075.Check(mcpTarget(t, `{"b":{"command":"ssh","args":["-oStrictHostKeyChecking=accept-new","host","srv"]}}`)), "StrictHostKeyChecking=accept-new")
	})
	t.Run("mcp env GIT_SSH_COMMAND", func(t *testing.T) {
		warnOnly(t, CFG075.Check(mcpTarget(t, `{"g":{"command":"git-mcp","env":{"GIT_SSH_COMMAND":"ssh -o StrictHostKeyChecking=off"}}}`)), "GIT_SSH_COMMAND")
	})
	t.Run("settings env GIT_SSH_COMMAND", func(t *testing.T) {
		warnOnly(t, CFG075.Check(settingsTarget(t, `{"env":{"GIT_SSH_COMMAND":"ssh -o UserKnownHostsFile=/dev/null"}}`)), "UserKnownHostsFile=/dev/null")
	})
	for _, cmd := range []string{
		"ssh-keyscan github.com >> ~/.ssh/known_hosts",
		"ssh-keyscan -t ed25519 github.com > /home/ci/.ssh/known_hosts",
		"ssh-keyscan github.com | sudo tee -a /etc/ssh/ssh_known_hosts",
		`GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git push origin main`,
		"ssh -o 'StrictHostKeyChecking no' deploy@host ./deploy.sh",
	} {
		t.Run("hook "+cmd, func(t *testing.T) {
			f := CFG075.Check(hookTarget(t, cmd))
			if len(f) != 1 || f[0].Severity != finding.Warn {
				t.Fatalf("expected 1 warn, got %+v", f)
			}
		})
	}
}

func TestCFG075_SSHHostKeyChecking_NotReported(t *testing.T) {
	if f := CFG075.Check(mcpTarget(t, `{"b":{"command":"ssh","args":["deploy@host","mcp-server"]}}`)); len(f) != 0 {
		t.Errorf("plain ssh launch: expected no finding, got %+v", f)
	}
	if f := CFG075.Check(mcpTarget(t, `{"b":{"command":"ssh","args":["-o","StrictHostKeyChecking=yes","host","srv"]}}`)); len(f) != 0 {
		t.Errorf("StrictHostKeyChecking=yes: expected no finding, got %+v", f)
	}
	if f := CFG075.Check(mcpTarget(t, `{"g":{"command":"git-mcp","env":{"GIT_SSH_COMMAND":"${GIT_SSH_COMMAND}"}}}`)); len(f) != 0 {
		t.Errorf("templated GIT_SSH_COMMAND: expected no finding, got %+v", f)
	}
	for _, cmd := range []string{
		"ssh-keyscan -H host",
		"ssh-keyscan github.com | ssh-keygen -lf -",
		"ssh -o UserKnownHostsFile=.ssh/known_hosts deploy@host ./deploy.sh",
		"cat ~/.ssh/known_hosts",
	} {
		if f := CFG075.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("%q: expected no finding, got %+v", cmd, f)
		}
	}
}
