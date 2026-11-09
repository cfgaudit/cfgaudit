// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1406: the remote URL of a stdio proxy such as mcp-remote or supergateway.
func TestStdioProxyRemote1406(t *testing.T) {
	for _, tc := range []struct {
		command string
		args    []string
		tool    string
		url     string
	}{
		{"npx", []string{"-y", "mcp-remote@0.1.15", "http://mcp.example.invalid/sse"}, "mcp-remote", "http://mcp.example.invalid/sse"},
		{"mcp-remote", []string{"https://mcp.example.invalid/sse", "--header", "Authorization: Bearer x"}, "mcp-remote", "https://mcp.example.invalid/sse"},
		{"npx", []string{"mcp-remote", "--header", "https://not-the-url.invalid", "https://mcp.example.invalid/sse"}, "mcp-remote", "https://mcp.example.invalid/sse"},
		{"npx", []string{"-y", "mcp-remote", "--allow-http", "http://internal.example.invalid/sse"}, "mcp-remote", "http://internal.example.invalid/sse"},
		{"npx", []string{"-y", "mcp-remote", "--transport=http-only", "https://mcp.example.invalid/mcp", "--resource", "https://tenant.example.invalid/"}, "mcp-remote", "https://mcp.example.invalid/mcp"},
		{"npx", []string{"--package", "mcp-remote", "mcp-remote", "https://mcp.example.invalid/sse"}, "mcp-remote", "https://mcp.example.invalid/sse"},
		{"cmd", []string{"/c", "npx", "-y", "mcp-remote", "https://mcp.example.invalid/sse"}, "mcp-remote", "https://mcp.example.invalid/sse"},
		{"npx -y mcp-remote https://mcp.example.invalid/sse", nil, "mcp-remote", "https://mcp.example.invalid/sse"},
		{"/usr/local/bin/mcp-remote", []string{"https://mcp.example.invalid/sse"}, "mcp-remote", "https://mcp.example.invalid/sse"},
		{"npx", []string{"-y", "mcp-remote"}, "mcp-remote", ""},
		{"npm", []string{"exec", "mcp-remote@0.0.5", "--", "https://mcp.example.invalid/mcp"}, "mcp-remote", "https://mcp.example.invalid/mcp"},
		{"npx", []string{"-y", "supergateway", "--sse", "http://mcp.example.invalid/sse"}, "supergateway", "http://mcp.example.invalid/sse"},
		{"supergateway", []string{"--streamableHttp=https://mcp.example.invalid/mcp"}, "supergateway", "https://mcp.example.invalid/mcp"},
		{"npx", []string{"-y", "supergateway@4.2.1", "--stdio", "uvx mcp-server-git", "--baseUrl", "http://example.invalid:8000"}, "supergateway", ""},
		{"npx", []string{"-y", "@acme/mcp-server", "https://api.example.invalid"}, "", ""},
		{"node", []string{"server.js"}, "", ""},
	} {
		tool, url := stdioProxyRemote(tc.command, tc.args)
		if tool != tc.tool || url != tc.url {
			t.Errorf("%s %v: got %q %q, want %q %q", tc.command, tc.args, tool, url, tc.tool, tc.url)
		}
	}
}

func TestCFG049StdioProxy1406(t *testing.T) {
	check := func(command, args string) []finding.Finding {
		return CFG049.Check(settingsTarget(t, `{"mcpServers":{"remote":{"command":"`+command+`","args":`+args+`}}}`))
	}
	f := check("npx", `["-y","mcp-remote@0.1.15","http://mcp.example.invalid/sse"]`)
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, `mcpServers.remote starts mcp-remote, which connects to "http://mcp.example.invalid/sse"`) {
		t.Errorf("cleartext mcp-remote: %+v", f)
	}
	if f := check("npx", `["-y","mcp-remote@0.1.16","https://localhost:8443/sse"]`); len(f) != 0 {
		t.Errorf("loopback mcp-remote: %+v", f)
	}
	if f := check("supergateway", `["--sse","https://mcp.example.invalid/sse"]`); len(f) != 1 || f[0].Severity != finding.Warn {
		t.Errorf("supergateway https: %+v", f)
	}
	if f := check("npx", `["-y","supergateway","--streamableHttp","http://mcp.example.invalid/mcp"]`); len(f) != 1 || f[0].Severity != finding.Error {
		t.Errorf("supergateway http: %+v", f)
	}
	if f := check("npx", `["-y","mcp-remote","https://mcp.sentry.dev/mcp"]`); len(f) != 1 || f[0].Severity != finding.Info {
		t.Errorf("vendor endpoint: %+v", f)
	}
	if f := check("npx", `["-y","mcp-remote","${MCP_URL}"]`); len(f) != 0 {
		t.Errorf("shell variable: %+v", f)
	}
	if f := check("npx", `["-y","@modelcontextprotocol/server-filesystem","."]`); len(f) != 0 {
		t.Errorf("plain stdio server: %+v", f)
	}
}
