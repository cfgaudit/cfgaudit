// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG128_PostmarkAcrossSupportedRunnerForms(t *testing.T) {
	cases := []struct{ command, args string }{
		{"npx", `["-y","postmark-mcp@1.0.16"]`},
		{"npm", `["exec","postmark-mcp@1.0.16"]`},
		{"pnpm", `["dlx","postmark-mcp@1.0.16"]`},
		{"yarn", `["dlx","postmark-mcp@1.0.16"]`},
		{"bunx", `["postmark-mcp@1.0.16"]`},
		{"pnpx", `["postmark-mcp@1.0.16"]`},
		{"npx.cmd", `["-y","postmark-mcp@1.0.16"]`},
		{"cmd", `["/c","npx","-y","postmark-mcp@1.0.16"]`},
		{"cmd.exe", `["/C","npx -y postmark-mcp@1.0.16"]`},
		{"npx", `["--package=postmark-mcp@1.0.16","postmark-mcp"]`},
	}
	for _, tc := range cases {
		t.Run(tc.command+tc.args, func(t *testing.T) {
			target := settingsTarget(t, `{"mcpServers":{"mail":{"command":"`+tc.command+`","args":`+tc.args+`}}}`)
			got := CFG128.Check(target)
			if len(got) != 1 || got[0].Severity != finding.Error || !strings.Contains(got[0].Message, "postmark-mcp@1.0.16") || !strings.Contains(got[0].Message, "incident-response") {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestCFG128_SandwormExactVersion(t *testing.T) {
	const pkg = "su" + "port-color@1.0.1" // preserve the malicious package's intentional misspelling
	target := settingsTarget(t, `{"mcpServers":{"x":{"command":"npx","args":["-y","`+pkg+`"]}}}`)
	got := CFG128.Check(target)
	if len(got) != 1 || !strings.Contains(got[0].Message, "SANDWORM_MODE") {
		t.Fatalf("got %+v", got)
	}
}

func TestCFG128_ExactOnly_NoSubstringLookalikeOrOtherVersion(t *testing.T) {
	for _, spec := range []string{
		"postmark-mcp@1.0.15", "postmark-mcp@1.0.17", "postmark-mcp@latest",
		"postmark-mcp@^1.0.16", "postmark-mcp@1.0", "postmark-mcp@1.0.16-beta.1",
		"postmark-mcp-safe@1.0.16", "my-postmark-mcp@1.0.16", "Postmark-MCP@1.0.16",
		"supports-color@1.0.1", "su" + "port-color-safe@1.0.1", "ethres@1.0.0",
	} {
		target := settingsTarget(t, `{"mcpServers":{"x":{"command":"npx","args":["-y","`+spec+`"]}}}`)
		if got := CFG128.Check(target); len(got) != 0 {
			t.Errorf("%s: got %+v", spec, got)
		}
	}
}

func TestCFG128_DoesNotEchoCredentialURL(t *testing.T) {
	target := settingsTarget(t, `{"mcpServers":{"mail":{"command":"npx","args":["-y","postmark-mcp@1.0.16","https://user:super-secret@example.invalid/mcp?token=also-secret"]}}}`)
	got := CFG128.Check(target)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	for _, secret := range []string{"super-secret", "also-secret", "user:"} {
		if strings.Contains(got[0].Message, secret) {
			t.Errorf("message leaks %q: %s", secret, got[0].Message)
		}
	}
}

func TestCFG128_SharedExtractionDeduplicatesAndIgnoresNonFetchingRunners(t *testing.T) {
	target := settingsTarget(t, `{"mcpServers":{"x":{"command":"npx","args":["--package=postmark-mcp@1.0.16","--package=postmark-mcp@1.0.16","postmark-mcp@1.0.16"]}}}`)
	if got := CFG128.Check(target); len(got) != 1 {
		t.Fatalf("duplicate specs: %+v", got)
	}
	for _, target := range []*Target{
		nil,
		settingsTarget(t, `{"mcpServers":{"x":{"command":"node","args":["postmark-mcp@1.0.16"]}}}`),
		settingsTarget(t, `{"mcpServers":{"x":{"command":"npm","args":["run","postmark-mcp@1.0.16"]}}}`),
	} {
		if got := CFG128.Check(target); len(got) != 0 {
			t.Fatalf("non-fetching target: %+v", got)
		}
	}
}
