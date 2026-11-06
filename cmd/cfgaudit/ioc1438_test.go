// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownMaliciousPackageIOC1438_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{"mail":{"command":"npx","args":["-y","postmark-mcp@1.0.16","https://user:secret@example.invalid/mcp?token=hidden"]}}}`)

	code, out, stderr := runCLI(t, "--format", "text", "--only", "CFG128", dir)
	if code != 1 {
		t.Fatalf("exit %d, stderr %s\n%s", code, stderr, out)
	}
	for _, want := range []string{"[error] CFG128", ".mcp.json", "postmark-mcp@1.0.16", "incident-response"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"user:secret", "token=hidden"} {
		if strings.Contains(out, secret) {
			t.Errorf("output leaks %q:\n%s", secret, out)
		}
	}
}
