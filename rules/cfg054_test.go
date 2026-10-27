// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG054_FlagsHighEntropyToken(t *testing.T) {
	f := CFG054.Check(settingsTarget(t, `{"env":{"SESSION_KEY":"a8Kd92Lmz0Qw3RtY7bVx1NpC4"}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "env.SESSION_KEY") {
		t.Fatalf("expected warn for high-entropy SESSION_KEY, got %+v", f)
	}
}

func TestCFG054_MCPEnvAndHeaders(t *testing.T) {
	tg := &Target{
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP: map[string]parser.MCPServer{"m": {
			Env:     map[string]string{"SESSION": "a8Kd92Lmz0Qw3RtY7bVx1NpC4"},
			Headers: map[string]string{"X-Custom": "Zx9Qm2Lp7Rt0Yb3Vn5Kc8Wd1"},
		}},
	}
	if f := CFG054.Check(tg); len(f) != 2 {
		t.Fatalf("expected 2 findings (env + headers), got %+v", f)
	}
}

func TestCFG054_JSONValueLeaves(t *testing.T) {
	// A JSON object stored as a string value is walked leaf by leaf, so a
	// harmless header blob is not scored as a single high-entropy token.
	tg := &Target{
		Scope:          finding.ScopeProject,
		ProjectMCPFile: ".mcp.json",
		ProjectMCP: map[string]parser.MCPServer{"db": {
			Env: map[string]string{"EXAMPLE_HEADERS": `{"User-Agent":"example.client"}`},
		}},
	}
	if f := CFG054.Check(tg); len(f) != 0 {
		t.Fatalf("expected no finding for a JSON header blob, got %+v", f)
	}

	// A secret inside such a value is still reported, on the leaf.
	tg.ProjectMCP["db"] = parser.MCPServer{
		Env: map[string]string{"EXAMPLE_HEADERS": `{"Authorization":"a8Kd92Lmz0Qw3RtY7bVx1NpC4"}`},
	}
	f := CFG054.Check(tg)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a secret inside a JSON value, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "env.EXAMPLE_HEADERS.Authorization") {
		t.Errorf("expected the finding to point at the JSON leaf, got %+v", f[0])
	}

	// A leaf whose own JSON key ends in _TOKEN is still reported: the
	// suffix gate applies to the outer env/header name, which CFG007/CFG050
	// already handle themselves.
	tg.ProjectMCP["db"] = parser.MCPServer{
		Env: map[string]string{"EXAMPLE_CONFIG": `{"SERVICE_TOKEN":"a8Kd92Lmz0Qw3RtY7bVx1NpC4"}`},
	}
	f = CFG054.Check(tg)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a secret leaf under a *_TOKEN JSON key, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "env.EXAMPLE_CONFIG.SERVICE_TOKEN") {
		t.Errorf("expected the finding to point at the JSON leaf, got %+v", f[0])
	}
}

func TestCFG054_JSONValueEdgeCases(t *testing.T) {
	// A value that starts like JSON but does not parse is scored as one
	// token, as before JSON values were walked.
	f := CFG054.Check(settingsTarget(t, `{"env":{"SESSION_KEY":"{a8Kd92Lmz0Qw3RtY7bVx1NpC4"}}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "env.SESSION_KEY is") {
		t.Fatalf("expected one finding on the whole invalid-JSON value, got %+v", f)
	}

	// An array element is reported with its index.
	f = CFG054.Check(settingsTarget(t, `{"env":{"LIST":"[\"example.one\",\"a8Kd92Lmz0Qw3RtY7bVx1NpC4\"]"}}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "env.LIST[1] is") {
		t.Fatalf("expected one finding on the array element, got %+v", f)
	}
}

func TestCFG054_NotFlagged(t *testing.T) {
	cases := []string{
		`{"env":{"NODE_ENV":"development"}}`,                                // short, low entropy
		`{"env":{"GREETING":"hello there friend how are you"}}`,             // whitespace (prose)
		`{"env":{"BUILD_SHA":"d41d8cd98f00b204e9800998ecf8427e"}}`,          // pure hex md5 → 2 classes
		`{"env":{"PATHY":"/usr/local/share/app/x9KdmzQ1Lp2"}}`,              // path
		`{"env":{"REF":"$SESSION_KEY"}}`,                                    // shell ref
		`{"env":{"PH":"changeme-changeme-changeme"}}`,                       // placeholder-ish / low entropy
		`{"env":{"API_TOKEN":"a8Kd92Lmz0Qw3RtY7bVx1NpC4"}}`,                 // secret-suffix name → CFG007's job, not double-flagged
		`{"env":{"EXAMPLE_HEADERS":"{\"User-Agent\":\"example.client\"}"}}`, // JSON value: header blob, not one token
	}
	for _, c := range cases {
		if f := CFG054.Check(settingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG054_NoDoubleWithVendorPattern(t *testing.T) {
	// A known vendor token under an innocuous name is left to CFG007, not CFG054.
	if f := CFG054.Check(settingsTarget(t, `{"env":{"X":"ghp_abcdefghij0123456789ABCDEF"}}`)); len(f) != 0 {
		t.Errorf("expected CFG054 to skip a known vendor pattern, got %+v", f)
	}
}

func TestShannonEntropyAndClasses(t *testing.T) {
	if h := shannonEntropy("aaaaaaaa"); h != 0 {
		t.Errorf("uniform string entropy should be 0, got %v", h)
	}
	if h := shannonEntropy("a8Kd92Lmz0Qw3RtY7bVx1NpC4"); h < 4.0 {
		t.Errorf("random token entropy should be >= 4.0, got %v", h)
	}
	if c := charClasses("abcDEF123!"); c != 4 {
		t.Errorf("expected 4 classes, got %d", c)
	}
	if c := charClasses("abcdef0123"); c != 2 {
		t.Errorf("expected 2 classes (hex), got %d", c)
	}
}

func TestCFG054_NoTarget_NoFinding(t *testing.T) {
	if f := CFG054.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}
