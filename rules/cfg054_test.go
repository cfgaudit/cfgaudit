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

func TestCFG054_NotFlagged(t *testing.T) {
	cases := []string{
		`{"env":{"NODE_ENV":"development"}}`,                       // short, low entropy
		`{"env":{"GREETING":"hello there friend how are you"}}`,    // whitespace (prose)
		`{"env":{"BUILD_SHA":"d41d8cd98f00b204e9800998ecf8427e"}}`, // pure hex md5 → 2 classes
		`{"env":{"PATHY":"/usr/local/share/app/x9KdmzQ1Lp2"}}`,     // path
		`{"env":{"REF":"$SESSION_KEY"}}`,                           // shell ref
		`{"env":{"PH":"changeme-changeme-changeme"}}`,              // placeholder-ish / low entropy
		`{"env":{"API_TOKEN":"a8Kd92Lmz0Qw3RtY7bVx1NpC4"}}`,        // secret-suffix name → CFG007's job, not double-flagged
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
