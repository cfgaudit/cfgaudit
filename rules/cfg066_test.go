package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG066_WildcardCorsAlone_Warn(t *testing.T) {
	for _, k := range []string{"CORS_ORIGINS", "MCP_CORS_ORIGINS", "ACCESS_CONTROL_ALLOW_ORIGIN", "ALLOWED_ORIGINS"} {
		json := `{"mcpServers":{"m":{"command":"s","env":{"` + k + `":"*"}}}}`
		f := CFG066.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected 1 Warn for %s=*, got %+v", k, f)
		}
	}
}

func TestCFG066_WildcardCorsPlusAnonymous_Error(t *testing.T) {
	cases := []string{
		`{"mcpServers":{"m":{"command":"s","env":{"MCP_CORS_ORIGINS":"*","MCP_ALLOW_ANONYMOUS_ACCESS":"true"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"CORS_ORIGINS":"*","REQUIRE_AUTH":"false"}}}}`,
		`{"mcpServers":{"m":{"command":"s","env":{"ALLOWED_ORIGINS":"https://a, *","AUTH_DISABLED":"1"}}}}`,
	}
	for _, json := range cases {
		f := CFG066.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for wildcard+anon, got %+v (%s)", f, json)
		}
		if len(f) == 1 && !strings.Contains(f[0].Message, "anonymous") {
			t.Errorf("expected anonymous-access mention, got %q", f[0].Message)
		}
	}
}

func TestCFG066_NoFinding(t *testing.T) {
	for _, json := range []string{
		`{"mcpServers":{"m":{"command":"s","env":{"CORS_ORIGINS":"https://app.example.com"}}}}`, // scoped origin
		`{"mcpServers":{"m":{"command":"s","env":{"OTHER":"*"}}}}`,                              // wildcard on a non-CORS key
		`{"mcpServers":{"m":{"command":"s","env":{"PORT":"3000"}}}}`,                            // unrelated
	} {
		if f := CFG066.Check(settingsTarget(t, json)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", json, f)
		}
	}
	if f := CFG066.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for empty target, got %+v", f)
	}
}

func TestCFG066_AnonAccessFalseStaysWarn(t *testing.T) {
	// REQUIRE_AUTH true (auth on) → wildcard alone → warn, not error.
	f := CFG066.Check(settingsTarget(t, `{"mcpServers":{"m":{"command":"s","env":{"CORS_ORIGINS":"*","REQUIRE_AUTH":"true"}}}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected Warn when auth required, got %+v", f)
	}
}
