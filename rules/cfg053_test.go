package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG053_AllowAllClaudeAiMcps(t *testing.T) {
	f := CFG053.Check(settingsTarget(t, `{"allowAllClaudeAiMcps":true}`))
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "allowAllClaudeAiMcps") {
		t.Fatalf("expected error for allowAllClaudeAiMcps, got %+v", f)
	}
}

func TestCFG053_EnabledWildcard(t *testing.T) {
	f := CFG053.Check(settingsTarget(t, `{"enabledMcpjsonServers":["memory","*"]}`))
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "enabledMcpjsonServers") {
		t.Fatalf("expected error for wildcard enabledMcpjsonServers, got %+v", f)
	}
}

func TestCFG053_EnabledLargeList_Warn(t *testing.T) {
	var items []string
	for i := 0; i < 10; i++ {
		items = append(items, `"s`+string(rune('a'+i))+`"`)
	}
	json := `{"enabledMcpjsonServers":[` + strings.Join(items, ",") + `]}`
	f := CFG053.Check(settingsTarget(t, json))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected warn for large enabledMcpjsonServers, got %+v", f)
	}
}

func TestCFG053_WildcardAllowlistURL_Warn(t *testing.T) {
	for _, u := range []string{`*`, `*://*`, `https://*`, `https://*/*`} {
		json := `{"allowedMcpServers":[{"serverUrl":"` + u + `"}]}`
		f := CFG053.Check(settingsTarget(t, json))
		if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "wildcard serverUrl") {
			t.Errorf("expected warn for wildcard serverUrl %q, got %+v", u, f)
		}
	}
}

func TestCFG053_NotFlagged(t *testing.T) {
	cases := []string{
		`{"allowAllClaudeAiMcps":false}`,                                   // explicit false
		`{"enabledMcpjsonServers":["memory","github"]}`,                    // short explicit list
		`{"allowedMcpServers":[{"serverName":"github"}]}`,                  // name allowlist, no url
		`{"allowedMcpServers":[{"serverUrl":"https://*.corp.example/*"}]}`, // domain-scoped wildcard
		`{"permissions":{"deny":["Read(.env)"]}}`,                          // unrelated
	}
	for _, c := range cases {
		if f := CFG053.Check(settingsTarget(t, c)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG053_NoSettings_NoFinding(t *testing.T) {
	if f := CFG053.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}
