package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func boolPtr(b bool) *bool { return &b }

func TestCFG062_ExplicitFalseNoAllowlist_Warn(t *testing.T) {
	gs := &parser.GeminiSettings{Security: &parser.GeminiSecurity{BlockGitExtensions: boolPtr(false)}}
	f := CFG062.Check(geminiTarget(gs))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
}

func TestCFG062_NoFinding(t *testing.T) {
	cases := []*parser.GeminiSettings{
		{Security: &parser.GeminiSecurity{BlockGitExtensions: boolPtr(true)}},                                       // explicitly blocked
		{Security: &parser.GeminiSecurity{}},                                                                        // absent (nil) — not flagged
		{Security: &parser.GeminiSecurity{BlockGitExtensions: boolPtr(false), AllowedExtensions: []string{"x/.*"}}}, // allow-list constrains it
		{}, // no security section
	}
	for i, gs := range cases {
		if f := CFG062.Check(geminiTarget(gs)); len(f) != 0 {
			t.Errorf("case %d: expected no finding, got %+v", i, f)
		}
	}
	if f := CFG062.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for non-Gemini target, got %+v", f)
	}
}

// #466: experimental.extensionRegistryURI decides where extensions are
// discovered from, one step ahead of what allowedExtensions permits.
func geminiExperimentalTarget(uri string) *Target {
	return &Target{
		Scope:      finding.ScopeProject,
		GeminiFile: ".gemini/settings.json",
		Gemini: &parser.GeminiSettings{
			Experimental: &parser.GeminiExperimental{ExtensionRegistryURI: uri},
		},
	}
}

func TestCFG062_ExtensionRegistryRedirected(t *testing.T) {
	got := onlyFinding(t, CFG062.Check(geminiExperimentalTarget("https://registry.evil.example/extensions.json")), finding.Warn)
	for _, want := range []string{"registry.evil.example", "another host", "trusted"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
}

// A value that does not start with http is resolved against the working
// directory, so the repository supplies the catalogue itself.
func TestCFG062_ExtensionRegistryLocalPath(t *testing.T) {
	got := onlyFinding(t, CFG062.Check(geminiExperimentalTarget("./extensions.json")), finding.Warn)
	if !strings.Contains(got.Message, "a file inside the repository") {
		t.Errorf("expected the local-path wording, got %q", got.Message)
	}
}

// Restating the default is a no-op, and an absent key is the ordinary case.
func TestCFG062_ExtensionRegistryDefaultAndAbsent(t *testing.T) {
	for _, uri := range []string{parser.DefaultGeminiExtensionRegistry, "HTTPS://GEMINICLI.COM/EXTENSIONS.JSON", "", "   "} {
		if f := CFG062.Check(geminiExperimentalTarget(uri)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", uri, f)
		}
	}
	if f := CFG062.Check(&Target{Gemini: &parser.GeminiSettings{}}); len(f) != 0 {
		t.Errorf("expected no finding with no experimental block, got %+v", f)
	}
}

// The registry check is independent of the git-extension half, so a file that
// weakens both reports both.
func TestCFG062_BothHalvesTogether(t *testing.T) {
	no := false
	f := CFG062.Check(&Target{
		Scope:      finding.ScopeProject,
		GeminiFile: ".gemini/settings.json",
		Gemini: &parser.GeminiSettings{
			Security:     &parser.GeminiSecurity{BlockGitExtensions: &no},
			Experimental: &parser.GeminiExperimental{ExtensionRegistryURI: "https://registry.evil.example/e.json"},
		},
	})
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %+v", f)
	}
}

// security.autoAddToPolicyByDefault is deliberately not read. Verified at the
// consumer in gemini-cli 0.55.1: it only moves the initially highlighted option
// in a confirmation dialog that still appears, and only when the folder is
// trusted, the separate allowPermanentApproval setting is on (default false),
// and the confirmation is an info/edit/mcp one. It appears in 32 committed
// .gemini/ files, so reporting it would be 32 false positives.
func TestCFG062_AutoAddToPolicyByDefaultNotFlagged(t *testing.T) {
	target := &Target{
		Scope:      finding.ScopeProject,
		GeminiFile: ".gemini/settings.json",
		Gemini:     &parser.GeminiSettings{Security: &parser.GeminiSecurity{}},
	}
	for _, r := range All {
		if f := r.Check(target); len(f) != 0 {
			t.Errorf("%s fired on a settings file whose only security key is autoAddToPolicyByDefault: %+v", r.ID(), f)
		}
	}
}
