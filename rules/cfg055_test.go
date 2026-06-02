package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG055_EnableFromSelfRegisteredMarketplace_Error(t *testing.T) {
	tg := settingsTarget(t, `{"extraKnownMarketplaces":{"evil":{"source":{"source":"url","url":"https://x/m.json"}}},"enabledPlugins":{"backdoor@evil":true}}`)
	tg.Scope = finding.ScopeProject
	f := CFG055.Check(tg)
	// one error (enable) + one warn (marketplace registration)
	var errs, warns int
	for _, x := range f {
		switch x.Severity {
		case finding.Error:
			errs++
			if !strings.Contains(x.Message, "backdoor@evil") {
				t.Errorf("error should name the plugin, got %q", x.Message)
			}
		case finding.Warn:
			warns++
		}
	}
	if errs != 1 || warns != 1 {
		t.Fatalf("expected 1 error + 1 warn, got %d/%d: %+v", errs, warns, f)
	}
}

func TestCFG055_EnableFromOtherMarketplace_Warn(t *testing.T) {
	tg := settingsTarget(t, `{"enabledPlugins":{"formatter@anthropic-tools":true}}`)
	tg.Scope = finding.ScopeProject
	f := CFG055.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "formatter@anthropic-tools") {
		t.Fatalf("expected single warn for other-marketplace enable, got %+v", f)
	}
}

func TestCFG055_MarketplaceOnly_Warn(t *testing.T) {
	tg := settingsTarget(t, `{"extraKnownMarketplaces":{"mkt":{"source":{"source":"github","repo":"a/b"}}}}`)
	tg.Scope = finding.ScopeProject
	f := CFG055.Check(tg)
	if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "mkt") {
		t.Fatalf("expected single warn for marketplace registration, got %+v", f)
	}
}

func TestCFG055_UserScopeExempt(t *testing.T) {
	tg := settingsTarget(t, `{"enabledPlugins":{"x@y":true},"extraKnownMarketplaces":{"y":{"source":{"source":"url","url":"https://x"}}}}`)
	tg.Scope = finding.ScopeUser
	if f := CFG055.Check(tg); len(f) != 0 {
		t.Errorf("expected no finding at user scope, got %+v", f)
	}
}

func TestCFG055_NotFlagged(t *testing.T) {
	cases := []string{
		`{"enabledPlugins":{"x@y":false}}`,        // disabled
		`{"permissions":{"deny":["Read(.env)"]}}`, // unrelated
		`{}`,
	}
	for _, c := range cases {
		tg := settingsTarget(t, c)
		tg.Scope = finding.ScopeProject
		if f := CFG055.Check(tg); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", c, f)
		}
	}
}

func TestCFG055_NoSettings_NoFinding(t *testing.T) {
	if f := CFG055.Check(&Target{Scope: finding.ScopeProject}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}
