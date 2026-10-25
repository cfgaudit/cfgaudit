// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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

// #521: the alias spelling registers the same marketplace, so CFG055 reports it
// and names the key the file used rather than the canonical one.
func TestCFG055_AliasSpellingRegistersMarketplace(t *testing.T) {
	f := CFG055.Check(settingsTarget(t, `{"additionalMarketplaces": {"acme": {"source": {"source": "github", "repo": "acme/mk"}}}}`))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn for the alias spelling, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "additionalMarketplaces registers") {
		t.Errorf("message should name the spelling used, got %q", f[0].Message)
	}
}

// enabledPlugins pointing at a marketplace the same file registers under the
// alias is the same self-contained supply chain, so it stays an error.
func TestCFG055_AliasSpelling_SelfRegisteredPluginIsError(t *testing.T) {
	f := CFG055.Check(settingsTarget(t, `{
        "additionalMarketplaces": {"acme": {"source": {"source": "github", "repo": "acme/mk"}}},
        "enabledPlugins": {"tool@acme": true}}`))
	var errs int
	for _, x := range f {
		if x.Severity == finding.Error && strings.Contains(x.Message, "additionalMarketplaces") {
			errs++
		}
	}
	if errs != 1 {
		t.Fatalf("expected 1 error naming the alias, got %+v", f)
	}
}

// Re-registering the official marketplace with its own source is not a
// marketplace the file controls; any other source for that name still is
// (#872).
func TestCFG055_Issue872(t *testing.T) {
	tg := settingsTarget(t, `{"extraKnownMarketplaces":{"claude-plugins-official":{"source":{"source":"github","repo":"anthropics/claude-plugins-official"}},"cypress":{"source":{"source":"github","repo":"cypress-io/ai-toolkit"}}},"enabledPlugins":{"cypress@cypress":true,"typescript-lsp@claude-plugins-official":true}}`)
	var errs, warns int
	for _, f := range CFG055.Check(tg) {
		switch {
		case f.Severity == finding.Error && strings.Contains(f.Message, "cypress@cypress"):
			errs++
		case f.Severity == finding.Warn && strings.Contains(f.Message, "typescript-lsp@claude-plugins-official"):
			warns++
		case strings.Contains(f.Message, "\"claude-plugins-official\""):
			t.Errorf("official marketplace registration reported: %+v", f)
		}
	}
	if errs != 1 || warns != 1 {
		t.Errorf("expected one error for cypress and one warn for the official plugin, got %d/%d", errs, warns)
	}
	tg = settingsTarget(t, `{"extraKnownMarketplaces":{"claude-plugins-official":{"source":{"source":"github","repo":"someone/claude-plugins-official"}}},"enabledPlugins":{"x@claude-plugins-official":true}}`)
	errs = 0
	for _, f := range CFG055.Check(tg) {
		if f.Severity == finding.Error {
			errs++
		}
	}
	if errs != 1 {
		t.Errorf("expected an error for a foreign source under the official name, got %d", errs)
	}
}
