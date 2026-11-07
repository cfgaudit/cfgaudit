// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestCFG055_Issue1209_InRepoMarketplaceRegistration(t *testing.T) {
	for _, source := range []string{
		`{"source":"directory","path":"./plugins"}`,
		`{"source":"file","path":"plugins/marketplace.json"}`,
	} {
		raw := `{"extraKnownMarketplaces":{"local":{"source":` + source + `}}}`
		if f := CFG055.Check(settingsTarget(t, raw)); len(f) != 0 {
			t.Errorf("in-repo marketplace registration must be exempt: %+v", f)
		}
		raw = `{"extraKnownMarketplaces":{"local":{"source":` + source + `}},"enabledPlugins":{"x@local":true}}`
		f := CFG055.Check(settingsTarget(t, raw))
		if len(f) != 1 || f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "enabledPlugins") {
			t.Errorf("enabling in-repo plugin must still warn: %+v", f)
		}
	}
	for _, source := range []string{
		`{"source":"directory","path":"../outside"}`,
		`{"source":"directory","path":"/opt/plugins"}`,
		`{"source":"github","repo":"another-org/plugins"}`,
	} {
		raw := `{"extraKnownMarketplaces":{"external":{"source":` + source + `}}}`
		if f := CFG055.Check(settingsTarget(t, raw)); len(f) != 1 {
			t.Errorf("unsafe marketplace registration must still warn: %+v", f)
		}
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
		case f.Severity == finding.Info && strings.Contains(f.Message, "typescript-lsp@claude-plugins-official"):
			warns++
		case strings.Contains(f.Message, "\"claude-plugins-official\""):
			t.Errorf("official marketplace registration reported: %+v", f)
		}
	}
	if errs != 1 || warns != 1 {
		t.Errorf("expected one error for cypress and one info for the official plugin (#1178), got %d/%d", errs, warns)
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

func TestCFG055_Issue893(t *testing.T) {
	sevOf := func(settings, entry string) finding.Severity {
		t.Helper()
		for _, f := range CFG055.Check(settingsTarget(t, settings)) {
			if strings.Contains(f.Message, "\""+entry+"\"") {
				return f.Severity
			}
		}
		t.Fatalf("no finding for %s in %s", entry, settings)
		return ""
	}
	cases := []struct {
		source, want string
	}{
		{`{"source":"github","repo":"anthropics/claude-code"}`, "warn"},
		{`{"source":"github","repo":"anthropics/skills"}`, "warn"},
		{`{"source":"git","url":"https://github.com/anthropics/skills.git"}`, "warn"},
		{`{"source":"directory","path":"./.agents"}`, "warn"},
		{`{"source":"directory","path":"plugins/local"}`, "warn"},
		{`{"source":"github","repo":"someone/claude-code"}`, "error"},
		{`{"source":"github","repo":"anthropics-fork/skills"}`, "error"},
		{`{"source":"git","url":"https://gitlab.com/anthropics/skills.git"}`, "error"},
		{`{"source":"directory","path":"../shared-plugins"}`, "error"},
		{`{"source":"directory","path":"/opt/plugins"}`, "error"},
		{`{"source":"directory","path":"~/plugins"}`, "error"},
	}
	for _, c := range cases {
		s := `{"extraKnownMarketplaces":{"mkt":{"source":` + c.source + `}},"enabledPlugins":{"p@mkt":true}}`
		if got := sevOf(s, "p@mkt"); string(got) != c.want {
			t.Errorf("%s: expected %s for the enable, got %s", c.source, c.want, got)
		}
	}
}

// A marketplace on the repository owner's own GitHub account is warn, a
// fork's upstream or another owner stays error, and a plugin from the
// official marketplace is info (#1178).
func TestCFG055_OwnerAndOfficial1178(t *testing.T) {
	sevs := func(origin, settings string) []finding.Severity {
		t.Helper()
		tg := settingsTarget(t, settings)
		dir := t.TempDir()
		if origin != "" {
			if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
			cfg := "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = " + origin + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
			if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		tg.ProjectDir = dir
		var out []finding.Severity
		for _, f := range CFG055.Check(tg) {
			if strings.HasPrefix(f.Message, "enabledPlugins") {
				out = append(out, f.Severity)
			}
		}
		return out
	}
	gh := `{"extraKnownMarketplaces":{"m":{"source":{"source":"github","repo":"My-Org/plugins"}}},"enabledPlugins":{"p@m":true}}`
	git := `{"extraKnownMarketplaces":{"m":{"source":{"source":"git","url":"https://github.com/my-org/plugins.git"}}},"enabledPlugins":{"p@m":true}}`
	for _, c := range []struct {
		name, origin, settings string
		want                   finding.Severity
	}{
		{"same owner, github", "git@github.com:my-org/app.git", gh, finding.Warn},
		{"same owner, git URL", "https://github.com/MY-ORG/app", git, finding.Warn},
		{"fork of the owner's repo", "https://github.com/someone/app.git", gh, finding.Error},
		{"no origin", "", gh, finding.Error},
		{"unknown marketplace, same file", "https://github.com/my-org/app", `{"extraKnownMarketplaces":{"m":{"source":{"source":"github","repo":"other/plugins"}}},"enabledPlugins":{"p@m":true}}`, finding.Error},
		{"official", "", `{"enabledPlugins":{"code-review@claude-plugins-official":true}}`, finding.Info},
		{"other marketplace", "", `{"enabledPlugins":{"x@somewhere":true}}`, finding.Warn},
	} {
		got := sevs(c.origin, c.settings)
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if marketplaceOwner(json.RawMessage(`{"m":{"source":{"source":"github","repo":"noslash"}}}`), "m") != "" {
		t.Error("a repo without an owner has no owner")
	}
	if marketplaceOwner(json.RawMessage(`{"m":{"source":{"source":"url","url":"https://example.com/m.json"}}}`), "m") != "" {
		t.Error("a url source has no GitHub owner")
	}
}
