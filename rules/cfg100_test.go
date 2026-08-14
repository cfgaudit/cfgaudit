package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func grokPluginsTarget(p *parser.GrokPlugins) *Target {
	return &Target{
		Scope:    finding.ScopeProject,
		GrokFile: ".grok/config.toml",
		Grok:     &parser.GrokConfig{Plugins: p},
	}
}

// The archetype from the wild: the repository ships the plugin under ./plugins/
// and switches it on in the same file.
func TestCFG100_RepoLocalPathAndEnabled(t *testing.T) {
	got := onlyFinding(t, CFG100.Check(grokPluginsTarget(&parser.GrokPlugins{
		Paths:   []string{"./plugins/soleur"},
		Enabled: []string{"soleur"},
	})), finding.Warn)
	for _, want := range []string{"./plugins/soleur", "soleur", "ships the plugin code and switches it on"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
}

// enabled alone still turns plugins on, because project plugins default to off.
func TestCFG100_EnabledAlone(t *testing.T) {
	got := onlyFinding(t, CFG100.Check(grokPluginsTarget(&parser.GrokPlugins{
		Enabled: []string{"vercel", "railway"},
	})), finding.Warn)
	if !strings.Contains(got.Message, "default to off") {
		t.Errorf("expected the default stated, got %q", got.Message)
	}
}

// A path outside the repository is a different sentence: the repo points the
// loader somewhere rather than supplying the code.
func TestCFG100_PathOutsideRepo(t *testing.T) {
	for _, p := range []string{"/opt/grok-plugins", "~/grok-plugins", "$HOME/plugins"} {
		got := onlyFinding(t, CFG100.Check(grokPluginsTarget(&parser.GrokPlugins{Paths: []string{p}})), finding.Warn)
		if !strings.Contains(got.Message, "outside the repository") {
			t.Errorf("%s: expected the outside wording, got %q", p, got.Message)
		}
	}
}

// A file doing both gets one finding that says both, not two overlapping ones.
func TestCFG100_NoDuplicateForPathPlusEnabled(t *testing.T) {
	f := CFG100.Check(grokPluginsTarget(&parser.GrokPlugins{
		Paths:   []string{"plugins/local"},
		Enabled: []string{"local"},
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
}

// disabled is hardening and must never be reported, the trap that caught
// exclude_slash_tmp and disableTmpWrite.
func TestCFG100_DisabledIsHardening(t *testing.T) {
	for _, p := range []*parser.GrokPlugins{
		{Disabled: []string{"boardgame-io"}},
		{Disabled: []string{"a", "b"}, Paths: []string{}, Enabled: []string{}},
		{},
		{Enabled: []string{"  ", ""}},
	} {
		if f := CFG100.Check(grokPluginsTarget(p)); len(f) != 0 {
			t.Errorf("expected no finding for %+v, got %+v", p, f)
		}
	}
}

// A user-global ~/.grok/config.toml is the user's own choice, matching how
// CFG055 and CFG089 scope their equivalents.
func TestCFG100_UserScopeSilent(t *testing.T) {
	tg := grokPluginsTarget(&parser.GrokPlugins{Enabled: []string{"x"}})
	tg.Scope = finding.ScopeUser
	if f := CFG100.Check(tg); len(f) != 0 {
		t.Errorf("expected no finding at user scope, got %+v", f)
	}
}

func TestCFG100_NoTable(t *testing.T) {
	if f := CFG100.Check(&Target{Grok: &parser.GrokConfig{}}); len(f) != 0 {
		t.Errorf("expected no finding without a [plugins] table, got %+v", f)
	}
	if f := CFG100.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without a Grok config, got %+v", f)
	}
}
