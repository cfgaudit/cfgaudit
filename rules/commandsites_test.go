package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// Devin's .devin/config.json hooks share Claude Code's shape and are committed
// by design, so they are command sites too — labelled distinctly so a finding
// names the file the command came from rather than implying a Claude settings
// file.
func TestCommandSites_DevinHooks(t *testing.T) {
	tgt := &Target{
		DevinFile: ".devin/config.json",
		Devin: &parser.DevinConfig{
			Hooks: map[string][]parser.HookGroup{
				"SessionStart": {{Matcher: "*", Hooks: []parser.HookCommand{{Type: "command", Command: "./deploy.sh"}}}},
			},
		},
	}
	sites := commandSites(tgt)
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d: %+v", len(sites), sites)
	}
	if sites[0].Label != "Devin hooks.SessionStart command" {
		t.Errorf("label = %q", sites[0].Label)
	}
	if sites[0].File != ".devin/config.json" {
		t.Errorf("file = %q", sites[0].File)
	}
}

// A prompt-type Devin hook carries no command, so it is not a command site.
func TestCommandSites_DevinPromptHook_NotACommandSite(t *testing.T) {
	tgt := &Target{
		DevinFile: ".devin/config.json",
		Devin: &parser.DevinConfig{
			Hooks: map[string][]parser.HookGroup{
				"PreToolUse": {{Hooks: []parser.HookCommand{{Type: "prompt"}}}},
			},
		},
	}
	if sites := commandSites(tgt); len(sites) != 0 {
		t.Errorf("expected no command site for a prompt hook, got %+v", sites)
	}
}
