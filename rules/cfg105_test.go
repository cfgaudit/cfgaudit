package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func openCodePermTarget(permission string, agents map[string]string) *Target {
	cfg := &parser.OpenCodeConfig{}
	if permission != "" {
		cfg.Permission = json.RawMessage(permission)
	}
	if len(agents) > 0 {
		cfg.Agent = map[string]parser.OpenCodeAgent{}
		for name, perm := range agents {
			cfg.Agent[name] = parser.OpenCodeAgent{Permission: json.RawMessage(perm)}
		}
	}
	return &Target{Scope: finding.ScopeProject, OpenCode: cfg, OpenCodeFile: "opencode.json"}
}

// The ordinary allows restate OpenCode's own defaults, whose ruleset opens with
// {action: "*", resource: "*", effect: "allow"}, so none of them is a finding.
func TestCFG105_OrdinaryAllowsAreSilent(t *testing.T) {
	f := CFG105.Check(openCodePermTarget(`{"bash":"allow","edit":"allow","glob":"allow","webfetch":"allow","skill":"allow"}`, nil))
	if len(f) != 0 {
		t.Errorf("expected no findings for allows that restate the defaults, got %+v", f)
	}
}

// read: allow lands after the defaults, and findLast means it wins over the
// .env entries the defaults put on ask.
func TestCFG105_ReadAllowRemovesTheEnvPrompt(t *testing.T) {
	f := CFG105.Check(openCodePermTarget(`{"read":"allow"}`, nil))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, ".env") || !strings.Contains(f[0].Message, `"read": "allow"`) {
		t.Errorf("message should name the file's own rule, got %q", f[0].Message)
	}
}

// The fix the message suggests must actually silence the rule.
func TestCFG105_RestoringBothEnvPatternsIsSilent(t *testing.T) {
	f := CFG105.Check(openCodePermTarget(`{"read":{"*":"allow","*.env":"ask","*.env.*":"ask"}}`, nil))
	if len(f) != 0 {
		t.Errorf("the suggested fix must silence the finding, got %+v", f)
	}
	// Restoring only one of the two patterns leaves the other open, and the rule
	// says so rather than accepting a half fix.
	half := CFG105.Check(openCodePermTarget(`{"read":{"*":"allow","*.env":"ask"}}`, nil))
	if len(half) != 1 || !strings.Contains(half[0].Message, "*.env.*") {
		t.Errorf("expected the remaining pattern to be reported, got %+v", half)
	}
}

// Order decides: OpenCode resolves with findLast, so a later ask wins over an
// earlier blanket allow, and the reverse order is a finding.
func TestCFG105_OrderDecides(t *testing.T) {
	quiet := CFG105.Check(openCodePermTarget(`{"*":"allow","external_directory":"ask","read":{"*.env":"ask","*.env.*":"ask"}}`, nil))
	if len(quiet) != 0 {
		t.Errorf("a later ask must win, got %+v", quiet)
	}
	loud := CFG105.Check(openCodePermTarget(`{"external_directory":"ask","*":"allow"}`, nil))
	var sawExternal bool
	for _, x := range loud {
		if strings.Contains(x.Message, "external_directory") {
			sawExternal = true
		}
	}
	if !sawExternal {
		t.Errorf("a later blanket allow must win, got %+v", loud)
	}
}

// A scoped external_directory grant is documented usage; only a pattern
// covering the home directory or the filesystem root is reported.
func TestCFG105_ExternalDirectoryScope(t *testing.T) {
	if f := CFG105.Check(openCodePermTarget(`{"external_directory":{"~/projects/personal/**":"allow"}}`, nil)); len(f) != 0 {
		t.Errorf("a scoped grant is documented usage, got %+v", f)
	}
	f := CFG105.Check(openCodePermTarget(`{"external_directory":{"~/**":"allow"}}`, nil))
	if len(f) != 1 || !strings.Contains(f[0].Message, "home directory") {
		t.Fatalf("expected the home-wide grant reported, got %+v", f)
	}
}

// An agent's own block is resolved separately and named separately.
func TestCFG105_AgentBlockAttribution(t *testing.T) {
	f := CFG105.Check(openCodePermTarget("", map[string]string{"build": `{"external_directory":"allow"}`}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding from the agent block, got %+v", f)
	}
	if !strings.HasPrefix(f[0].Message, "agent.build.permission ") {
		t.Errorf("message should name the agent block, got %q", f[0].Message)
	}
}

// deny narrows, and an absent block or a non-OpenCode target is silent.
func TestCFG105_NarrowingAndAbsent(t *testing.T) {
	if f := CFG105.Check(openCodePermTarget(`{"external_directory":"deny","read":{"*.env":"deny"}}`, nil)); len(f) != 0 {
		t.Errorf("deny must not fire, got %+v", f)
	}
	if f := CFG105.Check(openCodePermTarget("", nil)); len(f) != 0 {
		t.Errorf("absent block, got %+v", f)
	}
	if f := CFG105.Check(&Target{}); len(f) != 0 {
		t.Errorf("non-OpenCode target, got %+v", f)
	}
}
