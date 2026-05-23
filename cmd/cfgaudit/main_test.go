package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/rules"
)

// stubRule lets the filter tests run without touching the real rule registry.
type stubRule struct{ id string }

func (s stubRule) ID() string                              { return s.id }
func (s stubRule) Check(_ *rules.Target) []finding.Finding { return nil }

var (
	r1 = stubRule{id: "CFG001"}
	r2 = stubRule{id: "CFG002"}
	r3 = stubRule{id: "CFG003"}
)

func TestRuleSet_Set_CSVAndRepeats(t *testing.T) {
	var rs ruleSet
	if err := rs.Set("CFG001, CFG002"); err != nil {
		t.Fatalf("Set csv: %v", err)
	}
	if err := rs.Set("CFG003"); err != nil {
		t.Fatalf("Set repeated: %v", err)
	}
	if err := rs.Set(""); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	want := ruleSet{"CFG001": true, "CFG002": true, "CFG003": true}
	if !reflect.DeepEqual(rs, want) {
		t.Errorf("Set produced %v, want %v", rs, want)
	}
}

func TestRuleFilter_NilWhenNoFlags(t *testing.T) {
	if got := ruleFilter(nil, nil); got != nil {
		t.Errorf("ruleFilter with empty sets must return nil, got non-nil")
	}
}

func TestRuleFilter_OnlyTakesPrecedenceOverSkip(t *testing.T) {
	only := ruleSet{"CFG001": true, "CFG002": true}
	skip := ruleSet{"CFG002": true}
	accept := ruleFilter(only, skip)

	if !accept(r1) {
		t.Errorf("CFG001 should be accepted (in only, not in skip)")
	}
	if accept(r2) {
		t.Errorf("CFG002 should be rejected (skip wins after only allows it)")
	}
	if accept(r3) {
		t.Errorf("CFG003 should be rejected (not in only)")
	}
}

func TestRuleFilter_OnlySkip_NoOnly(t *testing.T) {
	skip := ruleSet{"CFG002": true}
	accept := ruleFilter(nil, skip)

	if !accept(r1) || !accept(r3) {
		t.Errorf("non-skipped rules must pass when only is empty")
	}
	if accept(r2) {
		t.Errorf("CFG002 must be skipped")
	}
}

func TestUnknownRuleIDs(t *testing.T) {
	only := ruleSet{"CFG001": true, "CFGXYZ": true}
	skip := ruleSet{"CFG999": true, "CFG001": true}
	all := []rules.Rule{r1, r2, r3}

	got := unknownRuleIDs(only, skip, all)
	want := []string{"CFG999", "CFGXYZ"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unknownRuleIDs = %v, want %v", got, want)
	}
}

func TestBuildTargets_DiscoversProjectMCPJSON(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".mcp.json"),
		`{"mcpServers":{"fs":{"command":"npx","args":["pkg@latest"]}}}`)

	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	// With no settings.json, the single project target carries the .mcp.json servers.
	if len(targets) != 1 {
		t.Fatalf("expected 1 target (project, from .mcp.json), got %d", len(targets))
	}
	tg := targets[0]
	if tg.Scope != finding.ScopeProject {
		t.Errorf("expected project scope, got %s", tg.Scope)
	}
	if tg.Settings != nil {
		t.Errorf("expected nil Settings when settings.json absent, got %+v", tg.Settings)
	}
	if len(tg.ProjectMCP) != 1 || tg.ProjectMCPFile != filepath.Join(dir, ".mcp.json") {
		t.Errorf("expected .mcp.json servers attached, got %d servers, file %q", len(tg.ProjectMCP), tg.ProjectMCPFile)
	}
}

func TestBuildTargets_MCPJSONAttachesToSettingsTarget(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{"permissions":{"deny":["Read(.env)"]}}`)
	mustWrite(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{"fs":{"command":"npx","args":["pkg@latest"]}}}`)

	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	// settings.json and .mcp.json must share one project target, not two.
	var project []*rules.Target
	for _, tg := range targets {
		if tg.Scope == finding.ScopeProject {
			project = append(project, tg)
		}
	}
	if len(project) != 1 {
		t.Fatalf("expected exactly 1 project target, got %d", len(project))
	}
	if project[0].Settings == nil || len(project[0].ProjectMCP) != 1 {
		t.Errorf("expected both settings.json and .mcp.json on the project target")
	}
}

func TestBuildTargets_MalformedMCPJSON_Errors(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".mcp.json"), `{not json`)
	if _, err := buildTargets(dir, false); err == nil {
		t.Error("expected error for malformed .mcp.json, got nil")
	}
}

func TestBuildTargets_NoMCPJSON_NoProjectTargetWithoutSettings(t *testing.T) {
	dir := t.TempDir() // empty: no settings.json, no .mcp.json
	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected no targets for empty dir, got %d", len(targets))
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
