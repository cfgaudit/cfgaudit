package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func agentTarget(mode string) *Target {
	fm := "---\nname: helper\ndescription: does things\n"
	if mode != "" {
		fm += "permissionMode: " + mode + "\n"
	}
	fm += "---\n\nBody text.\n"
	return &Target{
		Scope:              finding.ScopeProject,
		InstructionFile:    ".claude/agents/helper.md",
		InstructionContent: fm,
	}
}

func TestCFG085_WeakeningModes(t *testing.T) {
	cases := map[string]finding.Severity{
		"bypassPermissions": finding.Error,
		"dontAsk":           finding.Error,
		"auto":              finding.Warn,
		"acceptEdits":       finding.Warn,
	}
	for mode, want := range cases {
		f := CFG085.Check(agentTarget(mode))
		if len(f) != 1 || f[0].Severity != want {
			t.Errorf("expected 1 %s for permissionMode %q, got %+v", want, mode, f)
		}
	}
}

// default, plan and manual prompt normally, and manual is documented as an alias
// for default — none of them weakens anything.
func TestCFG085_SafeModes_NoFinding(t *testing.T) {
	for _, mode := range []string{"default", "plan", "manual", ""} {
		if f := CFG085.Check(agentTarget(mode)); len(f) != 0 {
			t.Errorf("expected no finding for permissionMode %q, got %+v", mode, f)
		}
	}
}

// The field only means something in a subagent definition. Claude Code documents
// that it is ignored for plugin subagents, and it is inert in a CLAUDE.md or a
// skill, so firing there would be a false positive.
func TestCFG085_WrongSurface_NoFinding(t *testing.T) {
	body := "---\nname: x\ndescription: d\npermissionMode: bypassPermissions\n---\nbody\n"
	for _, path := range []string{
		"CLAUDE.md",
		".claude/skills/x/SKILL.md",
		".claude/commands/x.md",
		"plugins/foo/agents/helper.md", // plugin tree, not .claude/agents
		".cursorrules",
	} {
		tgt := &Target{Scope: finding.ScopeProject, InstructionFile: path, InstructionContent: body}
		if f := CFG085.Check(tgt); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", path, f)
		}
	}
}

func TestCFG085_UserScopeAgent(t *testing.T) {
	tgt := agentTarget("bypassPermissions")
	tgt.InstructionFile = "/home/u/.claude/agents/helper.md"
	if f := CFG085.Check(tgt); len(f) != 1 {
		t.Errorf("expected the finding for a user-scope agent file, got %+v", f)
	}
}

func TestCFG085_NoFrontmatter_NoFinding(t *testing.T) {
	tgt := &Target{Scope: finding.ScopeProject, InstructionFile: ".claude/agents/helper.md", InstructionContent: "no frontmatter here\n"}
	if f := CFG085.Check(tgt); len(f) != 0 {
		t.Errorf("expected no finding without frontmatter, got %+v", f)
	}
}

func TestCFG085_NoTarget_NoFinding(t *testing.T) {
	if f := CFG085.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding for an empty target, got %+v", f)
	}
}

// #386: Grok .grok/agents/*.md uses the same permissionMode field, but Grok
// wires only bypassPermissions at spawn — the softer modes are forward-compat
// and inert, so reporting them would be a false positive.
func grokAgentTarget(mode string) *Target {
	fm := "---\nname: helper\n"
	if mode != "" {
		fm += "permissionMode: " + mode + "\n"
	}
	fm += "---\n\nBody text.\n"
	return &Target{
		Scope:              finding.ScopeProject,
		InstructionFile:    ".grok/agents/helper.md",
		InstructionContent: fm,
	}
}

func TestCFG085_Grok_BypassPermissions_Error(t *testing.T) {
	f := CFG085.Check(grokAgentTarget("bypassPermissions"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for Grok bypassPermissions, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Grok") {
		t.Errorf("expected the message to mention Grok, got %q", f[0].Message)
	}
}

func TestCFG085_Grok_ForwardCompatModes_NoFinding(t *testing.T) {
	// dontAsk/auto/acceptEdits are parsed by Grok but not wired at spawn, so a
	// committed value is inert and must not be flagged.
	for _, mode := range []string{"dontAsk", "auto", "acceptEdits"} {
		if f := CFG085.Check(grokAgentTarget(mode)); len(f) != 0 {
			t.Errorf("expected no finding for Grok inert mode %q, got %+v", mode, f)
		}
	}
}

// #579: qwen .qwen/agents/*.md mirrors the Claude agent schema but resolves the
// mode as `approvalMode ?? bridge(permissionMode)`. qwenAgentTarget builds a file
// with an optional native approvalMode and/or a Claude permissionMode.
func qwenAgentTarget(approvalMode, permissionMode string) *Target {
	fm := "---\nname: helper\ndescription: does things\n"
	if approvalMode != "" {
		fm += "approvalMode: " + approvalMode + "\n"
	}
	if permissionMode != "" {
		fm += "permissionMode: " + permissionMode + "\n"
	}
	fm += "---\n\nBody text.\n"
	return &Target{
		Scope:              finding.ScopeProject,
		InstructionFile:    ".qwen/agents/helper.md",
		InstructionContent: fm,
	}
}

func TestCFG085_Qwen_NativeApprovalMode(t *testing.T) {
	cases := map[string]finding.Severity{
		"yolo":      finding.Error,
		"auto-edit": finding.Warn,
		"auto":      finding.Warn,
	}
	for mode, want := range cases {
		f := CFG085.Check(qwenAgentTarget(mode, ""))
		if len(f) != 1 || f[0].Severity != want {
			t.Errorf("expected 1 %s for qwen approvalMode %q, got %+v", want, mode, f)
		}
	}
}

// default, plan and the subagent-only bubble mode prompt normally.
func TestCFG085_Qwen_SafeApprovalModes_NoFinding(t *testing.T) {
	for _, mode := range []string{"default", "plan", "bubble", ""} {
		if f := CFG085.Check(qwenAgentTarget(mode, "")); len(f) != 0 {
			t.Errorf("expected no finding for qwen approvalMode %q, got %+v", mode, f)
		}
	}
}

// An approvalMode outside the enum makes qwen reject the whole file, so cfgaudit
// must not treat it as a configured weakening.
func TestCFG085_Qwen_InvalidApprovalMode_NoFinding(t *testing.T) {
	if f := CFG085.Check(qwenAgentTarget("full-send", "")); len(f) != 0 {
		t.Errorf("expected no finding for an invalid qwen approvalMode, got %+v", f)
	}
}

// permissionMode bridges only when approvalMode is unset. bypassPermissions
// bridges to yolo (Error), acceptEdits/auto bridge to auto-edit (Warn).
func TestCFG085_Qwen_PermissionModeBridge(t *testing.T) {
	cases := map[string]finding.Severity{
		"bypassPermissions": finding.Error,
		"acceptEdits":       finding.Warn,
		"auto":              finding.Warn,
	}
	for mode, want := range cases {
		f := CFG085.Check(qwenAgentTarget("", mode))
		if len(f) != 1 || f[0].Severity != want {
			t.Errorf("expected 1 %s for qwen permissionMode %q, got %+v", want, mode, f)
		}
		if !strings.Contains(f[0].Message, "bridges to approvalMode") {
			t.Errorf("expected the bridge to be named for permissionMode %q, got %q", mode, f[0].Message)
		}
	}
}

// qwen maps dontAsk to default (preserving its restrictive intent), so it is NOT
// a weakening value here even though CFG085 flags it for a Claude file. default
// and plan also prompt normally.
func TestCFG085_Qwen_SafePermissionModes_NoFinding(t *testing.T) {
	for _, mode := range []string{"dontAsk", "default", "plan"} {
		if f := CFG085.Check(qwenAgentTarget("", mode)); len(f) != 0 {
			t.Errorf("expected no finding for qwen permissionMode %q, got %+v", mode, f)
		}
	}
}

// permissionMode: yolo is not a value of the Claude enum, so qwen drops it. This
// is the common corpus shape (every sampled permissionMode: hit is yolo) and must
// stay inert.
func TestCFG085_Qwen_PermissionModeYolo_NoFinding(t *testing.T) {
	if f := CFG085.Check(qwenAgentTarget("", "yolo")); len(f) != 0 {
		t.Errorf("expected no finding for qwen permissionMode: yolo, got %+v", f)
	}
}

// A present approvalMode wins over permissionMode: approvalMode default with a
// permissionMode of bypassPermissions resolves to default, so nothing fires.
func TestCFG085_Qwen_ApprovalModeWinsOverPermissionMode(t *testing.T) {
	if f := CFG085.Check(qwenAgentTarget("default", "bypassPermissions")); len(f) != 0 {
		t.Errorf("expected approvalMode to win and suppress the bridge, got %+v", f)
	}
	// And when the native mode is the weakening one, it fires as itself.
	f := CFG085.Check(qwenAgentTarget("yolo", "default"))
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "approvalMode: \"yolo\"") {
		t.Errorf("expected the native yolo to fire, got %+v", f)
	}
}
