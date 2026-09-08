package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// parseCodexApps writes a config.toml and returns it parsed, so the toml tags
// are exercised rather than the struct literal.
func parseCodexApps(t *testing.T, body string) *CodexConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	return c
}

func TestCodexAppApprovals_AllBlanketPositions(t *testing.T) {
	c := parseCodexApps(t, `
[apps._default]
default_tools_approval_mode = "approve"

[apps.linear]
default_tools_approval_mode = "approve"

[apps.linear.links.acct_1]
default_tools_approval_mode = "approve"

[apps.notion]
default_tools_approval_mode = "prompt"

[apps.notion.links.acct_2]
default_tools_approval_mode = "writes"
`)
	got := c.AppApprovals()
	want := []string{
		"apps._default.default_tools_approval_mode",
		"apps.linear.default_tools_approval_mode",
		"apps.linear.links.acct_1.default_tools_approval_mode",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d approvals, got %d: %+v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i].Path != w {
			t.Errorf("approval %d: got %q, want %q", i, got[i].Path, w)
		}
	}
	if got[0].App != CodexAppsDefaultKey {
		t.Errorf("first approval should carry the defaults key, got %q", got[0].App)
	}
	if got[2].Link != "acct_1" {
		t.Errorf("link approval should carry the link id, got %q", got[2].Link)
	}
}

// _default takes neither a tools nor a links table upstream (AppsDefaultConfig
// denies unknown fields), so a file that writes one does not load at all and a
// finding there would name configuration Codex never reads.
func TestCodexAppApprovals_DefaultsTakeNoToolsOrLinks(t *testing.T) {
	c := parseCodexApps(t, `
[apps._default.links.acct_1]
default_tools_approval_mode = "approve"

[apps._default.tools.delete_thing]
approval_mode = "approve"
`)
	if got := c.AppApprovals(); len(got) != 0 {
		t.Errorf("expected no blanket approvals under _default, got %+v", got)
	}
	if got := c.AppToolApprovals(); len(got) != 0 {
		t.Errorf("expected no tool approvals under _default, got %+v", got)
	}
}

func TestCodexAppToolApprovals_OnlyApproveIsCollected(t *testing.T) {
	c := parseCodexApps(t, `
[apps.linear.tools.linear_delete_attachment]
approval_mode = "approve"

[apps.linear.tools.linear_read_issue]
approval_mode = "approve"

[apps.linear.tools.linear_write_issue]
approval_mode = "prompt"

[apps.drive.tools.drive_read_file]
approval_mode = "auto"
`)
	got := c.AppToolApprovals()
	if len(got) != 1 {
		t.Fatalf("expected one app with approved tools, got %+v", got)
	}
	if got[0].App != "linear" || got[0].Path != "apps.linear.tools" {
		t.Errorf("unexpected app/path: %+v", got[0])
	}
	want := []string{"linear_delete_attachment", "linear_read_issue"}
	if len(got[0].Tools) != len(want) {
		t.Fatalf("expected %v, got %v", want, got[0].Tools)
	}
	for i, w := range want {
		if got[0].Tools[i] != w {
			t.Errorf("tool %d: got %q, want %q", i, got[0].Tools[i], w)
		}
	}
}

func TestCodexAppReviewers_AllPositionsAndLegacyAlias(t *testing.T) {
	c := parseCodexApps(t, `
[apps._default]
approvals_reviewer = "auto_review"

[apps.linear]
approvals_reviewer = "guardian_subagent"

[apps.linear.links.acct_1]
approvals_reviewer = "auto_review"

[apps.notion]
approvals_reviewer = "user"
`)
	got := c.AppReviewers()
	want := []struct{ path, value string }{
		{"apps._default.approvals_reviewer", "auto_review"},
		{"apps.linear.approvals_reviewer", "guardian_subagent"},
		{"apps.linear.links.acct_1.approvals_reviewer", "auto_review"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d reviewers, got %d: %+v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i].Path != w.path || got[i].Value != w.value {
			t.Errorf("reviewer %d: got %q=%q, want %q=%q", i, got[i].Path, got[i].Value, w.path, w.value)
		}
	}
}

func TestCodexApps_AbsentAndNil(t *testing.T) {
	c := parseCodexApps(t, "model = \"gpt-5.1\"\n")
	if len(c.AppApprovals())+len(c.AppToolApprovals())+len(c.AppReviewers()) != 0 {
		t.Error("expected nothing from a config without an [apps] table")
	}
	var nilCfg *CodexConfig
	if len(nilCfg.AppApprovals())+len(nilCfg.AppToolApprovals())+len(nilCfg.AppReviewers()) != 0 {
		t.Error("expected nothing from a nil config")
	}
}
