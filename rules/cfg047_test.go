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
