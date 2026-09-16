package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func schedTarget(tasks ...parser.ScheduledTask) *Target {
	return &Target{
		Scope:              finding.ScopeProject,
		ScheduledTasks:     &parser.ScheduledTasks{Tasks: tasks},
		ScheduledTasksFile: ".claude/scheduled_tasks.json",
	}
}

// A bare task (no session identity) fires in any checkout: error.
func TestCFG108_BareTask_Error(t *testing.T) {
	f := CFG108.Check(schedTarget(parser.ScheduledTask{
		ID: "x", Cron: "* * * * *", Prompt: "do the thing", Recurring: true,
	}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error for a bare task, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "no session identity") {
		t.Errorf("message = %q", f[0].Message)
	}
}

// A session-bound task is inert on another machine: info.
func TestCFG108_SessionBound_Info(t *testing.T) {
	for _, task := range []parser.ScheduledTask{
		{ID: "x", Cron: "0 9 * * *", Prompt: "p", CreatedBySession: "sess-abc"},
		{ID: "y", Cron: "0 9 * * *", Prompt: "p", CreatedInProject: "/home/author/repo"},
	} {
		f := CFG108.Check(schedTarget(task))
		if len(f) != 1 || f[0].Severity != finding.Info {
			t.Errorf("expected 1 info for a session-bound task, got %+v", f)
		}
	}
}

// Bare and bound in one file: an error and an info, not one merged finding.
func TestCFG108_Mixed_TwoTiers(t *testing.T) {
	f := CFG108.Check(schedTarget(
		parser.ScheduledTask{ID: "bare", Cron: "* * * * *", Prompt: "a", Recurring: true},
		parser.ScheduledTask{ID: "bound", Cron: "0 9 * * *", Prompt: "b", CreatedBySession: "s"},
	))
	sev := map[finding.Severity]int{}
	for _, x := range f {
		sev[x.Severity]++
	}
	if sev[finding.Error] != 1 || sev[finding.Info] != 1 || len(f) != 2 {
		t.Fatalf("expected one error and one info, got %+v", f)
	}
}

// A task with no prompt or no cron does nothing, so it is not reported.
func TestCFG108_NonActionable_NoFinding(t *testing.T) {
	for _, task := range []parser.ScheduledTask{
		{ID: "x", Cron: "* * * * *", Prompt: "   "}, // no prompt
		{ID: "y", Cron: "  ", Prompt: "p"},          // no cron
	} {
		if f := CFG108.Check(schedTarget(task)); len(f) != 0 {
			t.Errorf("expected no finding for a non-actionable task %+v, got %+v", task, f)
		}
	}
}

func TestCFG108_NoTasks_NoFinding(t *testing.T) {
	if f := CFG108.Check(schedTarget()); len(f) != 0 {
		t.Errorf("empty tasks: expected no finding, got %+v", f)
	}
	if f := CFG108.Check(&Target{}); len(f) != 0 {
		t.Errorf("no store: expected no finding, got %+v", f)
	}
}
