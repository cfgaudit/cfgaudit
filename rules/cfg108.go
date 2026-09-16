package rules

import (
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg108 struct{}

// CFG108 reports a committed .claude/scheduled_tasks.json, Claude Code's
// cron-scheduler store, that carries actionable tasks.
var CFG108 = &cfg108{}

func init() { All = append(All, CFG108) }

func (r *cfg108) ID() string { return "CFG108" }

// Check flags a committed scheduled_tasks.json whose tasks would run on a timer
// in a contributor's session. Two things make a committed copy dangerous, both
// read from the 2.1.273 binary and confirmed by driving an interactive session:
//
//  1. The file self-enables the scheduler. Scheduling is off by default (the
//     launch flag initialises to false), but the interactive scheduler's start()
//     calls replaceScheduledTasksEnabled(true) whenever the store has a non-empty
//     tasks array (nan()), so the file's presence turns the feature on.
//  2. A task with no session identity fires in any checkout. The fire gate
//     de(task) returns the scheduler-lock flag for a task with no
//     createdBySessionId, so a "bare" task runs here; a session-bound task stays
//     inert unless createdInProject resolves to this project and the pid matches.
//
// A fired task enqueues its `prompt` as if the user had typed it — verified: an
// interactive session with a committed bare recurring task sent the task's prompt
// to the API with the billing header cc_workload=cron, no interaction.
//
// Severity follows the bare/session-bound split, which is what separates a live
// task from an inert one:
//
//   - a bare task (no createdBySessionId, no createdInProject) is error: it
//     self-enables the scheduler and fires in any clone;
//   - a session-bound task is info: inert on another machine, but still committed
//     autonomous scheduling worth a mention.
//
// Only actionable tasks count (a prompt to enqueue and a cron to fire on); an
// entry missing either does nothing.
func (r *cfg108) Check(t *Target) []finding.Finding {
	if t == nil || t.ScheduledTasks == nil {
		return nil
	}

	var bare, bound []parser.ScheduledTask
	for _, task := range t.ScheduledTasks.Tasks {
		if !task.Actionable() {
			continue
		}
		if task.Bare() {
			bare = append(bare, task)
		} else {
			bound = append(bound, task)
		}
	}

	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG108",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.ScheduledTasksFile,
			Message:  msg + userScopeNote(t),
		})
	}

	if len(bare) > 0 {
		add(finding.Error, "committed scheduled_tasks.json carries "+countTasks(len(bare))+" with no session identity ("+scheduledTaskList(bare)+") — "+
			"a committed scheduler store turns on Claude Code's cron scheduler (off by default, enabled by the file's presence) and enqueues "+theseOrThis(len(bare))+" prompt on the cron schedule in every contributor's interactive session, as if typed and with no interaction. "+
			"Delete the file from the repository: scheduled tasks are per-user runtime state, not shared configuration")
	}

	if len(bound) > 0 {
		staysInert := "it stays inert"
		if len(bound) != 1 {
			staysInert = "they stay inert"
		}
		add(finding.Info, "committed scheduled_tasks.json carries "+countTasks(len(bound))+" bound to the author's own session or checkout ("+scheduledTaskList(bound)+") — "+
			staysInert+" in another clone, but a committed scheduler store is committed autonomous scheduling and turns the scheduler on for everyone. Remove it from the repository")
	}

	return findings
}

// scheduledTaskList renders up to three tasks as `<cron>` with a short prompt
// preview, so a finding names what would run without dumping every prompt.
func scheduledTaskList(tasks []parser.ScheduledTask) string {
	const max = 3
	parts := make([]string, 0, max)
	for i, task := range tasks {
		if i == max {
			parts = append(parts, "…")
			break
		}
		cron := strings.TrimSpace(task.Cron)
		label := "\"" + cron + "\""
		if task.Recurring {
			label += " recurring"
		}
		parts = append(parts, label+" → "+previewPrompt(task.Prompt))
	}
	return strings.Join(parts, "; ")
}

// previewPrompt trims a task prompt to a short single-line preview, cutting on a
// rune boundary so a multibyte character is never split.
func previewPrompt(prompt string) string {
	p := strings.Join(strings.Fields(prompt), " ")
	const max = 60
	if r := []rune(p); len(r) > max {
		p = string(r[:max]) + "…"
	}
	return "\"" + p + "\""
}

// countTasks renders "1 scheduled task" / "N scheduled tasks".
func countTasks(n int) string {
	if n == 1 {
		return "1 scheduled task"
	}
	return strconv.Itoa(n) + " scheduled tasks"
}

// theseOrThis agrees with the task count.
func theseOrThis(n int) string {
	if n == 1 {
		return "its"
	}
	return "their"
}
