package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg047 struct{}

var CFG047 = &cfg047{}

func init() { All = append(All, CFG047) }

func (r *cfg047) ID() string { return "CFG047" }

// Check flags .vscode/tasks.json tasks that run automatically when the folder is
// opened (runOptions.runOn: "folderOpen"). VS Code and its forks (Cursor,
// Windsurf) read this committable file, so an auto-run task is zero-click code
// execution on anyone who opens the repo — actively abused in the wild. A silent
// presentation (reveal: "never") hides it from the user entirely.
func (r *cfg047) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	return append(r.checkVSCode(t), r.checkZed(t)...)
}

// checkZed flags a Zed `.zed/tasks.json` task carrying a `hooks` entry. Zed
// spawns such a task itself — `run_create_worktree_tasks` resolves the templates
// and calls `spawn_in_terminal` directly — so the command runs with no approval
// prompt for it.
//
// **warn, not error.** The trigger is narrower than `folderOpen`: Zed's only hook
// today is `create_worktree`, which needs the user to create a git worktree
// first. That is a deliberate action, so this is not the zero-click case CFG047's
// error covers. What the user is never asked about is the command, and the file
// carrying it is not gated: `.zed/settings.json` is applied only when the
// worktree is trusted, but the Tasks arm of the same SettingsObserver applies
// `.zed/tasks.json` unconditionally. The command's own content is judged
// separately by the command-content rules, which is where a dangerous one earns
// its error.
func (r *cfg047) checkZed(t *Target) []finding.Finding {
	if t.ZedTasks == nil {
		return nil
	}
	var findings []finding.Finding
	for _, task := range t.ZedTasks.Tasks {
		hooks := task.AutoRunHooks()
		if len(hooks) == 0 {
			continue
		}
		msg := "Zed task \"" + task.Name() + "\" is spawned by the \"" + strings.Join(hooks, "\", \"") +
			"\" hook — Zed runs it in a terminal when a git worktree is created, without asking about the command. " +
			"Unlike .zed/settings.json, this file is not worktree-trust gated, so a committed task applies to whoever opens the repo. Drop the hook and invoke the task explicitly"
		if strings.EqualFold(strings.TrimSpace(task.Reveal), "never") {
			msg = "Zed task \"" + task.Name() + "\" is spawned by the \"" + strings.Join(hooks, "\", \"") +
				"\" hook with reveal: \"never\" — Zed runs it in a terminal when a git worktree is created, without asking about the command and without showing it. " +
				"Unlike .zed/settings.json, this file is not worktree-trust gated, so a committed task applies to whoever opens the repo. Drop the hook and invoke the task explicitly"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG047",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.ZedTasksFile,
			Message:  msg,
		})
	}
	return findings
}

func (r *cfg047) checkVSCode(t *Target) []finding.Finding {
	if t.VSCodeTasks == nil {
		return nil
	}
	var findings []finding.Finding
	for _, task := range t.VSCodeTasks.Tasks {
		if task.RunOptions == nil || !strings.EqualFold(task.RunOptions.RunOn, "folderOpen") {
			continue
		}
		name := strings.TrimSpace(task.Label)
		if name == "" {
			name = strings.TrimSpace(task.Command)
		}
		if name == "" {
			name = "(unnamed)"
		}
		msg := "task \"" + name + "\" runs automatically when the folder is opened (runOptions.runOn: \"folderOpen\")" +
			" — committed to a repo this is zero-click code execution on anyone who opens it. Remove the auto-run or put the command behind an explicit invocation"
		if task.Presentation != nil && strings.EqualFold(task.Presentation.Reveal, "never") {
			msg = "task \"" + name + "\" runs automatically and silently when the folder is opened (runOptions.runOn: \"folderOpen\", presentation.reveal: \"never\")" +
				" — committed to a repo this is invisible zero-click code execution on anyone who opens it. Remove it"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG047",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.VSCodeTasksFile,
			Message:  msg,
		})
	}
	return findings
}
