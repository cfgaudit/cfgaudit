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
	if t == nil || t.VSCodeTasks == nil {
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
