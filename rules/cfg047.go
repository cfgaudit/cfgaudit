// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
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

// configDirFileRe is a path inside an agent or editor configuration directory,
// where the implants found in the pre-release corpus run for v1.20.0 kept the
// script their folder-open task started (#1181).
var configDirFileRe = regexp.MustCompile(`(?:^|[\s"'/=])\.(?:claude|vscode|cursor|codex|gemini|windsurf|agents?|github/copilot|zed|kiro|roo|cline|continue|opencode|qwen|kimi)/`)

// devStepRe is one step of a project's own dev workflow: a package manager
// running a build, watch, dev-server, test, lint or install script, tsc in
// watch or build mode, a language toolchain's build/test/sync, or compose up.
var devStepRe = regexp.MustCompile(`^(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+|run-script\s+)?(?:(?:watch|dev|start|build|compile|test|serve|lint|typecheck|format|prepare|bootstrap)(?:[:\-][\w:\-]*)?|install|i|ci)|(?:npx\s+)?tsc(?:\s+-[-\w]+)*|(?:uv|poetry|pdm|pipenv)\s+(?:sync|install)|(?:cargo|go)\s+(?:build|check|test|watch|run)|(?:make|just)(?:\s+(?:build|watch|dev|all|setup))?|(?:\./)?gradlew?\s+\w+|mvn\s+\S+|dotnet\s+(?:build|watch|restore|run)|docker\s+compose\s+up|deno\s+task\s+(?:dev|watch|build|start))(?:\s+[\w./=:@,\-]+)*$`)

// devScriptRe is the script name of an npm-type task with the same meaning.
var devScriptRe = regexp.MustCompile(`^(?:watch|dev|start|build|compile|test|serve|lint|typecheck|format|prepare|bootstrap|install)(?:[:\-][\w:\-]*)?$`)

// devStepSplitRe splits a command line into steps at && and ;.
var devStepSplitRe = regexp.MustCompile(`&&|;`)

// taskRunsConfigDirFile reports whether the task, or a task it depends on,
// names a file in an agent or editor configuration directory.
func taskRunsConfigDirFile(task parser.VSCodeTask, all []parser.VSCodeTask) bool {
	return anyDependency(task, all, func(t parser.VSCodeTask) bool {
		for _, l := range t.CommandLines() {
			if configDirFileRe.MatchString(l) {
				return true
			}
		}
		return false
	})
}

// devWorkflowTask reports whether the task only runs the project's own dev
// workflow (#1181): every command line is a chain of dev steps joined by &&
// or ;, with no pipe, redirect, substitution or download; an npm task whose
// script name is a dev script; a TypeScript build or watch task; or a task
// that only depends on such tasks.
func devWorkflowTask(task parser.VSCodeTask, all []parser.VSCodeTask) bool {
	return !anyDependency(task, all, func(t parser.VSCodeTask) bool { return !devWorkflowStep(t) })
}

func devWorkflowStep(task parser.VSCodeTask) bool {
	switch {
	case strings.EqualFold(task.Type, "typescript") && task.Command == "":
		return true
	case strings.EqualFold(task.Type, "npm") && task.Command == "":
		return devScriptRe.MatchString(strings.TrimSpace(task.Script))
	case task.Command == "" && len(task.Args) == 0 && task.Windows == nil && task.Linux == nil && task.OSX == nil:
		// A compound task with only dependsOn runs nothing itself.
		return len(task.DependsOnLabels()) > 0
	}
	for _, l := range task.CommandLines() {
		if l == "" || strings.ContainsAny(l, "|<>`\n") || strings.Contains(l, "$(") {
			return false
		}
		for _, step := range devStepSplitRe.Split(l, -1) {
			if !devStepRe.MatchString(strings.TrimSpace(step)) {
				return false
			}
		}
	}
	return true
}

// anyDependency reports whether pred holds for task or for any task it
// depends on by label, following dependsOn through the file once per task.
// A label that names no task in the file counts as matching, since what it
// runs is unknown.
func anyDependency(task parser.VSCodeTask, all []parser.VSCodeTask, pred func(parser.VSCodeTask) bool) bool {
	byLabel := map[string]parser.VSCodeTask{}
	for _, t := range all {
		if l := strings.TrimSpace(t.Label); l != "" {
			byLabel[l] = t
		}
	}
	seen := map[string]bool{}
	var walk func(parser.VSCodeTask) bool
	walk = func(t parser.VSCodeTask) bool {
		if pred(t) {
			return true
		}
		for _, l := range t.DependsOnLabels() {
			if seen[l] {
				continue
			}
			seen[l] = true
			dep, ok := byLabel[strings.TrimSpace(l)]
			if !ok || walk(dep) {
				return true
			}
		}
		return false
	}
	return walk(task)
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
		sev := finding.Error
		switch {
		case taskRunsConfigDirFile(task, t.VSCodeTasks.Tasks):
			msg += "; the command runs a file inside an agent or editor configuration directory (.claude/, .vscode/, .cursor/, ...), where a project keeps no build code"
		case devWorkflowTask(task, t.VSCodeTasks.Tasks):
			// #1181 option C: the project's own build, watch, dev-server, test
			// or dependency-sync command is warn; anything else stays error.
			sev = finding.Warn
			msg += " (a build, watch, dev-server, test or dependency-sync command of the project, reported at warn)"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG047",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.VSCodeTasksFile,
			Key:      "tasks",
			Message:  msg,
		})
	}
	return findings
}
