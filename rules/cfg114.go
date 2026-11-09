// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg114 struct{}

// CFG114 reports a committed OpenCode plugin or tool file: JavaScript or
// TypeScript that OpenCode imports and runs from the repository itself, with no
// prompt and no workspace trust step (#642).
var CFG114 = &cfg114{}

func init() { All = append(All, CFG114) }

func (r *cfg114) ID() string { return "CFG114" }

// openCodeCodeWhen says when each kind of file runs, as measured with opencode
// 1.18.18: plugins during any startup, including a bare `opencode debug config`,
// and tools as soon as an agent is loaded.
var openCodeCodeWhen = map[string]string{
	"plugin": "every time OpenCode starts in this repository, before any session and with no prompt (a bare `opencode debug config` is enough)",
	"tool":   "as soon as OpenCode loads an agent in this repository, before the model calls anything and with no prompt",
	// OpenCode 2 plugin directories (#748), read from the v2.2.6 source.
	"plugin-dir": "when OpenCode 2 starts in this repository, with no prompt (from the OpenCode 2 source; OpenCode 1.x does not load a plugin directory)",
}

// openCodeCodeName is how the message names each kind.
var openCodeCodeName = map[string]string{"plugin-dir": "plugin directory", "plugin-gui": "desktop plugin directory"}

// Check flags the file. Its content is code, which cfgaudit does not analyse,
// so the finding is about the trigger, the same reasoning as CFG047 for a
// folderOpen task and CFG086 for a zero-click hook: committed code that runs on
// opening the project is a finding even when it looks innocuous, because a
// reader has to review it before the first run, not after.
func (r *cfg114) Check(t *Target) []finding.Finding {
	if t == nil || t.AgentCode == nil {
		return nil
	}
	if t.AgentCode.Kind == "copilot-extension" {
		return []finding.Finding{{
			RuleID:   "CFG114",
			Severity: finding.Info,
			Scope:    t.Scope,
			File:     t.AgentCode.Path,
			Message:  "committed Copilot CLI project extension " + filepath.Base(filepath.Dir(t.AgentCode.Path)) + " is run with Node.js when the CLI starts in this repository, with the user's own privileges. Two gates stand in front of it: extensions are experimental (`--experimental` or `/experimental on`), and project extensions load only once the folder is trusted. cfgaudit does not analyse the code; review it before turning experimental features on in a clone",
		}}
	}
	if t.AgentCode.Kind == "plugin-gui" {
		return []finding.Finding{{
			RuleID:   "CFG114",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.AgentCode.Path,
			Message: "committed OpenCode desktop plugin directory " + filepath.Base(filepath.Dir(t.AgentCode.Path)) + " has only a desktop part, " + filepath.Base(t.AgentCode.Path) +
				", which the OpenCode 2 desktop app runs in its windows when it opens this project. Whether that asks first is not measured. cfgaudit does not analyse the code; review it before opening a clone in the desktop app",
		}}
	}
	if kind, ok := strings.CutPrefix(t.AgentCode.Kind, "kilo-"); ok {
		when := "every time Kilo Code starts in this repository, before any session and with no prompt"
		if kind == "tool" {
			when = "as soon as Kilo Code loads an agent in this repository, before the model calls anything and with no prompt"
		}
		return []finding.Finding{{
			RuleID: "CFG114", Severity: finding.Error, Scope: t.Scope, File: t.AgentCode.Path,
			Message: "committed Kilo Code " + kind + " " + filepath.Base(t.AgentCode.Path) + " is imported and run " + when +
				" (Kilo Code shares OpenCode's loader, read from the v7.8.27 source). It has no workspace trust step for this code, so anyone who opens a clone with Kilo Code runs it with their own permissions. cfgaudit does not analyse the code itself; review it before the first run",
		}}
	}
	when := openCodeCodeWhen[t.AgentCode.Kind]
	what := t.AgentCode.Kind
	subject := filepath.Base(t.AgentCode.Path)
	if n, ok := openCodeCodeName[what]; ok {
		what = n
		subject = filepath.Base(filepath.Dir(t.AgentCode.Path)) + " (" + subject + ")"
	}
	return []finding.Finding{{
		RuleID:   "CFG114",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     t.AgentCode.Path,
		Message: "committed OpenCode " + what + " " + subject + " is imported and run " + when +
			". OpenCode has no workspace trust step, so anyone who opens a clone with OpenCode runs this code with their own permissions. cfgaudit does not analyse the code itself; review it before the first run, and keep it out of the repository if it is not meant for every contributor",
	}}
}
