// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"

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
}

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
	when := openCodeCodeWhen[t.AgentCode.Kind]
	return []finding.Finding{{
		RuleID:   "CFG114",
		Severity: finding.Error,
		Scope:    t.Scope,
		File:     t.AgentCode.Path,
		Message: "committed OpenCode " + t.AgentCode.Kind + " " + filepath.Base(t.AgentCode.Path) + " is imported and run " + when +
			". OpenCode has no workspace trust step, so anyone who opens a clone with OpenCode runs this code with their own permissions. cfgaudit does not analyse the code itself; review it before the first run, and keep it out of the repository if it is not meant for every contributor",
	}}
}
