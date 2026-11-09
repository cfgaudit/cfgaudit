// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg136 struct{}

// CFG136 reports a Claude Code plugin hooks.json that names hooks modules
// (#1601). Measured on 2.1.321: a skills-directory plugin's module loads
// after workspace trust with no install step, "(worker, environment 1, tier
// user)", and its session.start hook ran a host command through
// $.process.run with no prompt. The module's content is code and is not
// scanned.
var CFG136 = &cfg136{}

func init() { All = append(All, CFG136) }

func (r *cfg136) ID() string { return "CFG136" }

func (r *cfg136) Check(t *Target) []finding.Finding {
	if t == nil || t.PluginHookModulesFile == "" {
		return nil
	}
	dir := filepath.Dir(t.PluginHookModulesFile)
	var out []finding.Finding
	for _, m := range t.PluginHookModules {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		where := filepath.ToSlash(filepath.Join(filepath.Base(dir), filepath.FromSlash(m)))
		if parser.ManifestPathEscapes(m) {
			where = m
		}
		out = append(out, finding.Finding{
			RuleID:   "CFG136",
			Severity: finding.Warn,
			File:     t.PluginHookModulesFile,
			Key:      "modules",
			Message:  "hooks.json loads the hooks module \"" + where + "\": Claude Code runs it as code in a worker of its own process at session start, once the workspace is trusted and with no install step, and through its $ it can run host commands ($.process.run), read and write files and answer tool calls. cfgaudit does not scan the module's code. Review it as you would a hook script, or drop the plugin" + userScopeNote(t),
		})
	}
	return out
}
