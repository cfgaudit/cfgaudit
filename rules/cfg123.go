// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg123 struct{}

var CFG123 = &cfg123{}

func init() { All = append(All, CFG123) }

func (r *cfg123) ID() string { return "CFG123" }

// yarnReleaseRe is the file name Yarn writes for a committed release:
// yarn-4.5.1.cjs, yarn-1.22.0.js for Yarn 1, yarn-berry.cjs for early
// Yarn 2. On 80 committed .yarnrc.yml files from public repositories, the
// one yarnPath outside these and a .yarn/releases directory was a launcher
// script.
var yarnReleaseRe = regexp.MustCompile(`^yarn-(?:berry|\d+\.\d+\.\d+(?:-[\w.]+)?)\.c?js$`)

// Check reports committed files that stand in for a tool an agent or editor
// runs (#997): a Windows program named like the tool at the repository root,
// which Windows runs before the installed one (CVE-2026-88066); a committed
// Python virtual environment, whose interpreter and entry scripts run when
// an agent uses it (CVE-2026-73217); and a .yarnrc.yml yarnPath that is not
// a Yarn release file, which `yarn --version` loads as JavaScript
// (CVE-2025-59828, CVE-2025-65099).
func (r *cfg123) Check(t *Target) []finding.Finding {
	if t == nil || t.ProjectDir == "" {
		return nil
	}
	var out []finding.Finding
	for _, name := range t.RootFiles {
		if toolBinaryRe.MatchString(name) {
			tool := strings.TrimSuffix(strings.ToLower(name), path.Ext(name))
			out = append(out, finding.Finding{RuleID: "CFG123", Severity: finding.Error, File: filepath.Join(t.ProjectDir, name),
				Message: "the repository commits " + name + " at its root — on Windows a program in the current directory runs before the installed one, so an agent or editor that starts " + tool + " in this checkout runs this file instead. Remove it"})
		}
	}
	for _, v := range t.Venvs {
		out = append(out, finding.Finding{RuleID: "CFG123", Severity: finding.Warn, File: filepath.Join(t.ProjectDir, v, "pyvenv.cfg"),
			Message: "the repository commits a Python virtual environment (" + v + "/) — its interpreter and entry scripts run when an agent activates it or runs a tool from it, and a committed one carries whatever the author put there. Remove it and list the dependencies instead"})
	}
	if y := strings.TrimSpace(t.YarnPath); y != "" {
		clean := path.Clean(strings.ReplaceAll(y, `\`, "/"))
		if dir := path.Dir(clean); (dir != ".yarn/releases" && !strings.HasSuffix(dir, "/.yarn/releases")) || !yarnReleaseRe.MatchString(path.Base(clean)) {
			out = append(out, finding.Finding{RuleID: "CFG123", Severity: finding.Warn, File: t.YarnrcFile, Key: "yarnPath",
				Message: "yarnPath is \"" + y + "\", not a Yarn release under .yarn/releases/yarn-<version>.cjs — Yarn runs that file as JavaScript for every yarn command, including a `yarn --version` an agent or editor runs on open. Point it at the release Yarn wrote, or remove it"})
		}
	}
	return out
}
