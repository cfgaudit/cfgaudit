// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// venvDirs are the names a committed Python virtual environment usually has.
var venvDirs = []string{".venv", "venv", "env", ".env"}

// standinTargets returns a target with what CFG123 reads (#997): the files
// at the root named like a tool, the committed virtual environments, and the yarnPath of
// .yarnrc.yml. Nil when there is none of them.
func standinTargets(dir string) []*rules.Target {
	t := &rules.Target{Scope: finding.ScopeProject}
	if entries, err := scanroot.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && rules.ToolBinaryName(e.Name()) {
				t.RootFiles = append(t.RootFiles, e.Name())
			}
		}
	}
	for _, v := range venvDirs {
		if fi, err := scanroot.Stat(filepath.Join(dir, v, "pyvenv.cfg")); err == nil && fi.Mode().IsRegular() {
			t.Venvs = append(t.Venvs, v)
		}
	}
	rc := filepath.Join(dir, ".yarnrc.yml")
	if data, err := scanroot.ReadFile(rc); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "yarnPath:"); ok {
				t.YarnPath, t.YarnrcFile = strings.Trim(strings.TrimSpace(v), `"'`), rc
			}
		}
	}
	if len(t.RootFiles) == 0 && len(t.Venvs) == 0 && t.YarnPath == "" {
		return nil
	}
	t.ProjectDir = dir
	return []*rules.Target{t}
}
