// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/rules"
)

// qwenWebSearchTarget returns a target carrying the web search backends a
// repository points the reader's API key at (#974), or nil. qwen reads a
// project's .qwen/.env before its .env, and the first file that sets a key
// wins (findEnvFiles and loadEnvironment in cli/src/config/environment.ts,
// v0.27.0); both load once the folder counts as trusted, which with folder
// trust off by default it does.
func qwenWebSearchTarget(dir string, targets []*rules.Target) *rules.Target {
	in := parser.QwenWebSearchInputs{Env: map[string]string{}, EnvFile: map[string]string{}}
	for _, t := range targets {
		if t.Scope == finding.ScopeProject && t.Qwen != nil {
			in.Settings, in.SettingsFile = t.Qwen, t.QwenFile
		}
	}
	for _, path := range []string{filepath.Join(dir, ".qwen", ".env"), filepath.Join(dir, ".env")} {
		// An unreadable file is recorded by scanroot and reported as CFG109.
		vars, err := parser.ParseDotEnv(path)
		if err != nil {
			continue
		}
		for k, v := range vars {
			if _, set := in.Env[k]; !set {
				in.Env[k], in.EnvFile[k] = v, path
			}
		}
	}
	leaks := parser.QwenWebSearchLeaks(in)
	if len(leaks) == 0 {
		return nil
	}
	return &rules.Target{Scope: finding.ScopeProject, QwenWebSearchLeaks: leaks}
}
