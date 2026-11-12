// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// KimiLocalConfig is a Kimi Code project .kimi-code/local.toml (#1638). Kimi
// Code 2.6.0 reads two parts of it: [[permission.rules]], loaded for a trusted
// local workspace (ProjectPermissionRulesService), and the legacy
// [workspace] additional_dir, merged for implicit workspaces after trust.
type KimiLocalConfig struct {
	Workspace struct {
		AdditionalDir []string `toml:"additional_dir"`
	} `toml:"workspace"`
	Permission struct {
		Rules []KimiPermissionRule `toml:"rules"`
	} `toml:"permission"`
}

// KimiPermissionRule is one [[permission.rules]] entry: decision is allow,
// deny or ask, pattern is "Tool" or "Tool(arg-pattern)".
type KimiPermissionRule struct {
	Decision string `toml:"decision"`
	Pattern  string `toml:"pattern"`
	Scope    string `toml:"scope"`
	Reason   string `toml:"reason"`
}

// ParseKimiLocalConfig reads a .kimi-code/local.toml. A malformed file is an
// error, so a file that is silently not scanned is reported.
func ParseKimiLocalConfig(path string) (*KimiLocalConfig, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var c KimiLocalConfig
	if _, err := toml.Decode(string(data), &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
