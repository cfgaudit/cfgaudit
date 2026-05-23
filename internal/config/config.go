// Package config loads the optional .cfgaudit.yml project configuration:
// per-rule severity overrides and disables, a minimum severity to report,
// strict / no-exit-code behaviour, and path globs to exclude from results.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"gopkg.in/yaml.v3"
)

// FileNames are the config file names auto-discovered in the scanned directory.
var FileNames = []string{".cfgaudit.yml", ".cfgaudit.yaml"}

// Config is the decoded .cfgaudit.yml. A nil *Config is valid and inert: every
// method treats it as "no configuration".
type Config struct {
	Rules        map[string]RuleConfig `yaml:"rules"`
	MinSeverity  string                `yaml:"min-severity"`
	Strict       bool                  `yaml:"strict"`
	NoExitCodes  bool                  `yaml:"no-exit-codes"`
	ExcludePaths []string              `yaml:"exclude-paths"`
}

// RuleConfig is a per-rule override. It accepts either the flat form
// (`CFG003: off`) or the nested form (`CFG004: {severity: warn}`).
type RuleConfig struct {
	Off      bool
	Severity string
}

// UnmarshalYAML accepts a scalar ("off" to disable, or a severity to override)
// or a mapping ({off: true, severity: warn}).
func (rc *RuleConfig) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if strings.EqualFold(node.Value, "off") {
			rc.Off = true
			return nil
		}
		rc.Severity = node.Value
		return nil
	case yaml.MappingNode:
		var aux struct {
			Off      bool   `yaml:"off"`
			Severity string `yaml:"severity"`
		}
		if err := node.Decode(&aux); err != nil {
			return err
		}
		rc.Off, rc.Severity = aux.Off, aux.Severity
		return nil
	default:
		return fmt.Errorf("rule config must be a string or a mapping, got %v", node.Kind)
	}
}

// Load reads and decodes an explicit config path. A missing file is an error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path supplied via --config by the user
	if err != nil {
		return nil, err
	}
	return parse(data, path)
}

// Discover looks for a config file in dir. Returns (nil, "", nil) when none exists.
func Discover(dir string) (*Config, string, error) {
	for _, name := range FileNames {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p) // #nosec G304 -- path resolved from the scanned dir
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, "", err
		}
		c, err := parse(data, p)
		if err != nil {
			return nil, "", err
		}
		return c, p, nil
	}
	return nil, "", nil
}

func parse(data []byte, path string) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// ExitCode returns the process exit code for a finding set: 1 when any error is
// present (or, under strict, any warn), else 0. no-exit-codes forces 0. Safe on
// a nil *Config (behaves as the default: errors → 1).
func (c *Config) ExitCode(findings []finding.Finding) int {
	if c != nil && c.NoExitCodes {
		return 0
	}
	strict := c != nil && c.Strict
	for _, f := range findings {
		if f.Severity == finding.Error || (strict && f.Severity == finding.Warn) {
			return 1
		}
	}
	return 0
}

// RuleEnabled reports whether a rule may run (false when disabled via `off`).
func (c *Config) RuleEnabled(id string) bool {
	if c == nil {
		return true
	}
	rc, ok := c.Rules[id]
	return !ok || !rc.Off
}

// PostProcess applies severity overrides, the min-severity filter, and
// exclude-paths to a finding set. dir is the scan root, used to resolve
// exclude globs relative to it.
func (c *Config) PostProcess(findings []finding.Finding, dir string) []finding.Finding {
	if c == nil {
		return findings
	}
	minRank := severityRank(c.MinSeverity) // 0 when unset/invalid → no filtering
	out := findings[:0]
	for _, f := range findings {
		if rc, ok := c.Rules[f.RuleID]; ok && rc.Severity != "" {
			if sev, valid := parseSeverity(rc.Severity); valid {
				f.Severity = sev
			}
		}
		if severityRank(string(f.Severity)) < minRank {
			continue
		}
		if c.pathExcluded(dir, f.File) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (c *Config) pathExcluded(dir, file string) bool {
	if len(c.ExcludePaths) == 0 || file == "" {
		return false
	}
	rel, err := filepath.Rel(dir, file)
	if err != nil {
		rel = file
	}
	rel = filepath.ToSlash(rel)
	for _, pat := range c.ExcludePaths {
		if matchGlob(pat, rel) {
			return true
		}
	}
	return false
}

// severityRank orders severities so a min-severity filter can compare. An
// unrecognised or empty value ranks 0 (info), i.e. disables filtering.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "warn":
		return 1
	case "error":
		return 2
	default:
		return 0
	}
}

func parseSeverity(s string) (finding.Severity, bool) {
	switch strings.ToLower(s) {
	case "error":
		return finding.Error, true
	case "warn":
		return finding.Warn, true
	case "info":
		return finding.Info, true
	}
	return "", false
}

// matchGlob matches a path against a glob supporting `*` (within a segment),
// `**` (across segments), `?`, and a trailing `/` (directory prefix).
func matchGlob(pattern, path string) bool {
	pattern = filepath.ToSlash(pattern)
	if strings.HasSuffix(pattern, "/") {
		return path == strings.TrimSuffix(pattern, "/") || strings.HasPrefix(path, pattern)
	}
	return globToRegexp(pattern).MatchString(path)
}

func globToRegexp(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				b.WriteString(".*")
				i++
				if i+1 < len(p) && p[i+1] == '/' {
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
