// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package config loads the optional .cfgaudit.yml project configuration:
// per-rule severity overrides and disables, a minimum severity to report,
// strict / no-exit-code behaviour, and path globs to exclude from results.
package config

import (
	"errors"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/safeyaml"
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
	Policy       Policy                `yaml:"policy"`
	ShellCheck   bool                  `yaml:"shellcheck"`
	// ShellCheckExclude lists ShellCheck codes CFG045 never reports, passed to
	// shellcheck as --exclude. parse normalizes each entry to "SC" plus four
	// digits and rejects anything else (#717).
	ShellCheckExclude []string `yaml:"shellcheck-exclude"`
	// ContentPaths are globs, relative to the scanned directory and in the
	// exclude-paths syntax, naming files that are not agent instruction files
	// but that agents read while they work, such as README.md or docs/**/*.md.
	// The high-precision instruction-content rules scan them too (#795).
	ContentPaths []string `yaml:"content-paths"`

	// ruleLines maps each rule ID under rules to its line in the file, for
	// UnknownRuleIDs.
	ruleLines map[string]int
}

// UnknownRule is a rule ID under rules that no registered rule reports.
type UnknownRule struct {
	ID   string
	Line int
}

// UnknownRuleIDs returns the rule IDs under rules that are not in known, in
// file order. The caller warns about them: an unknown ID is not an error, so a
// config written for a newer cfgaudit still loads (#1051). Safe on a nil
// *Config.
func (c *Config) UnknownRuleIDs(known map[string]bool) []UnknownRule {
	if c == nil {
		return nil
	}
	var out []UnknownRule
	for id, line := range c.ruleLines {
		if !known[id] {
			out = append(out, UnknownRule{ID: id, Line: line})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// ContentPathGlobs returns the content-paths globs. Safe on a nil *Config.
func (c *Config) ContentPathGlobs() []string {
	if c == nil {
		return nil
	}
	return c.ContentPaths
}

// ShellCheckEnabled reports whether shellcheck analysis is requested via config.
// Safe on a nil *Config.
func (c *Config) ShellCheckEnabled() bool {
	return c != nil && c.ShellCheck
}

// ShellCheckExcludes returns the normalized shellcheck-exclude codes. Safe on a
// nil *Config.
func (c *Config) ShellCheckExcludes() []string {
	if c == nil {
		return nil
	}
	return c.ShellCheckExclude
}

// shellCheckCodeRe matches a ShellCheck code with or without its SC prefix, in
// either case: SC2086, sc2086, 2086.
var shellCheckCodeRe = regexp.MustCompile(`^(?i:SC)?([0-9]{4})$`)

// normalizeShellCheckCodes rewrites each code as "SC" plus its four digits,
// the spelling shellcheck --exclude accepts (it rejects a lowercase "sc").
func normalizeShellCheckCodes(codes []string) ([]string, error) {
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		m := shellCheckCodeRe.FindStringSubmatch(strings.TrimSpace(code))
		if m == nil {
			return nil, fmt.Errorf("shellcheck-exclude: %q is not a ShellCheck code (SC followed by four digits, e.g. SC2086)", code)
		}
		out = append(out, "SC"+m[1])
	}
	return out, nil
}

// Policy is the organisation's custom permission policy (evaluated by CFG025):
// commands that must be blocked by permissions.deny, and commands that must not
// be grantable by permissions.allow.
type Policy struct {
	RequireDeny []string `yaml:"require-deny"`
	ForbidAllow []string `yaml:"forbid-allow"`
}

// Configured reports whether any policy entries are set.
func (p Policy) Configured() bool {
	return len(p.RequireDeny) > 0 || len(p.ForbidAllow) > 0
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
		var aux ruleMapping
		if err := node.Decode(&aux); err != nil {
			return err
		}
		rc.Off, rc.Severity = aux.Off, aux.Severity
		return nil
	default:
		return fmt.Errorf("rule config must be a string or a mapping, got %v", node.Kind)
	}
}

// ruleMapping is the nested form of a RuleConfig.
type ruleMapping struct {
	Off      bool   `yaml:"off"`
	Severity string `yaml:"severity"`
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
		data, err := scanroot.ReadFile(p)
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
	var doc yaml.Node
	if err := safeyaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ruleLines, err := validate(&doc)
	if err != nil {
		return nil, fmt.Errorf("%s:%w", path, err)
	}
	var c Config
	if err := safeyaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ruleLines = ruleLines
	codes, err := normalizeShellCheckCodes(c.ShellCheckExclude)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ShellCheckExclude = codes
	return &c, nil
}

// Keys accepted at the top level, under policy, and in the nested form of a
// rule override. They come from the yaml tags, so a new field is accepted
// without a second list to keep in sync.
var (
	topLevelKeys = yamlKeys(reflect.TypeOf(Config{}))
	policyKeys   = yamlKeys(reflect.TypeOf(Policy{}))
	ruleKeys     = yamlKeys(reflect.TypeOf(ruleMapping{}))
)

func yamlKeys(t reflect.Type) map[string]bool {
	keys := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ","); name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// configError is a problem at one line of the config file. Its message starts
// with the line so parse can prefix the path: ".cfgaudit.yml:1: unknown key".
type configError struct {
	line int
	msg  string
}

func (e *configError) Error() string { return fmt.Sprintf("%d: %s", e.line, e.msg) }

// validate rejects what the decoder would silently ignore: an unknown key at
// the top level, under policy or in a rule override, and an invalid severity
// (#1051). A typo in a file that sets the exit code of a security gate must
// not turn a check off without a word. It returns the line of each rule ID
// under rules. Anything the decoder itself rejects, such as a list where a
// mapping belongs, is left to it.
func validate(doc *yaml.Node) (map[string]int, error) {
	root := deref(doc)
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = deref(root.Content[0])
	}
	if root.Kind != yaml.MappingNode {
		return nil, nil
	}
	if err := checkKeys(root, topLevelKeys, ""); err != nil {
		return nil, err
	}
	var ruleLines map[string]int
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], deref(root.Content[i+1])
		switch key.Value {
		case "min-severity":
			if err := checkSeverity(val, "min-severity"); err != nil {
				return nil, err
			}
		case "policy":
			if val.Kind == yaml.MappingNode {
				if err := checkKeys(val, policyKeys, "policy."); err != nil {
					return nil, err
				}
			}
		case "rules":
			if val.Kind != yaml.MappingNode {
				continue
			}
			ruleLines = map[string]int{}
			for j := 0; j+1 < len(val.Content); j += 2 {
				id, rc := val.Content[j], deref(val.Content[j+1])
				if id.Value == "<<" {
					continue
				}
				ruleLines[id.Value] = id.Line
				if err := checkRule(id.Value, rc); err != nil {
					return nil, err
				}
			}
		}
	}
	return ruleLines, nil
}

// deref follows a YAML alias to the node it names.
func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

// checkKeys rejects a key of m that is not in known. A merge key (<<) is
// left alone.
func checkKeys(m *yaml.Node, known map[string]bool, prefix string) error {
	for i := 0; i < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Value != "<<" && !known[k.Value] {
			return &configError{k.Line, fmt.Sprintf("unknown key %q", prefix+k.Value)}
		}
	}
	return nil
}

// checkSeverity rejects a scalar that is not error, warn or info. An empty
// value means unset.
func checkSeverity(n *yaml.Node, key string) error {
	if n.Kind != yaml.ScalarNode || n.Value == "" {
		return nil
	}
	if _, ok := parseSeverity(n.Value); !ok {
		return &configError{n.Line, fmt.Sprintf("%s: %q is not a severity (error, warn or info)", key, n.Value)}
	}
	return nil
}

// checkRule validates one rule override: "off" or a severity in the flat
// form, and only off and severity in the nested form.
func checkRule(id string, rc *yaml.Node) error {
	key := "rules." + id
	switch rc.Kind {
	case yaml.ScalarNode:
		if rc.Value == "" || strings.EqualFold(rc.Value, "off") {
			return nil
		}
		if _, ok := parseSeverity(rc.Value); !ok {
			return &configError{rc.Line, fmt.Sprintf("%s: %q is neither off nor a severity (error, warn or info)", key, rc.Value)}
		}
	case yaml.MappingNode:
		if err := checkKeys(rc, ruleKeys, key+"."); err != nil {
			return err
		}
		for i := 0; i+1 < len(rc.Content); i += 2 {
			if rc.Content[i].Value == "severity" {
				if err := checkSeverity(deref(rc.Content[i+1]), key+".severity"); err != nil {
					return err
				}
			}
		}
	}
	return nil
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
	minRank := severityRank(c.MinSeverity) // 0 when unset → no filtering; parse rejects an invalid value
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

// MatchGlob reports whether path, slash-separated and relative to the scanned
// directory, matches pattern in the syntax of exclude-paths.
func MatchGlob(pattern, path string) bool { return matchGlob(pattern, path) }

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
