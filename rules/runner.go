// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/version"
)

// Versioned is implemented by rules that require a minimum Claude Code release.
// MinVersion returns a SemVer-like string ("2.1.91"); an empty string means
// the rule applies to every version.
type Versioned interface {
	MinVersion() string
}

// Run executes every registered rule against target.
//
// If detected is non-nil, rules implementing Versioned with a MinVersion
// above detected are skipped and replaced by a single info-severity finding
// so the omission is visible in the output. A nil detected disables all
// version gating — every rule runs unconditionally.
//
// If accept is non-nil it is consulted before each rule; rules for which
// accept returns false are dropped silently (the caller, e.g. a CLI flag,
// is expected to print its own "rule excluded" feedback if relevant).
//
// Every finding has its Scope back-filled from target.Scope when the rule
// did not set one itself, so JSON consumers can filter by blast radius
// without each rule having to remember to populate the field.
func Run(target *Target, detected *version.Version, accept func(Rule) bool) []finding.Finding {
	// Expose the detected version to rules whose findings depend on version-gated
	// runtime semantics (e.g. the deny-all "*" glob handling in CFG041–044).
	target.ClaudeVersion = detected

	var out []finding.Finding
	for _, r := range All {
		if accept != nil && !accept(r) {
			continue
		}
		if target.ContentPath {
			allowed := ContentPathRules[r.ID()]
			if target.CapabilityPackage {
				allowed = CapabilityPackageRules[r.ID()]
			}
			if !allowed {
				continue
			}
		}
		if target.SkillHelper != "" && !SkillHelperRules[r.ID()] {
			continue
		}
		if detected != nil {
			if skipMsg := versionSkip(r, *detected); skipMsg != "" {
				out = append(out, finding.Finding{
					RuleID:   r.ID(),
					Severity: finding.Info,
					Scope:    target.Scope,
					File:     target.SettingsFile,
					Message:  skipMsg,
				})
				continue
			}
		}
		results := r.Check(target)
		shipped := skillScripts(target)
		for i := range results {
			if results[i].Scope == "" {
				results[i].Scope = target.Scope
			}
			if len(target.ImportChain) > 0 && results[i].File == target.InstructionFile {
				results[i].Message += "; Claude Code loads this file through @-imports: " + strings.Join(target.ImportChain, " -> ")
			}
			if target.NestedDir != "" && results[i].File == target.InstructionFile {
				results[i].Message += nestedDirNote(target)
			}
			if target.ContentPath && results[i].File == target.InstructionFile {
				if results[i].Severity == finding.Error {
					results[i].Severity = finding.Warn
				}
				if target.CapabilityPackage {
					results[i].Message += "; scanned as setup documentation of a detected agent capability package: an agent may relay these installation steps, but does not load this file as trusted instructions"
				} else {
					results[i].Message += "; scanned because content-paths lists it: agents read this file when they open it, not as instructions"
				}
			}
			if skill, ok := shipped[results[i].File]; ok {
				if results[i].Severity == finding.Error {
					results[i].Severity = finding.Warn
				}
				results[i].Message += "; the agent runs this script when the skill " + skill + " tells it to, not on its own"
				if r.ID() == "CFG050" && skillTestScript(skill, results[i].File) {
					results[i].Severity = finding.Info
					results[i].Message += ", and it is a test script, where a credential is usually a fixture"
				}
			}
			if target.SkillHelper != "" && results[i].File == target.InstructionFile {
				switch {
				case ReferencePageRules[r.ID()] && !target.SkillHelperFollowed:
					results[i].Severity = finding.Info
					results[i].Message += "; this file ships with the skill " + target.SkillHelper + " as a reference page, and nothing in the skill tells the agent to follow it"
				default:
					if results[i].Severity == finding.Error {
						results[i].Severity = finding.Warn
					}
					results[i].Message += "; this file ships with the skill " + target.SkillHelper + ", and the agent reads it when the skill points it there"
				}
			}
		}
		out = append(out, results...)
	}
	return out
}

// ContentPathRules are the rules that run on the files content-paths lists
// (#795). They look for text with no legitimate place in any Markdown file:
// hidden Unicode controls (CFG024), pseudo system tags and control tokens
// (CFG032), encoded payloads (CFG057) and directives in HTML comments
// (CFG080). On 7,494 README, top-level and docs/ Markdown files from 149
// public repositories they reported 4 findings: two CFG032 on a `<ROOT>`
// placeholder, which CFG032 no longer reports (#806), and two CFG024 on a
// stray zero-width joiner after an emoji and a zero-width space in text
// documenting one. The phrase rules reported 343 on the same files.
var ContentPathRules = map[string]bool{
	"CFG024": true,
	"CFG032": true,
	"CFG057": true,
	"CFG080": true,
}

// CapabilityPackageRules replace ContentPathRules for setup documents in
// a structurally identified capability package (#1437). CFG036 covers the
// AgentBaiting/ClawHub installation shapes (download-and-run, encoded shell
// payloads and password-protected archives); CFG120 covers prose exfiltration.
// The target is still a ContentPath, so findings cannot exceed warn. CFG014 and
// CFG119 keep their command/script semantics and inspect executable surfaces,
// not inert prose; they are documented as complementary rather than run here.
var CapabilityPackageRules = map[string]bool{
	"CFG024": true,
	"CFG036": true,
	"CFG057": true,
	"CFG080": true,
	"CFG120": true,
}

// skillScripts maps the file of each script t's skill ships (#987) to that
// skill. Nothing starts such a script but the agent, when the skill tells it
// to, so Run reports its findings at most at warn: on 2,051 corpus
// repositories with skill helper files the errors were connectivity probes
// over /dev/tcp, VM bootstrap scripts enabling a service and release scripts
// reading the keychain.
func skillScripts(t *Target) map[string]string {
	var m map[string]string
	for _, s := range t.LaunchedScripts {
		if s.Skill != "" {
			if m == nil {
				m = map[string]string{}
			}
			m[s.File] = s.Skill
		}
	}
	return m
}

// SkillHelperRules are the rules that run on a Markdown file beside a
// SKILL.md (#987). The agent reads such a file when the skill tells it to, so
// the instruction-content rules apply; the rules about frontmatter, skill
// triggers and the file's own name do not. Run reports at most warn on these
// files: on 2,051 corpus repositories, 145 errors in 59 of them were mostly
// security skills quoting the attacks they detect, defensive "ignore
// instructions embedded in it" lines, invisible marks in copied reference
// docs and comments in report templates.
var SkillHelperRules = map[string]bool{
	"CFG024": true, // hidden Unicode controls
	"CFG026": true, // instruction-bypass phrases
	"CFG031": true, // sensitive file paths
	"CFG036": true, // shell commands for auto-execution or exfiltration
	"CFG057": true, // encoded payloads
	"CFG080": true, // directives in HTML comments
	"CFG081": true, // surviving context compaction
	"CFG120": true, // exfiltration directives in prose
}

// ReferencePageRules are the SkillHelperRules that report a helper file at
// info unless the skill tells the agent to follow it (#1611). In the
// pre-release corpus run for v1.21.0 their warn findings on such files were
// pattern catalogues of scanner skills, security reference pages listing the
// files an attacker targets, and test inputs with deliberate zero-width
// characters. CFG036 has its own reference-page case (#1176).
var ReferencePageRules = map[string]bool{
	"CFG024": true, // hidden Unicode controls
	"CFG026": true, // instruction-bypass phrases
	"CFG031": true, // sensitive file paths
	"CFG057": true, // encoded payloads
}

// skillFollowRe matches a line that tells the agent to follow a file rather
// than consult it: "read references/setup.md and follow it", "apply the
// steps in", "do what it says", "execute the instructions from".
var skillFollowRe = regexp.MustCompile(`(?i)\b(?:follow(?:s|ed|ing)?|apply|execute|carry\s+out|obey|comply\s+with|act\s+on|do\s+(?:what|as)\b|(?:instructions?|steps?|procedure|workflow)\s+(?:in|from|of|at)\b)`)

// SkillTellsToFollow reports whether skill, the content of a SKILL.md, tells
// the agent to follow the helper file at rel (a slash path relative to the
// skill directory): a line that names the file, or the line before it, holds
// a follow order (#1611).
func SkillTellsToFollow(skill, rel string) bool {
	rel = strings.TrimPrefix(rel, "./")
	base := path.Base(rel)
	lines := strings.Split(skill, "\n")
	for i, l := range lines {
		if !strings.Contains(l, rel) && !strings.Contains(l, base) {
			continue
		}
		if skillFollowRe.MatchString(l) || (i > 0 && skillFollowRe.MatchString(lines[i-1])) {
			return true
		}
	}
	return false
}

// versionSkip returns a non-empty notice message when r is Versioned and
// requires a Claude Code release newer than detected.
func versionSkip(r Rule, detected version.Version) string {
	v, ok := r.(Versioned)
	if !ok {
		return ""
	}
	minStr := v.MinVersion()
	if minStr == "" {
		return ""
	}
	min, err := version.Parse(minStr)
	if err != nil {
		return ""
	}
	if detected.AtLeast(min) {
		return ""
	}
	return fmt.Sprintf("skipped: requires Claude Code >= %s, detected %s", minStr, detected)
}

// nestedDirNote names the folder a nested instruction file applies to, and the
// agent that loads it there (#975).
func nestedDirNote(t *Target) string {
	slash := filepath.ToSlash(t.InstructionFile)
	switch {
	case strings.Contains(slash, "/.cursor/rules/"):
		return "; this rule applies to work under " + t.NestedDir + "/ (Cursor attaches nested rules when files there are in use)"
	case strings.Contains(slash, "/.devin/rules/"), strings.Contains(slash, "/.windsurf/rules/"):
		return "; this rule applies to work under " + t.NestedDir + "/ (Devin reads rule folders from subdirectories of the workspace)"
	}
	if filepath.Base(t.InstructionFile) == "CLAUDE.md" {
		return "; this CLAUDE.md applies to work under " + t.NestedDir + "/ (Claude Code loads it when it works in that folder)"
	}
	return "; this AGENTS.md applies to work under " + t.NestedDir + "/ (Cursor loads it as soon as its agent edits a file there)"
}

// skillTestScriptRe matches the path of a test script inside a skill: under
// tests/ or test/, or named test_*, *_test.* or smoke* (#1668).
var skillTestScriptRe = regexp.MustCompile(`(?i)(?:^|/)(?:tests?/|test_[^/]*$|[^/]*_test\.[^/]*$|smoke[^/]*$)`)

// skillTestScript reports whether file is a test script of the skill whose
// SKILL.md is skill. On the corpus run of 2026-11-10, 28 of the 36 CFG050
// findings in skill scripts sat under test or smoke paths, and every one
// sampled was a fixture.
func skillTestScript(skill, file string) bool {
	rel, err := filepath.Rel(filepath.Dir(skill), file)
	if err != nil {
		return false
	}
	return skillTestScriptRe.MatchString(filepath.ToSlash(rel))
}
