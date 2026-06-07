package rules

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg032 struct{}

var CFG032 = &cfg032{}

func init() { All = append(All, CFG032) }

func (r *cfg032) ID() string { return "CFG032" }

// authorityTags are invented all-caps tags that claim system-level authority.
var authorityTags = map[string]bool{
	"SYSTEM": true, "SYSTEM_REQUIREMENT": true, "SYSTEM_OVERRIDE": true,
	"HIDDEN": true, "GLOBAL": true, "GLOBAL_OVERRIDE": true, "ADMIN": true,
	"OVERRIDE": true, "ROOT": true, "TRUST": true, "PRIVILEGED": true,
	"SUDO": true, "JAILBREAK": true, "DEVELOPER_MODE": true,
}

// authoritySuspiciousWords are segments that make a novel all-caps tag read as an
// authority/permission/imperative claim rather than a benign field placeholder.
// The generic all-caps catch-all only warns when a tag contains one of these;
// everything else (template placeholders like <FILL>/<TASK>/<ISO>/<UUID>, field
// names, HTML tags) is ignored, which keeps false positives low on real docs.
var authoritySuspiciousWords = map[string]bool{
	"MANDATORY": true, "REQUIRED": true, "FORCE": true, "FORCED": true,
	"OVERRIDE": true, "BYPASS": true, "ENFORCE": true, "ELEVATED": true,
	"PRIVILEGED": true, "SUPERUSER": true, "UNRESTRICTED": true, "UNLIMITED": true,
	"NOAUTH": true, "NOPROMPT": true, "FULLACCESS": true,
}

var (
	allCapsTagRe = regexp.MustCompile(`<([A-Z][A-Z_]{2,})>`)
	turnBoundary = regexp.MustCompile(`\n\n(?:Human|Assistant):\s`)
	roleTagRe    = regexp.MustCompile(`(?is)<(human|assistant)>.*?</(?:human|assistant)>`)
	sysInstrRe   = regexp.MustCompile(`(?m)^System Instruction:\s`)
	foreignToken = regexp.MustCompile(`<\|im_start\|>|<\|im_end\|>|<s>\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<\|system\|>|<\|user\|>|<\|assistant\|>`)
)

// Check scans CLAUDE.md for pseudo-system markup and role-injection tokens.
// Part A: authority tags (error) + a generic all-caps catch-all (warn, with
// HTML/placeholder exclusions). Part B: Claude turn-boundary / role injection
// (error). Part C: foreign-LLM tokenizer control sequences (warn — harmless to
// Claude's tokenizer but a strong adversarial-authorship signal). Code-fenced
// matches are still reported.
func (r *cfg032) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		c := src.Content
		var srcFindings []finding.Finding
		add := func(off int, sev finding.Severity, msg string) {
			line, col := posOf(c, off)
			srcFindings = append(srcFindings, finding.Finding{
				RuleID:   "CFG032",
				Severity: sev,
				File:     src.File,
				Line:     line,
				Col:      col,
				Message:  src.Name + " line " + strconv.Itoa(line) + " " + msg,
			})
		}

		// Part A — all-caps tags
		for _, m := range allCapsTagRe.FindAllStringSubmatchIndex(c, -1) {
			tag := c[m[2]:m[3]]
			switch {
			case authorityTags[tag]:
				add(m[0], finding.Error, "contains pseudo-system authority tag \"<"+tag+">\" (Part A) — invented markup claiming system-level authority; remove it")
			case hasAuthoritySegment(tag):
				add(m[0], finding.Warn, "contains suspicious all-caps pseudo-tag \"<"+tag+">\" (Part A) — reads as an authority/permission claim, not a standard tag")
			default:
				// benign all-caps tag — template placeholder, field name, or HTML — ignore
			}
		}

		// Part B — Claude turn-boundary / role injection (error)
		for _, loc := range turnBoundary.FindAllStringIndex(c, -1) {
			add(loc[0]+2, finding.Error, "injects a Claude turn boundary (Human:/Assistant:) (Part B) — an attempt to close the turn and open an attacker-controlled one; remove it")
		}
		for _, loc := range roleTagRe.FindAllStringIndex(c, -1) {
			add(loc[0], finding.Error, "contains a <human>/<assistant> role tag (Part B) — role-injection markup; remove it")
		}
		for _, loc := range sysInstrRe.FindAllStringIndex(c, -1) {
			add(loc[0], finding.Error, "contains a \"System Instruction:\" directive (Part B) — pseudo-system framing; remove it")
		}

		// Part C — foreign-LLM tokenizer control sequences (warn)
		for _, loc := range foreignToken.FindAllStringIndex(c, -1) {
			add(loc[0], finding.Warn, "contains a foreign-LLM control token \""+c[loc[0]:loc[1]]+"\" (Part C) — harmless to the agent's tokenizer, but a strong sign the file was adapted from a multi-model attack payload")
		}

		sort.SliceStable(srcFindings, func(i, j int) bool {
			if srcFindings[i].Line != srcFindings[j].Line {
				return srcFindings[i].Line < srcFindings[j].Line
			}
			return srcFindings[i].Col < srcFindings[j].Col
		})
		findings = append(findings, srcFindings...)
	}
	return findings
}

func hasAuthoritySegment(tag string) bool {
	for _, seg := range strings.Split(tag, "_") {
		if authoritySuspiciousWords[seg] {
			return true
		}
	}
	return false
}

// posOf returns the 1-based line and column of a byte offset in content.
func posOf(content string, off int) (int, int) {
	line, col := 1, 1
	for i := 0; i < off && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}
