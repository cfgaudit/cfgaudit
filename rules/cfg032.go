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

// htmlSafeTags are standard HTML/SVG tags (uppercased) that must not trip the
// generic all-caps catch-all.
var htmlSafeTags = map[string]bool{
	"HTML": true, "HEAD": true, "BODY": true, "TABLE": true, "THEAD": true,
	"TBODY": true, "TFOOT": true, "DIV": true, "SVG": true, "PRE": true,
	"NAV": true, "IMG": true, "COL": true, "DEL": true, "INS": true, "WBR": true,
}

// placeholderWords are documentation-placeholder tokens; an all-caps tag whose
// underscore-separated segments include one of these (e.g. <YOUR_API_KEY>,
// <PROJECT_NAME>, <VERSION>) is a template placeholder, not an injection.
var placeholderWords = map[string]bool{
	"YOUR": true, "NAME": true, "KEY": true, "TOKEN": true, "SECRET": true,
	"VALUE": true, "PATH": true, "URL": true, "URI": true, "VERSION": true,
	"DATE": true, "TIME": true, "USER": true, "USERNAME": true, "EMAIL": true,
	"PORT": true, "HOST": true, "ENV": true, "VAR": true, "ARG": true,
	"DIR": true, "FILE": true, "FOLDER": true, "PROJECT": true, "BRANCH": true,
	"REPO": true, "ORG": true, "REGION": true, "BUCKET": true, "ACCOUNT": true,
	"NUMBER": true, "COUNT": true, "INDEX": true, "PLACEHOLDER": true,
	"TODO": true, "FIXME": true, "ID": true,
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
	if t == nil || t.ClaudeMDContent == "" {
		return nil
	}
	c := t.ClaudeMDContent
	var findings []finding.Finding
	add := func(off int, sev finding.Severity, msg string) {
		line, col := posOf(c, off)
		findings = append(findings, finding.Finding{
			RuleID:   "CFG032",
			Severity: sev,
			File:     t.ClaudeMDFile,
			Line:     line,
			Col:      col,
			Message:  "CLAUDE.md line " + strconv.Itoa(line) + " " + msg,
		})
	}

	// Part A — all-caps tags
	for _, m := range allCapsTagRe.FindAllStringSubmatchIndex(c, -1) {
		tag := c[m[2]:m[3]]
		switch {
		case authorityTags[tag]:
			add(m[0], finding.Error, "contains pseudo-system authority tag \"<"+tag+">\" (Part A) — invented markup claiming system-level authority; remove it")
		case htmlSafeTags[tag] || hasPlaceholderSegment(tag):
			// standard HTML or a documentation placeholder — ignore
		default:
			add(m[0], finding.Warn, "contains suspicious all-caps pseudo-tag \"<"+tag+">\" (Part A) — not a standard tag; a signal of adversarial markup")
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
		add(loc[0], finding.Warn, "contains a foreign-LLM control token \""+c[loc[0]:loc[1]]+"\" (Part C) — harmless to Claude's tokenizer, but a strong sign the file was adapted from a multi-model attack payload")
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Col < findings[j].Col
	})
	return findings
}

func hasPlaceholderSegment(tag string) bool {
	for _, seg := range strings.Split(tag, "_") {
		if placeholderWords[seg] {
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
