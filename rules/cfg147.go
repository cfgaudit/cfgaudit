// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg147 struct{}

// CFG147 reports an auto-run command (a hook, a folder-open task or an MCP
// launch) whose program name is disguised by shell-level obfuscation, so the
// content rules that key on the program word (CFG014's `curl ... | sh`, the
// command-content family) do not recognise it (#1823). A committed command has
// no legitimate reason to hide the program it runs, so the obfuscation itself
// is the finding, as it is for an obfuscated script in CFG119: the rule does
// not resolve what the command would run.
var CFG147 = &cfg147{}

func init() { All = append(All, CFG147) }

func (r *cfg147) ID() string { return "CFG147" }

var (
	// backslashObfRe matches two or more back-to-back backslash-escaped letters
	// (`\c\u\r\l`, `\s\h`). A letter needs no escaping, so a run of them only
	// splits a name. A Windows path (`C:\Users\bin`) escapes path separators,
	// not consecutive letters, and is excluded by the `:` guard.
	backslashObfRe = regexp.MustCompile(`(?:\\[A-Za-z]){2,}`)
	// varConcatRe matches two or more variable expansions with nothing between
	// (`$a$b`, `${a}${b}`), the shape that assembles a program name from
	// fragments.
	varConcatRe = regexp.MustCompile(`(?:\$\{?[A-Za-z_]\w*\}?){2,}`)
	// obfVarNameRe pulls the variable names out of such a word.
	obfVarNameRe = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)\}?`)
	// emptyQuoteSplitRe matches an empty quote pair ('' or "") next to a letter
	// or digit, the shape that splits a program name (`c''url`, `cu""rl`). A
	// quoted variable or path (`"$CLAUDE_PROJECT_DIR"/bin`) has no empty pair,
	// so the common hook convention of quoting an env var is not a split.
	emptyQuoteSplitRe = regexp.MustCompile("[A-Za-z0-9]''|''[A-Za-z0-9]|[A-Za-z0-9]\"\"|\"\"[A-Za-z0-9]")
	// obfAssignRe matches a leading NAME=value assignment word.
	obfAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// Check reports each auto-run command whose program word is obfuscated, at
// error for a zero-click site (a SessionStart hook, a folder-open task or an
// MCP launch) and at warn elsewhere.
func (r *cfg147) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, lc := range LaunchCommands(t) {
		hits := obfuscatedCommandWords(lc.Command)
		if len(hits) == 0 {
			continue
		}
		sev := finding.Warn
		if obfZeroClick(lc.Label) {
			sev = finding.Error
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG147",
			Severity: sev,
			File:     lc.File,
			Message: lc.Label + " runs a command whose program name is disguised by " + hits[0].form +
				". A committed hook, task or MCP launch has no reason to hide the program it runs, and the disguise keeps the content rules from seeing it. Write the command out in plain form, and if nobody in the project added it, treat the repository as compromised" + userScopeNote(t),
		})
	}
	return findings
}

// obfZeroClick reports a launcher that runs as soon as the repository is opened
// or a session starts (a SessionStart hook, a folder-open task) or when the
// agent connects to a committed MCP server, which happens without the user
// asking for the command.
func obfZeroClick(label string) bool {
	return ZeroClickLaunch(label) || strings.HasPrefix(label, "mcpServers.")
}

// commandWordHit is one obfuscated program word and how it is disguised.
type commandWordHit struct {
	word string
	form string
}

// obfuscatedCommandWords returns the program words of command that are
// disguised by shell-level obfuscation, one per statement or pipeline segment.
func obfuscatedCommandWords(command string) []commandWordHit {
	assigns := obfAssignments(command)
	var hits []commandWordHit
	for _, st := range statementSplit(command) {
		for _, seg := range pipeSplit(st) {
			w := rawCommandWord(seg)
			if w == "" {
				continue
			}
			if form := obfuscationForm(w, assigns); form != "" {
				hits = append(hits, commandWordHit{word: w, form: form})
			}
		}
	}
	return hits
}

// obfAssignments collects the NAME=value assignments in command, so a program
// word built from variables assigned here (`a=cu;b=rl;$a$b`) is told apart from
// one built from environment variables.
func obfAssignments(command string) map[string]bool {
	out := map[string]bool{}
	for _, st := range statementSplit(command) {
		st = strings.TrimSpace(st)
		if m := obfAssignRe.FindString(st); m != "" && !strings.ContainsAny(st, " \t") {
			out[strings.TrimSuffix(m, "=")] = true
		}
	}
	return out
}

// rawCommandWord returns the raw text of the program word of a pipeline
// segment, past leading assignments and command wrappers (sudo, env, ...),
// with its quotes and backslashes kept so the obfuscation is still visible.
func rawCommandWord(seg string) string {
	words := rawWords(seg)
	for len(words) > 0 {
		w := words[0]
		norm := ""
		if sw := shellWords(w); len(sw) > 0 {
			norm = executableName(sw[0])
		}
		switch {
		case obfAssignRe.MatchString(w):
			words = words[1:]
		case commandRunners[norm]:
			words = words[1:]
			for len(words) > 0 && strings.HasPrefix(words[0], "-") {
				words = words[1:]
			}
		default:
			return w
		}
	}
	return ""
}

// rawWords splits s into words on unquoted whitespace, keeping each word's
// original text (quotes, backslashes and `$'...'` included). Unlike shellWords
// it does not strip quotes, so quote-splitting stays visible.
func rawWords(s string) []string {
	var words []string
	var b strings.Builder
	var quote byte
	flush := func() {
		if b.Len() > 0 {
			words = append(words, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch {
		case c == '\\' && i+1 < len(s):
			b.WriteByte(c)
			b.WriteByte(s[i+1])
			i++
		case c == '\'' || c == '"':
			b.WriteByte(c)
			quote = c
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return words
}

// obfuscationForm names how a program word is disguised, or "" when it is
// plain. The forms are the strong signals from #1823: a split by an embedded
// empty quote pair, by backslash escapes, by ANSI-C quoting, or by variable
// concatenation. A glob in the program word is deliberately left out: on the
// corpus every candidate was a `case` pattern, a subshell fragment or a quoted
// argument that the shell segmenter cannot tell apart from a genuine command
// word, not a disguised program. `${IFS}` as a separator is left to CFG009.
func obfuscationForm(w string, assigns map[string]bool) string {
	if strings.Contains(w, "$'") {
		// ANSI-C quoting: `$'\x63\x75\x72\x6c'`, or `$'curl'`, both of which
		// spell a program name the content rules do not see as one word.
		return "ANSI-C quoting (`" + w + "`)"
	}
	if emptyQuoteSplitRe.MatchString(w) {
		return "quote splitting (`" + w + "`)"
	}
	if !strings.Contains(w, ":") && backslashObfRe.MatchString(w) {
		return "backslash-escaped letters (`" + w + "`)"
	}
	if varConcatRe.MatchString(w) && referencesAssigned(w, assigns) {
		return "variable concatenation (`" + w + "`)"
	}
	return ""
}

// referencesAssigned reports whether the concatenated word names a variable
// assigned in the same command.
func referencesAssigned(w string, assigns map[string]bool) bool {
	for _, m := range obfVarNameRe.FindAllStringSubmatch(w, -1) {
		if assigns[m[1]] {
			return true
		}
	}
	return false
}
