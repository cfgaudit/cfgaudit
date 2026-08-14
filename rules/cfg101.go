package rules

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg101 struct{}

var CFG101 = &cfg101{}

func init() { All = append(All, CFG101) }

func (r *cfg101) ID() string { return "CFG101" }

// bashRuleRe extracts the pattern out of a Bash(...) rule. PowerShell is matched
// so it can be recognised and skipped rather than falling through as unparsed.
var bashRuleRe = regexp.MustCompile(`(?i)^\s*(bash|powershell)\s*\(\s*(.*?)\s*\)\s*$`)

// bundledShortFlagRe matches a single token that bundles two or three short
// flags behind one dash: -rf, -fr, -it, -xzf. Those are the tokens the shell
// treats as a set, so writing them in one order in a rule does not cover the
// others.
//
// Deliberately narrow, and each exclusion is there because something real would
// otherwise be misread:
//
//   - A long flag (--force) cannot be permuted within itself.
//   - A lone short flag (-f) has nothing to permute.
//   - Four letters or more is where single-dash LONG options live in real tools:
//     `find -name`, `find -type`, `java -version`. Those are one option, not a
//     bundle, and permuting their letters produces nonsense.
//   - Capitals are how PowerShell writes every parameter (-Force, -Recurse), and
//     PowerShell does not bundle at all, which is why this rule never looks at
//     PowerShell rules.
var bundledShortFlagRe = regexp.MustCompile(`^-[a-z]{2,3}$`)

// permutations renders the alternative orderings of a bundled flag token, so the
// message can show the reader the exact string that walks past their rule. Capped
// so a long bundle does not produce an unreadable finding.
func permutations(flag string) []string {
	letters := flag[1:]
	if len(letters) < 2 {
		return nil
	}
	// Two spellings are enough to make the point: the reverse, and the rotation
	// that moves the first letter to the end. Both are orderings a person writes
	// without thinking about it.
	reversed := []byte(letters)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	candidates := []string{"-" + string(reversed), "-" + letters[1:] + letters[:1]}
	seen := map[string]bool{flag: true}
	var out []string
	for _, c := range candidates {
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Check flags a Bash deny or ask rule whose pattern bundles short flags, because Claude Code matches those patterns as a literal prefix and a
// bundled flag can be written in another order.
//
// Measured against Claude Code 2.1.231 (#480). With Bash(echo -n *) denied:
//
//	echo -n zzAAA   DENIED
//	echo -e -n zzBBB   ran
//	echo zzCCC -n      ran
//
// So a rule naming flags is walked past by reordering or inserting one, and
// upstream says the same in its own words, calling argument-constrained Bash
// patterns "fragile". Applied to the shape this rule reports, Bash(rm -rf *)
// never covered rm -fr x.
//
// # Scope, and why it is this narrow
//
// Only a bundled short-flag token (-rf, -xzf) is reported. Two shapes are
// deliberately left alone even though they are also position-sensitive:
//
//   - A long flag (--force) cannot be permuted within itself. Covering it would
//     mean reporting every argument-constrained rule ever written, including the
//     four spellings `cfgaudit init` itself emits for force-push, which exist
//     precisely because no broader form is available there.
//   - A subcommand (npm run test) is not a flag and does not reorder freely.
//
// The remedy is always available for the reported shape: deny the command by
// name. That is what #482 did to this project's own baseline, replacing
// Bash(rm -rf *) with Bash(rm *).
//
// Only deny and ask rules are examined. An allow rule that fails to match is a
// prompt rather than a bypass, which is the safe direction.
func (r *cfg101) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	p := t.Settings.Permissions
	// A file that also denies the bare command has already closed the gap: the
	// broad rule catches every spelling, and the flag-constrained one beside it is
	// redundant rather than a hole. Reporting it would be pedantry about a file
	// that got the important part right.
	covered := barelyDeniedCommands(p.Deny)

	var findings []finding.Finding
	for _, list := range []struct {
		kind    string
		entries []string
	}{{"deny", p.Deny}, {"ask", p.Ask}} {
		var entries, flags, commands []string
		for _, entry := range list.entries {
			// The tool is discarded: bashRulePattern rejects PowerShell, so every
			// entry that reaches here is a Bash rule.
			_, pattern, ok := bashRulePattern(entry)
			if !ok {
				continue
			}
			entryFlags := bundledFlagsIn(pattern)
			if len(entryFlags) == 0 {
				continue
			}
			command := commandWordOf(pattern)
			if command != "" && covered[command] {
				continue
			}
			entries = append(entries, strings.TrimSpace(entry))
			flags = appendNew(flags, entryFlags...)
			if command != "" {
				commands = appendNew(commands, command)
			}
		}
		if len(entries) == 0 {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG101",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.SettingsFile,
			Message:  cfg101Message(list.kind, entries, flags, commands) + userScopeNote(t),
		})
	}
	return findings
}

// cfg101Message renders one finding for every offending entry in one list of one
// file, rather than one finding per entry (#517). The volume measured before that
// change was 68 findings over 38 files, all of them genuine: collapsing loses no
// distinct problem, because the reader has to fix them in the same file anyway,
// and the remedy is the same sentence repeated. The single-entry wording is kept
// exactly as it was, since that is what almost every file produces.
func cfg101Message(kind string, entries, flags, commands []string) string {
	const tool = "Bash"
	tail := " Upstream calls argument-constrained patterns fragile; "
	if len(entries) == 1 {
		suggestion := ""
		if len(commands) == 1 {
			suggestion = " Deny the command by name instead, as \"" + tool + "(" + commands[0] + " *)\"."
		}
		return "permissions." + kind + " entry \"" + entries[0] + "\" constrains bundled short flags " + quoteList(flags) +
			", and " + tool + " patterns are matched as a literal prefix. Writing the same flags in another order walks past the rule" +
			permutationHint(flags) + "." + suggestion + tail + "this one is evaded without any thought at all"
	}
	suggestion := ""
	if len(commands) > 0 {
		var as []string
		for _, c := range capList(commands, 3) {
			as = append(as, tool+"("+c+" *)")
		}
		suggestion = " Deny each command by name instead, as " + quoteList(as) + "."
	}
	return "permissions." + kind + " has " + strconv.Itoa(len(entries)) + " entries that constrain bundled short flags: " +
		quoteList(capList(entries, 4)) + andMore(len(entries), 4) + ". " + tool +
		" patterns are matched as a literal prefix, so writing the same flags in another order walks past them" +
		permutationHint(flags) + "." + suggestion + tail + "these are evaded without any thought at all"
}

// capList returns at most n elements, so a file with a long deny list does not
// produce an unreadable finding.
func capList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

// andMore names what capList dropped, so the count in the message and the list in
// it never disagree silently.
func andMore(total, shown int) string {
	if total <= shown {
		return ""
	}
	return " and " + strconv.Itoa(total-shown) + " more"
}

// appendNew appends the values not already present, preserving first-seen order.
func appendNew(dst []string, values ...string) []string {
	for _, v := range values {
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

// permutationHint renders a concrete evading spelling for the first reported
// flag, so the finding shows rather than asserts.
func permutationHint(flags []string) string {
	if len(flags) == 0 {
		return ""
	}
	alt := permutations(flags[0])
	if len(alt) == 0 {
		return ""
	}
	return " (" + quoteList(alt) + " reaches the same command)"
}

// bashRulePattern splits a Bash(...) or PowerShell(...) rule into its tool name
// and its pattern. PowerShell rules use the same shape as Bash rules.
func bashRulePattern(entry string) (tool, pattern string, ok bool) {
	m := bashRuleRe.FindStringSubmatch(entry)
	if m == nil {
		return "", "", false
	}
	if strings.EqualFold(m[1], "powershell") {
		// PowerShell has no flag bundling: every parameter is a single -Word.
		// There is nothing to permute, so the evasion this rule reports does not
		// exist there.
		return "", "", false
	}
	tool = "Bash"
	pattern = strings.TrimSpace(m[2])
	if pattern == "" || pattern == "*" {
		return "", "", false // a catch-all constrains no arguments
	}
	return tool, pattern, true
}

// bundledFlagsIn returns the bundled short-flag tokens of a rule pattern, sorted
// and deduplicated. The trailing wildcard is stripped from a token so
// "-rf*" is read as the flag it names.
func bundledFlagsIn(pattern string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.Fields(pattern) {
		tok = strings.TrimSuffix(strings.TrimSuffix(tok, "*"), ":")
		if !bundledShortFlagRe.MatchString(tok) || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// barelyDeniedCommands returns the commands a deny list already blocks by name
// alone, as in Bash(rm *) or Bash(rm:*). Those denials hold whatever flags
// follow, so a flag-constrained entry for the same command leaves no gap.
func barelyDeniedCommands(deny []string) map[string]bool {
	out := map[string]bool{}
	for _, entry := range deny {
		_, pattern, ok := bashRulePattern(entry)
		if !ok {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(pattern), ":*"))
		if len(fields) == 0 {
			continue
		}
		cmd := strings.TrimSuffix(fields[0], ":")
		if cmd == "" || strings.ContainsAny(cmd, "*") || strings.HasPrefix(cmd, "-") {
			continue
		}
		// Only a bare command, optionally followed by a wildcard, counts.
		rest := fields[1:]
		if len(rest) == 0 || (len(rest) == 1 && (rest[0] == "*" || rest[0] == "**")) {
			out[cmd] = true
		}
	}
	return out
}

// commandWordOf returns the leading command word of a pattern, so the message can
// name the broader rule that would hold. Empty when the pattern starts with a
// wildcard or a flag, where no such rule can be derived.
func commandWordOf(pattern string) string {
	fields := strings.Fields(pattern)
	if len(fields) == 0 {
		return ""
	}
	first := fields[0]
	if strings.HasPrefix(first, "-") || strings.ContainsAny(first, "*") {
		return ""
	}
	return first
}
