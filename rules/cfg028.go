// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg028 struct{}

var CFG028 = &cfg028{}

func init() { All = append(All, CFG028) }

func (r *cfg028) ID() string { return "CFG028" }

// trustFile matches the agent trust/config files a command must not rewrite.
//
// Matched case-insensitively: on macOS and Windows the filesystem is
// case-insensitive by default, so `> .Mcp.json` writes the genuine .mcp.json
// while a case-sensitive pattern sees nothing. That gap is not theoretical —
// CVE-2025-59944 (CWE-178) is exactly it, shipped in Cursor ≤1.6.23, where
// case-sensitive checks guarding */.cursor/mcp.json were bypassed for RCE.
//
// The flag is scoped with (?i:…) rather than a leading (?i): this constant is
// concatenated into the larger patterns below, and a bare flag would leak
// case-insensitivity into whatever follows it in the enclosing group.
//
// The trade is deliberate: on a case-sensitive filesystem `.MCP.json` really is
// a different, harmless file, so matching it is technically a false positive. A
// static analyzer cannot know the target filesystem, the evading spelling is
// contrived in legitimate config, and the miss it prevents is a full trust-file
// overwrite.
const trustName = `(?i:CLAUDE\.md|CLAUDE\.local\.md|settings\.local\.json|settings\.json|\.mcp\.json|\.vscode/mcp\.json)`

const trustDir = `(?i:\.claude/|\.cursor/|\.roo/|\.gemini/|\.codex/)`

const trustFile = `(?:` + trustName + `|` + trustDir + `)`

var trustFileRe = regexp.MustCompile(trustFile)

// redirectTargetPrefix is the part of one redirect or tee target before the
// trust-file name: ${VAR}, $(cmd) and characters that stay inside one shell
// word. It used to be \S*, which ran from "2>/dev/null)}" into the next path
// and read "bash \"${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel
// 2>/dev/null)}/.claude/hooks/guard.sh\"" as a write to .claude/ (#827).
const redirectTargetPrefix = `(?:\$\{[^}]*\}|\$\([^)]*\)|[^\s)};|&'"])*`

// trustWritePatterns detect a write whose target is a trust file:
//   - redirection (> / >>) or tee into one
//   - in-place stream edit (sed -i) of one
//   - cp / mv / install / ln / dd with one as the final (destination) argument
var trustWritePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:>>?|\btee\b(?:\s+-a)?\s+)\s*['"]?` + redirectTargetPrefix + trustFile),
	regexp.MustCompile(`\bsed\b[^|;&]*-i\b[^|;&]*` + trustFile),
	regexp.MustCompile(`\b(?:cp|mv|install|ln|dd)\b[^|;&]*(?:` + trustName + `|` + trustDir + `[^\s)'";|&]*)['"]?\s*(?:$|[|;&])`),
}

// Check flags command sites that write to an agent trust/config file. Rewriting
// instruction or MCP configuration from a hook or helper is a
// self-perpetuating prompt-injection and persistence vector: it can re-inject
// hidden instructions or re-enable dangerous settings on every session, and
// survive cleanup by restoring itself. Heuristic and static — it matches the
// common write idioms, not obfuscated writes (e.g. a path built from variables).
func (r *cfg028) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		target := trustWriteTarget(site.Command)
		if target == "" {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG028",
			Severity: finding.Error,
			File:     site.File,
			Message: site.Label + " writes to an agent trust/config file \"" + target +
				"\" — a self-perpetuating prompt-injection / persistence vector: it can re-inject hidden instructions or re-enable dangerous settings every session and restore itself after cleanup. A hook should never modify its agent's own configuration" + userScopeNote(t),
		})
	}
	return findings
}

// claudeLogRe matches a log file under .claude/, which the agent never reads
// as configuration: "echo '...' >>~/.claude/worktree-hook.log" (#874).
var claudeLogRe = regexp.MustCompile(`(?i)^\.claude/[\w.\-/]*\.log$`)

// trustWriteTarget returns the trust file a command writes to, or "" when it
// writes to none. A write whose target is a log file under .claude/ does not
// count.
func trustWriteTarget(cmd string) string {
	for _, re := range trustWritePatterns {
		for _, loc := range re.FindAllStringIndex(cmd, -1) {
			m := cmd[loc[0]:loc[1]]
			tl := trustFileRe.FindAllStringIndex(m, -1)
			start := loc[0] + tl[len(tl)-1][0]
			end := start
			for end < len(cmd) && !strings.ContainsRune(" \t\n;|&)'\"", rune(cmd[end])) {
				end++
			}
			if claudeLogRe.MatchString(cmd[start:end]) {
				continue
			}
			return cmd[start : loc[0]+tl[len(tl)-1][1]]
		}
	}
	return ""
}
