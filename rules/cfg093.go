package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg093 struct{}

var CFG093 = &cfg093{}

func init() { All = append(All, CFG093) }

func (r *cfg093) ID() string { return "CFG093" }

// shellPrefixCommands are base commands whose whole purpose is to run something
// else. Cursor's terminalAllowlist matches on the *prefix* of a command, so
// allowlisting one of these auto-approves anything passed to it — `bash` covers
// `bash -c '<anything>'`, `uv` covers `uv run <anything>`. Unlike a chained
// command (`git status && rm -rf /`), which depends on undocumented splitting
// behaviour, this needs no assumption beyond the documented prefix match.
var shellPrefixCommands = map[string]string{
	"sh": "a shell", "bash": "a shell", "zsh": "a shell", "ksh": "a shell",
	"dash": "a shell", "fish": "a shell", "csh": "a shell", "tcsh": "a shell",
	"pwsh": "a shell", "powershell": "a shell", "cmd": "a shell",
	"python": "an interpreter", "python2": "an interpreter", "python3": "an interpreter",
	"perl": "an interpreter", "ruby": "an interpreter", "php": "an interpreter",
	"node": "an interpreter", "deno": "an interpreter", "bun": "an interpreter",
	"osascript": "an interpreter",
	"eval":      "a command evaluator",
	"env":       "a command launcher", "xargs": "a command launcher",
	"nohup": "a command launcher", "setsid": "a command launcher",
	"npx": "a package runner", "pnpx": "a package runner", "bunx": "a package runner",
	"uvx": "a package runner", "pipx": "a package runner", "uv": "a package runner",
	"docker": "a container runtime", "podman": "a container runtime",
	"ssh": "a remote executor", "sudo": "a privilege escalator", "doas": "a privilege escalator",
}

// Check flags a committed Cursor .cursor/permissions.json whose allowlists remove
// the approval prompt for terminal commands or MCP tool calls.
//
// Cursor concatenates the per-repo file with a teammate's own
// ~/.cursor/permissions.json rather than letting either override the other, and
// only a team-admin dashboard policy outranks the file. So an entry committed
// here cannot be taken back by the person who clones the repo — which is exactly
// what Cursor's docs ask for ("Commit the per-repo file so teammates inherit the
// same rules"). That is the CFG004 threat model (a repo deciding that a prompt is
// unnecessary) reached through Cursor's file.
//
// Severity:
//   - **error** for an entry that is unbounded: an mcpAllowlist wildcard
//     ("*:*" = all tools from all servers, or "<server>:*" = a whole server), or
//     a terminalAllowlist entry whose base command exists to run other commands
//     (see shellPrefixCommands) — matching is documented as a prefix match, so
//     "bash" auto-approves "bash -c '<anything>'".
//   - **warn** for a bounded committed entry. The specific commands or tools
//     still run with no confirmation on every teammate, which is worth surfacing,
//     but the blast radius is what the entry names.
//
// The message says "when Run Mode is enabled" because Cursor's docs state
// permissions.json only takes effect then (Auto-review, Allowlist or Run
// Everything). Nothing here claims anything about how Cursor treats chained
// commands, pipes or subshells: that is undocumented, and asserting it would be a
// guess of the kind that has produced false findings before.
func (r *cfg093) Check(t *Target) []finding.Finding {
	if t == nil || t.CursorPermissions == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	p := t.CursorPermissions
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG093",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CursorPermissionsFile,
			Message:  msg,
		})
	}

	var mcpWild, mcpBounded []string
	for _, entry := range p.MCPAllowlist {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if isWildcardMCPAllow(e) {
			mcpWild = append(mcpWild, e)
			continue
		}
		mcpBounded = append(mcpBounded, e)
	}
	sort.Strings(mcpWild)
	sort.Strings(mcpBounded)
	if len(mcpWild) > 0 {
		what := "every MCP tool on every configured server"
		if !containsAllServersWildcard(mcpWild) {
			what = "every tool on the named MCP server"
		}
		add(finding.Error, "committed .cursor/permissions.json mcpAllowlist auto-approves "+what+
			" ("+quoteList(mcpWild)+") — when Run Mode is enabled, MCP tool calls run on every teammate who opened this repo with no confirmation, and Cursor concatenates this file with a user's own rather than letting them override it. Name the specific server:tool pairs the project needs")
	}
	if len(mcpBounded) > 0 {
		add(finding.Warn, "committed .cursor/permissions.json allowlists MCP tools "+quoteList(mcpBounded)+
			" — these run without a confirmation prompt on every teammate when Run Mode is enabled; a teammate's own permissions.json is concatenated with this one, so they cannot remove an entry. Keep the list to tools the project genuinely needs unattended")
	}

	var termShell, termBounded []string
	kinds := map[string]string{}
	for _, entry := range p.TerminalAllowlist {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if kind, ok := shellPrefixCommands[parser.TerminalBase(e)]; ok {
			termShell = append(termShell, e)
			kinds[e] = kind
			continue
		}
		termBounded = append(termBounded, e)
	}
	sort.Strings(termShell)
	sort.Strings(termBounded)
	if len(termShell) > 0 {
		add(finding.Error, "committed .cursor/permissions.json terminalAllowlist allowlists "+describeKinds(termShell, kinds)+
			" ("+quoteList(termShell)+") — terminalAllowlist matches the command prefix, so this auto-approves anything run through it (e.g. \"bash\" covers \"bash -c '<any command>'\"). When Run Mode is enabled that is unattended arbitrary command execution on every teammate. Allowlist the specific commands instead")
	}
	if len(termBounded) > 0 {
		add(finding.Warn, "committed .cursor/permissions.json allowlists terminal commands "+quoteList(termBounded)+
			" — these run without a confirmation prompt on every teammate when Run Mode is enabled, and entries match by prefix, so an entry covers every invocation that starts with it. Narrow each entry with the \"base:args-glob\" form where possible")
	}
	return findings
}

// isWildcardMCPAllow reports whether an mcpAllowlist entry grants a whole server
// or everything. Cursor documents "*:*" as all tools from all servers; "*" and a
// "<server>:*" tool wildcard are the same unbounded grant one scope down.
func isWildcardMCPAllow(entry string) bool {
	e := strings.TrimSpace(entry)
	if e == "*" || e == "*:*" {
		return true
	}
	_, tool, ok := strings.Cut(e, ":")
	return ok && strings.TrimSpace(tool) == "*"
}

// containsAllServersWildcard reports whether any entry grants across all servers,
// as opposed to every tool on one named server.
func containsAllServersWildcard(entries []string) bool {
	for _, e := range entries {
		if t := strings.TrimSpace(e); t == "*" || t == "*:*" {
			return true
		}
	}
	return false
}

// describeKinds renders the distinct kinds of the flagged entries ("a shell",
// "a package runner"), so the message names what the entry actually is. Kept in
// entry order rather than sorted, so the kinds line up with the quoted list.
func describeKinds(entries []string, kinds map[string]string) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if k := kinds[e]; k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return strings.Join(out, " / ")
}

// quoteList renders entries as a quoted, comma-separated list for a message.
func quoteList(entries []string) string {
	quoted := make([]string, 0, len(entries))
	for _, e := range entries {
		quoted = append(quoted, "\""+e+"\"")
	}
	return strings.Join(quoted, ", ")
}
