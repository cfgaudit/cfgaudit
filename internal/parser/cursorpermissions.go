package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CursorPermissions is a partial representation of a Cursor
// `.cursor/permissions.json` (Cursor 2.5+). Only the fields cfgaudit inspects
// are decoded; unknown keys are ignored.
//
// Cursor reads two of these files — `~/.cursor/permissions.json` (per-user) and
// `<workspace>/.cursor/permissions.json` (per-repo) — and **concatenates the
// arrays inside every field** rather than letting one override the other. Only a
// team-admin dashboard policy outranks the file. That is what makes the per-repo
// file a supply-chain surface: an entry committed to a repo cannot be removed by
// a teammate's own file, and Cursor's docs tell you to commit it ("Commit the
// per-repo file so teammates inherit the same rules").
//
// The whole file only takes effect when Run Mode is enabled in Cursor Settings
// (Auto-review, Allowlist, or Run Everything), and `autoRun` is consulted only in
// Auto-review mode. Rules built on this must say so rather than claim the entries
// always apply.
type CursorPermissions struct {
	// MCPAllowlist names MCP tools that run without approval, as
	// "<server>:<tool>" patterns. "*:*" is documented as all tools from all
	// servers.
	MCPAllowlist []string `json:"mcpAllowlist,omitempty"`

	// TerminalAllowlist names terminal commands that run without approval.
	// Entries are prefix matches on the command: "git" matches any command
	// starting with git. A ":" separates the base command from an args glob
	// ("npm:install*").
	TerminalAllowlist []string `json:"terminalAllowlist,omitempty"`

	// AutoRun steers the Auto-review classifier with natural-language
	// instructions instead of literal matches.
	AutoRun *CursorAutoRun `json:"autoRun,omitempty"`
}

// CursorAutoRun holds the natural-language instructions that push Cursor's
// auto-approval classifier toward approving or rejecting a tool call.
type CursorAutoRun struct {
	AllowInstructions []string `json:"allow_instructions,omitempty"`
	BlockInstructions []string `json:"block_instructions,omitempty"`
}

// Empty reports whether the file declared nothing cfgaudit inspects.
func (p *CursorPermissions) Empty() bool {
	if p == nil {
		return true
	}
	if len(p.MCPAllowlist) > 0 || len(p.TerminalAllowlist) > 0 {
		return false
	}
	return p.AutoRun == nil || (len(p.AutoRun.AllowInstructions) == 0 && len(p.AutoRun.BlockInstructions) == 0)
}

// TerminalBase returns the base command of a terminalAllowlist entry: the part
// before the ":" args-glob separator, and before the first space in the
// "command with arguments" form. Comparison-friendly (trimmed, lower-cased).
func TerminalBase(entry string) string {
	base := strings.TrimSpace(entry)
	if i := strings.IndexByte(base, ':'); i >= 0 {
		base = base[:i]
	}
	if i := strings.IndexAny(base, " \t"); i >= 0 {
		base = base[:i]
	}
	return strings.ToLower(strings.TrimSpace(base))
}

// ParseCursorPermissions reads and decodes a .cursor/permissions.json. Cursor
// documents the file with JSONC examples, so comments and trailing commas are
// stripped before decoding, as for .vscode/tasks.json.
func ParseCursorPermissions(path string) (*CursorPermissions, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var p CursorPermissions
	if err := json.Unmarshal(stripJSONC(data), &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &p, nil
}
