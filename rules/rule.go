package rules

import (
	"path/filepath"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// instructionName returns the base name of the loaded instruction file
// (CLAUDE.md, .cursorrules, AGENTS.md, …) for use in finding messages, or a
// generic fallback when unset.
func (t *Target) instructionName() string {
	if t != nil && t.InstructionFile != "" {
		return filepath.Base(t.InstructionFile)
	}
	return "instruction file"
}

// Target is the parsed representation of a project's AI-agent configuration.
// Fields are nil/empty when the corresponding file is absent.
type Target struct {
	SettingsFile string
	Settings     *parser.Settings
	Scope        finding.Scope

	// ProjectDir is the directory that contains the project's .claude/ folder.
	// Set for ScopeProject and ScopeProjectLocal targets; empty for user-global
	// scans. Rules that need to look at sibling files (.gitignore, CLAUDE.md, …)
	// resolve them from here.
	ProjectDir string

	// ProjectMCP holds the MCP servers declared in the project's .mcp.json,
	// separate from Settings.MCPServers (which come from settings.json). Attached
	// to the project-scope target so MCP rules cover both sources. Nil when no
	// .mcp.json is present. ProjectMCPFile is its path, used to attribute findings.
	ProjectMCP     map[string]parser.MCPServer
	ProjectMCPFile string

	// Instruction* carry the raw text and path of an agent instruction file loaded
	// for this scope — Claude Code's CLAUDE.md, or another agent's equivalent
	// (.cursorrules, .windsurfrules, AGENTS.md, .github/copilot-instructions.md).
	// These are read as trusted system context, so they are a prompt-injection
	// target. Both are empty when no instruction file is present.
	InstructionFile    string
	InstructionContent string

	// VSCodeTasks holds a parsed .vscode/tasks.json (VS Code / Cursor / Windsurf
	// workspace tasks). A task set to run on folder-open is a zero-click code
	// execution vector when committed to a repo (CFG047). Nil when absent;
	// VSCodeTasksFile is its path, used to attribute findings.
	VSCodeTasks     *parser.VSCodeTasks
	VSCodeTasksFile string

	// VSCodeSettings holds a parsed .vscode/settings.json (VS Code / Cursor /
	// Windsurf workspace settings). A committed setting that blanket-auto-approves
	// agent tools removes the human-in-the-loop (CFG048). Nil when absent;
	// VSCodeSettingsFile is its path, used to attribute findings.
	VSCodeSettings     *parser.VSCodeSettings
	VSCodeSettingsFile string

	// Policy*, when set, carry the organisation's custom permission policy from
	// .cfgaudit.yml (evaluated by CFG025). RequireDeny lists commands that must be
	// covered by permissions.deny; ForbidAllow lists commands that must not be
	// grantable by permissions.allow. Attached to the project-scope target only.
	PolicyRequireDeny []string
	PolicyForbidAllow []string

	// ShellCheck enables CFG045 (running the shellcheck binary over command
	// sites). Set by the CLI when --shellcheck / config requests it and the
	// binary is available.
	ShellCheck bool

	IgnoreFile  string
	IgnoreLines []parser.IgnoreLine
}

// mcpServerRef is a single MCP server definition paired with the file it was
// declared in, so a rule can attribute its finding to settings.json or .mcp.json.
type mcpServerRef struct {
	Name   string
	File   string
	Server parser.MCPServer
}

// mcpServerRefs returns every MCP server in scope for the target — those inline
// in settings.json (mcpServers) followed by those in the project .mcp.json —
// each sorted by name within its source and tagged with that source file.
func (t *Target) mcpServerRefs() []mcpServerRef {
	if t == nil {
		return nil
	}
	var refs []mcpServerRef
	if t.Settings != nil {
		refs = append(refs, sortedMCPRefs(t.Settings.MCPServers, t.SettingsFile)...)
	}
	refs = append(refs, sortedMCPRefs(t.ProjectMCP, t.ProjectMCPFile)...)
	return refs
}

func sortedMCPRefs(servers map[string]parser.MCPServer, file string) []mcpServerRef {
	if len(servers) == 0 {
		return nil
	}
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	refs := make([]mcpServerRef, 0, len(names))
	for _, n := range names {
		refs = append(refs, mcpServerRef{Name: n, File: file, Server: servers[n]})
	}
	return refs
}

// userScopeNote returns a message suffix to append to findings that originate
// from a user-global settings.json. The note flags the broader blast radius —
// user-global settings apply to every project the user opens with Claude Code.
// Empty for non-user scopes so callers can unconditionally append.
func userScopeNote(t *Target) string {
	if t == nil || t.Scope != finding.ScopeUser {
		return ""
	}
	return " — user-global scope: this setting applies to every Claude Code project you open"
}

// Rule is implemented by every cfgaudit check.
type Rule interface {
	ID() string
	Check(t *Target) []finding.Finding
}

// All is the ordered list of rules run on every target.
var All []Rule
