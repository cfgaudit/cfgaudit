package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/version"
	"github.com/cfgaudit/cfgaudit/rules"
)

// cfgauditVersion is injected at build time via:
//
//	go build -ldflags "-X main.cfgauditVersion=0.1.0" ./cmd/cfgaudit
//
// Unbranded local builds (`go run`, `go build` without ldflags) report "dev".
var cfgauditVersion = "dev"

func main() {
	// Subcommands are dispatched before flag parsing so their args (e.g. a rule
	// ID) aren't mistaken for the scan directory.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "explain":
			out, code := explainOutput(os.Args[2:])
			fmt.Print(out)
			os.Exit(code)
		case "list":
			out, code := listOutput(os.Args[2:])
			fmt.Print(out)
			os.Exit(code)
		case "policy":
			out, code := policyOutput(os.Args[2:])
			fmt.Print(out)
			os.Exit(code)
		case "init":
			out, code := initOutput(os.Args[2:], os.Stdin)
			fmt.Print(out)
			os.Exit(code)
		}
	}

	format := flag.String("format", "auto", "output format: auto (table on a TTY, text otherwise), text, table, json, sarif, codeclimate")
	user := flag.Bool("user", false, "also scan ~/.claude/settings.json")
	claudeVersion := flag.String("claude-version", "", "override the Claude Code version used for rule gating (default: detect via `claude --version`)")
	configPath := flag.String("config", "", "path to a .cfgaudit.yml (default: auto-discover in the scanned dir)")
	plugins := flag.String("plugins", "", "also scan a Claude Code plugin/skill package directory (SKILL.md, hooks, MCP servers)")
	strict := flag.Bool("strict", false, "treat warn findings as errors for the exit code (also: strict: true in .cfgaudit.yml)")
	shellcheck := flag.Bool("shellcheck", false, "run shellcheck on hook/helper commands (requires the shellcheck binary; also: shellcheck: true in .cfgaudit.yml)")
	showVersion := flag.Bool("version", false, "print cfgaudit version and exit")

	var only, skip ruleSet
	flag.Var(&only, "only", "run only these rule IDs (comma-separated; flag may be repeated)")
	flag.Var(&skip, "skip", "skip these rule IDs (comma-separated; flag may be repeated)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("cfgaudit %s\n", cfgauditVersion)
		return
	}

	if unknown := unknownRuleIDs(only, skip, rules.All); len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "cfgaudit: --only/--skip references unknown rule(s): %s\n", strings.Join(unknown, ", "))
	}

	dir := "."
	if flag.NArg() > 0 {
		dir = flag.Arg(0)
	}

	cfg, cfgPath, err := loadConfig(*configPath, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: %v\n", err)
		os.Exit(2)
	}
	if cfgPath != "" {
		fmt.Fprintf(os.Stderr, "cfgaudit: using config %s\n", cfgPath)
	}
	cfg = withStrict(cfg, *strict)

	accept := acceptWith(ruleFilter(only, skip), cfg)

	detected := resolveClaudeVersion(*claudeVersion)

	targets, err := buildTargets(dir, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: %v\n", err)
		os.Exit(2)
	}
	attachPolicy(targets, cfg)

	pluginTargets, err := buildPluginTargets(dir, *plugins, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: %v\n", err)
		os.Exit(2)
	}
	targets = append(targets, pluginTargets...)

	if shellCheckEnabled(*shellcheck || cfg.ShellCheckEnabled()) {
		for _, t := range targets {
			t.ShellCheck = true
		}
	}

	var all []finding.Finding
	for _, target := range targets {
		all = append(all, rules.Run(target, detected, accept)...)
	}
	all = cfg.PostProcess(all, dir)

	switch resolveFormat(*format, isTTY(os.Stdout)) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(all)
	case "sarif":
		if err := encodeSARIF(os.Stdout, all, cfgauditVersion, rules.All); err != nil {
			fmt.Fprintf(os.Stderr, "cfgaudit: sarif encode: %v\n", err)
			os.Exit(2)
		}
	case "codeclimate", "codequality":
		if err := encodeCodeClimate(os.Stdout, all, dir); err != nil {
			fmt.Fprintf(os.Stderr, "cfgaudit: codeclimate encode: %v\n", err)
			os.Exit(2)
		}
	case "table":
		renderTable(os.Stdout, all, cfgauditVersion)
	default:
		for _, f := range all {
			fmt.Println(f)
		}
		fmt.Printf("\ncfgaudit %s — %d %s\n", cfgauditVersion, len(all), pluralize("finding", len(all)))
	}

	if exitCode := cfg.ExitCode(all); exitCode != 0 {
		os.Exit(exitCode)
	}
}

// loadConfig resolves the .cfgaudit.yml to use: an explicit --config path (error
// if missing) takes precedence over auto-discovery in dir. Returns (nil, "", nil)
// when neither yields a file.
func loadConfig(explicit, dir string) (*config.Config, string, error) {
	if explicit != "" {
		c, err := config.Load(explicit)
		if err != nil {
			return nil, "", err
		}
		return c, explicit, nil
	}
	return config.Discover(dir)
}

// shellCheckEnabled reports whether ShellCheck analysis should run: requested
// (flag or config) and the binary is available. Warns to stderr when requested
// but unavailable, so the scan continues gracefully without shell analysis.
func shellCheckEnabled(requested bool) bool {
	if !requested {
		return false
	}
	if !rules.ShellcheckAvailable() {
		fmt.Fprintln(os.Stderr, "cfgaudit: --shellcheck requested but the shellcheck binary is not on PATH; skipping shell analysis")
		return false
	}
	return true
}

// attachPolicy wires the org policy from .cfgaudit.yml onto the project-scope
// target so CFG025 can enforce it. The project settings.json is the canonical
// committed artifact a policy applies to; other scopes are left untouched.
func attachPolicy(targets []*rules.Target, cfg *config.Config) {
	if cfg == nil || !cfg.Policy.Configured() {
		return
	}
	for _, t := range targets {
		if t.Scope == finding.ScopeProject {
			t.PolicyRequireDeny = cfg.Policy.RequireDeny
			t.PolicyForbidAllow = cfg.Policy.ForbidAllow
		}
	}
}

// withStrict applies the --strict flag: it forces warn→error for the exit code,
// taking precedence over the config. The flag cannot turn strict off — omit it to
// defer to the config's `strict:` value. A nil config is materialised when needed.
func withStrict(cfg *config.Config, strict bool) *config.Config {
	if !strict {
		return cfg
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Strict = true
	return cfg
}

// acceptWith combines the CLI --only/--skip filter with the config's rule
// disables. Returns nil (no filtering) only when neither constrains anything.
func acceptWith(base func(rules.Rule) bool, cfg *config.Config) func(rules.Rule) bool {
	if base == nil && cfg == nil {
		return nil
	}
	return func(r rules.Rule) bool {
		if base != nil && !base(r) {
			return false
		}
		return cfg.RuleEnabled(r.ID())
	}
}

func pluralize(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// resolveClaudeVersion picks the version to use for rule gating.
// Priority: explicit --claude-version flag > `claude --version` detection > nil.
// A nil return disables version gating and runs every rule unconditionally.
func resolveClaudeVersion(override string) *version.Version {
	if override != "" {
		v, err := version.Parse(override)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cfgaudit: --claude-version %q is not a recognised version; falling back to detection\n", override)
		} else {
			fmt.Fprintf(os.Stderr, "cfgaudit: scanning with Claude Code v%s (--claude-version)\n", v)
			return &v
		}
	}
	v, found, err := version.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgaudit: could not parse `claude --version` output (%v); running all rules without version gating\n", err)
		return nil
	}
	if !found {
		fmt.Fprintln(os.Stderr, "cfgaudit: `claude` binary not on PATH; running all rules without version gating")
		return nil
	}
	fmt.Fprintf(os.Stderr, "cfgaudit: scanning with Claude Code v%s (detected)\n", v)
	return &v
}

func buildTargets(dir string, includeUser bool) ([]*rules.Target, error) {
	ignorePath := filepath.Join(dir, ".claudeignore")
	ignoreLines, err := parser.ParseIgnore(ignorePath)
	if err != nil {
		return nil, err
	}

	// The project .mcp.json is parsed once and attached to the project-scope
	// target (built below), so MCP rules cover it and .gitignore/sibling-file
	// rules don't run twice.
	projectMCP, mcpFile, err := loadProjectMCP(dir)
	if err != nil {
		return nil, err
	}

	projectSettingsPath := filepath.Join(dir, ".claude", "settings.json")
	projectSettings, err := parseSettingsOptional(projectSettingsPath)
	if err != nil {
		return nil, err
	}
	projectClaudeMDPath := filepath.Join(dir, "CLAUDE.md")
	projectClaudeMD, err := loadClaudeMD(projectClaudeMDPath)
	if err != nil {
		return nil, err
	}

	var targets []*rules.Target

	// Project scope: settings.json, .mcp.json and CLAUDE.md share one target. It
	// exists when any of them is present.
	if projectSettings != nil || len(projectMCP) > 0 || projectClaudeMD != "" {
		t := &rules.Target{
			SettingsFile:   projectSettingsPath,
			Settings:       projectSettings,
			Scope:          finding.ScopeProject,
			ProjectDir:     dir,
			ProjectMCP:     projectMCP,
			ProjectMCPFile: mcpFile,
			IgnoreFile:     ignorePath,
			IgnoreLines:    ignoreLines,
		}
		if projectClaudeMD != "" {
			t.InstructionFile = projectClaudeMDPath
			t.InstructionContent = projectClaudeMD
		}
		targets = append(targets, t)
	}

	// Project-local scope: settings.local.json only.
	localPath := filepath.Join(dir, ".claude", "settings.local.json")
	localSettings, err := parseSettingsOptional(localPath)
	if err != nil {
		return nil, err
	}
	if localSettings != nil {
		targets = append(targets, &rules.Target{
			SettingsFile: localPath,
			Settings:     localSettings,
			Scope:        finding.ScopeProjectLocal,
			ProjectDir:   dir,
			IgnoreFile:   ignorePath,
			IgnoreLines:  ignoreLines,
			// Claude Code merges settings.json into settings.local.json, so the
			// project deny list applies to the local file too (CFG006).
			SiblingDeny: projectSettings != nil && projectSettings.Permissions != nil &&
				len(projectSettings.Permissions.Deny) > 0,
		})
	}

	// User scope: ~/.claude/settings.json and ~/.claude/CLAUDE.md (only with --user).
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		userSettingsPath := filepath.Join(home, ".claude", "settings.json")
		userSettings, err := parseSettingsOptional(userSettingsPath)
		if err != nil {
			return nil, err
		}
		userClaudeMDPath := filepath.Join(home, ".claude", "CLAUDE.md")
		userClaudeMD, err := loadClaudeMD(userClaudeMDPath)
		if err != nil {
			return nil, err
		}
		if userSettings != nil || userClaudeMD != "" {
			t := &rules.Target{
				SettingsFile: userSettingsPath,
				Settings:     userSettings,
				Scope:        finding.ScopeUser,
				IgnoreFile:   ignorePath,
				IgnoreLines:  ignoreLines,
			}
			if userClaudeMD != "" {
				t.InstructionFile = userClaudeMDPath
				t.InstructionContent = userClaudeMD
			}
			targets = append(targets, t)
		}
	}

	// Other agents' instruction files (Cursor, Windsurf, Copilot, AGENTS.md). Each
	// becomes its own target so the CLAUDE.md content rules scan it, attributed to
	// the source file. CLAUDE.md itself rides the project target above.
	instr, err := instructionTargets(dir, includeUser)
	if err != nil {
		return nil, err
	}
	targets = append(targets, instr...)

	// Other agents' MCP config files (Cursor, VS Code, Windsurf, Cline). MCP is a
	// shared standard, so the MCP rules apply unchanged; each config becomes its
	// own target attributed to the source file. Claude Code's .mcp.json rides the
	// project target above.
	mcp, err := mcpConfigTargets(dir, includeUser)
	if err != nil {
		return nil, err
	}
	targets = append(targets, mcp...)

	// VS Code workspace files (.vscode/), read by VS Code / Cursor / Windsurf.
	// Committed to a repo they are an auto-run / supply-chain surface.
	vsc, err := vscodeTargets(dir)
	if err != nil {
		return nil, err
	}
	targets = append(targets, vsc...)

	// Gemini CLI settings.json (.gemini/, and ~/.gemini/ with --user). Carries the
	// Gemini-specific security surface (CFG060–062) and its mcpServers ride
	// ProjectMCP so the MCP rules apply. GEMINI.md rides instructionTargets above.
	gem, err := geminiTargets(dir, includeUser)
	if err != nil {
		return nil, err
	}
	targets = append(targets, gem...)

	// OpenAI Codex CLI config.toml (~/.codex/, only with --user — Codex config is
	// user-global, not project-merged). Carries approval_policy / sandbox_mode
	// (CFG063/064) and [mcp_servers] rides ProjectMCP. AGENTS.md (the committed
	// project surface) rides instructionTargets above.
	cdx, err := codexTargets(includeUser)
	if err != nil {
		return nil, err
	}
	targets = append(targets, cdx...)

	// Continue config.yaml (.continue/, and ~/.continue/ with --user). Its
	// mcpServers list rides ProjectMCP so the MCP rules apply; inline apiKey
	// literals drive CFG065.
	cont, err := continueTargets(dir, includeUser)
	if err != nil {
		return nil, err
	}
	targets = append(targets, cont...)

	// skills-lock.json (vercel-labs/skills CLI) at the repo root — a committed lock
	// file declaring which external repos agent-skill (instruction) content is
	// pulled from. An unpinned source is a supply-chain surface (CFG074).
	sl, slFile, err := loadSkillsLock(dir)
	if err != nil {
		return nil, err
	}
	if sl != nil {
		targets = append(targets, &rules.Target{
			Scope:          finding.ScopeProject,
			SkillsLock:     sl,
			SkillsLockFile: slFile,
		})
	}

	return targets, nil
}

// loadSkillsLock parses dir/skills-lock.json (the project-local lock file written
// by the vercel-labs/skills CLI). A missing file — or one with no skills — yields
// (nil, "", nil) so no empty target is built. A malformed file is reported as an
// error, like the other JSON config loaders. The user-global ~/.agents/.skill-lock.json
// is deliberately not scanned: it is not committable, so it is out of scope.
func loadSkillsLock(dir string) (*parser.SkillsLock, string, error) {
	path := filepath.Join(dir, "skills-lock.json")
	sl, err := parser.ParseSkillsLock(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if sl == nil || len(sl.Skills) == 0 {
		return nil, "", nil
	}
	return sl, path, nil
}

// continueTargets discovers Continue config.yaml — .continue/config.yaml
// (project) and ~/.continue/config.yaml (user, only with --user). The mcpServers
// list is attached as ProjectMCP so the shared MCP rules fire (attributed to the
// config file); the parsed config drives CFG065.
func continueTargets(dir string, includeUser bool) ([]*rules.Target, error) {
	var targets []*rules.Target
	add := func(path string, scope finding.Scope) error {
		cc, err := parseContinueOptional(path)
		if err != nil {
			return err
		}
		if cc == nil {
			return nil
		}
		targets = append(targets, &rules.Target{
			Scope:          scope,
			Continue:       cc,
			ContinueFile:   path,
			ProjectMCP:     cc.MCPServerMap(),
			ProjectMCPFile: path,
		})
		return nil
	}
	if err := add(filepath.Join(dir, ".continue", "config.yaml"), finding.ScopeProject); err != nil {
		return nil, err
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		if err := add(filepath.Join(home, ".continue", "config.yaml"), finding.ScopeUser); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// parseContinueOptional parses a Continue config.yaml, returning (nil, nil) when
// the file does not exist so callers can treat absence as "no target".
func parseContinueOptional(path string) (*parser.ContinueConfig, error) {
	cc, err := parser.ParseContinueConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return cc, nil
}

// codexTargets discovers the user-global OpenAI Codex config.toml
// (~/.codex/config.toml, scanned only with --user). The Codex-specific fields
// drive CFG063/064; [mcp_servers] are attached as ProjectMCP so the shared MCP
// rules fire, attributed to the config file.
func codexTargets(includeUser bool) ([]*rules.Target, error) {
	if !includeUser {
		return nil, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	path := filepath.Join(home, ".codex", "config.toml")
	cc, err := parseCodexOptional(path)
	if err != nil {
		return nil, err
	}
	if cc == nil {
		return nil, nil
	}
	return []*rules.Target{{
		Scope:          finding.ScopeUser,
		Codex:          cc,
		CodexFile:      path,
		ProjectMCP:     cc.MCPServerMap(),
		ProjectMCPFile: path,
	}}, nil
}

// parseCodexOptional parses a Codex config.toml, returning (nil, nil) when the
// file does not exist so callers can treat absence as "no target".
func parseCodexOptional(path string) (*parser.CodexConfig, error) {
	cc, err := parser.ParseCodexConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return cc, nil
}

// geminiTargets discovers Gemini CLI settings.json files — .gemini/settings.json
// (project) and ~/.gemini/settings.json (user, only with --user) — and returns
// one target per present file. The Gemini-specific fields drive CFG060–062;
// mcpServers are attached as ProjectMCP so the shared MCP rules fire, attributed
// to the settings file.
func geminiTargets(dir string, includeUser bool) ([]*rules.Target, error) {
	var targets []*rules.Target
	add := func(path string, scope finding.Scope) error {
		gs, err := parseGeminiOptional(path)
		if err != nil {
			return err
		}
		if gs == nil {
			return nil
		}
		targets = append(targets, &rules.Target{
			Scope:          scope,
			Gemini:         gs,
			GeminiFile:     path,
			ProjectMCP:     gs.MCPServers,
			ProjectMCPFile: path,
		})
		return nil
	}
	if err := add(filepath.Join(dir, ".gemini", "settings.json"), finding.ScopeProject); err != nil {
		return nil, err
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		if err := add(filepath.Join(home, ".gemini", "settings.json"), finding.ScopeUser); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// parseGeminiOptional parses a Gemini settings.json, returning (nil, nil) when
// the file does not exist so callers can treat absence as "no target".
func parseGeminiOptional(path string) (*parser.GeminiSettings, error) {
	gs, err := parser.ParseGeminiSettings(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return gs, nil
}

// vscodeTargets discovers committable VS Code workspace files under dir and
// returns a target per present one, so the corresponding rules fire attributed
// to the source file. Shared by VS Code and its forks (Cursor, Windsurf).
func vscodeTargets(dir string) ([]*rules.Target, error) {
	var targets []*rules.Target
	tasks, tasksFile, err := loadVSCodeTasks(dir)
	if err != nil {
		return nil, err
	}
	if tasks != nil {
		targets = append(targets, &rules.Target{
			Scope:           finding.ScopeProject,
			VSCodeTasks:     tasks,
			VSCodeTasksFile: tasksFile,
		})
	}

	settings, settingsFile, err := loadVSCodeSettings(dir)
	if err != nil {
		return nil, err
	}
	if settings != nil {
		targets = append(targets, &rules.Target{
			Scope:              finding.ScopeProject,
			VSCodeSettings:     settings,
			VSCodeSettingsFile: settingsFile,
		})
	}
	return targets, nil
}

// loadVSCodeSettings parses dir/.vscode/settings.json. A missing or empty file
// yields (nil, "", nil); a malformed file is reported as an error.
func loadVSCodeSettings(dir string) (*parser.VSCodeSettings, string, error) {
	path := filepath.Join(dir, ".vscode", "settings.json")
	v, err := parser.ParseVSCodeSettings(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if v == nil || len(v.Raw) == 0 {
		return nil, "", nil
	}
	return v, path, nil
}

// loadVSCodeTasks parses dir/.vscode/tasks.json. A missing file yields
// (nil, "", nil); a file with no tasks yields the same so no empty target is
// built. A malformed file is reported as an error.
func loadVSCodeTasks(dir string) (*parser.VSCodeTasks, string, error) {
	path := filepath.Join(dir, ".vscode", "tasks.json")
	v, err := parser.ParseVSCodeTasks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if v == nil || len(v.Tasks) == 0 {
		return nil, "", nil
	}
	return v, path, nil
}

// agentInstructionFiles lists the (non-CLAUDE.md) instruction files cfgaudit
// scans across agents: single files plus glob patterns for rule directories.
var (
	agentInstructionFiles = []string{
		".cursorrules",
		".windsurfrules",
		"AGENTS.md",
		"GEMINI.md", // Gemini CLI project instruction file (analog to CLAUDE.md)
		filepath.Join(".github", "copilot-instructions.md"),
	}
	agentInstructionGlobs = []string{
		filepath.Join(".cursor", "rules", "*.md"),
		filepath.Join(".cursor", "rules", "*.mdc"),
		filepath.Join(".windsurf", "rules", "*.md"),
		// GitHub Copilot path-specific instructions (newer than the repo-wide
		// .github/copilot-instructions.md, which is in agentInstructionFiles) —
		// committed Markdown loaded as Copilot context, same prompt-injection surface.
		filepath.Join(".github", "instructions", "*.instructions.md"),
		// Claude Code custom subagents, slash commands, and skills — Markdown with a
		// YAML frontmatter (description trigger, allowed-tools) read as trusted
		// context. Skills live one directory deep: .claude/skills/<name>/SKILL.md.
		filepath.Join(".claude", "agents", "*.md"),
		filepath.Join(".claude", "commands", "*.md"),
		filepath.Join(".claude", "skills", "*", "SKILL.md"),
		// .claude/rules/ is NOT listed here: Claude Code discovers it recursively
		// (subdirectories allowed), which the single-level filepath.Glob above can't
		// express, so it is collected by claudeRulesFiles instead (#325).
	}
	// userInstructionGlobs are scanned only with --user (relative to $HOME): the
	// user-global subagents, slash commands, and skills apply to every project.
	userInstructionGlobs = []string{
		filepath.Join(".claude", "agents", "*.md"),
		filepath.Join(".claude", "commands", "*.md"),
		filepath.Join(".claude", "skills", "*", "SKILL.md"),
		filepath.Join(".gemini", "GEMINI.md"), // Gemini CLI user-global instruction file
	}
)

// instructionTargets discovers agents' instruction files (other-agent files and
// Claude Code subagents/slash commands) and returns one target per present,
// non-empty file. With includeUser it also scans the user-global
// ~/.claude/agents and ~/.claude/commands. ProjectDir is intentionally unset so
// file-based rules (e.g. CFG013) don't fire per file.
func instructionTargets(dir string, includeUser bool) ([]*rules.Target, error) {
	type scopedPath struct {
		path  string
		scope finding.Scope
	}
	var paths []scopedPath
	for _, rel := range agentInstructionFiles {
		paths = append(paths, scopedPath{filepath.Join(dir, rel), finding.ScopeProject})
	}
	addGlobs := func(base string, globs []string, scope finding.Scope) error {
		for _, pat := range globs {
			matches, err := filepath.Glob(filepath.Join(base, pat))
			if err != nil {
				return err
			}
			for _, m := range matches {
				paths = append(paths, scopedPath{m, scope})
			}
		}
		return nil
	}
	if err := addGlobs(dir, agentInstructionGlobs, finding.ScopeProject); err != nil {
		return nil, err
	}
	projRules, err := claudeRulesFiles(dir)
	if err != nil {
		return nil, err
	}
	for _, m := range projRules {
		paths = append(paths, scopedPath{m, finding.ScopeProject})
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		if err := addGlobs(home, userInstructionGlobs, finding.ScopeUser); err != nil {
			return nil, err
		}
		userRules, err := claudeRulesFiles(home)
		if err != nil {
			return nil, err
		}
		for _, m := range userRules {
			paths = append(paths, scopedPath{m, finding.ScopeUser})
		}
	}

	var targets []*rules.Target
	for _, p := range paths {
		content, err := loadClaudeMD(p.path)
		if err != nil {
			return nil, err
		}
		if content == "" {
			continue
		}
		targets = append(targets, &rules.Target{
			Scope:              p.scope,
			InstructionFile:    p.path,
			InstructionContent: content,
		})
	}
	return targets, nil
}

// claudeRulesFiles returns every *.md file under <base>/.claude/rules, discovered
// recursively. Claude Code loads .claude/rules/**/*.md as trusted instruction
// context at the same priority as CLAUDE.md — unconditional files at launch and
// conditional ones (carrying a `paths:` frontmatter) when a matching file is read
// — and walks subdirectories to find them, so unlike the single-level globs this
// needs a full walk (#325). A missing rules directory yields no files and no
// error; results are sorted for deterministic ordering.
func claudeRulesFiles(base string) ([]string, error) {
	root := filepath.Join(base, ".claude", "rules")
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A missing .claude/rules directory is the common case — not an error.
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".md") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// loadClaudeMD reads a CLAUDE.md file. A missing file yields ("", nil); the raw
// text is returned otherwise. CLAUDE.md is free-form Markdown, so unlike
// settings.json there is no parse step that can fail.
func loadClaudeMD(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// parseSettingsOptional parses a settings.json, returning (nil, nil) when the
// file does not exist so callers can treat absence as "no target".
func parseSettingsOptional(path string) (*parser.Settings, error) {
	s, err := parser.ParseSettings(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return s, nil
}

// loadProjectMCP parses dir/.mcp.json. A missing file yields (nil, "", nil); a
// malformed file is reported as an error so the user learns their .mcp.json is
// not being scanned rather than silently trusting it.
func loadProjectMCP(dir string) (map[string]parser.MCPServer, string, error) {
	path := filepath.Join(dir, ".mcp.json")
	servers, err := loadMCPConfigOptional(path)
	if err != nil {
		return nil, "", err
	}
	if len(servers) == 0 {
		return nil, "", nil
	}
	return servers, path, nil
}

// loadZedServersOptional parses .zed/settings.json and returns its
// context_servers, or (nil, nil) when the file does not exist. A malformed file
// is an error, so a Zed config that is silently not being scanned is reported
// rather than mistaken for "no servers".
func loadZedServersOptional(path string) (map[string]parser.MCPServer, error) {
	servers, err := parser.ParseZedSettings(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return servers, nil
}

// loadMCPConfigOptional parses an MCP config file, returning (nil, nil) when it
// does not exist so callers can treat absence as "no servers". A malformed file
// is an error.
func loadMCPConfigOptional(path string) (map[string]parser.MCPServer, error) {
	cfg, err := parser.ParseMCPConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return cfg.MCPServers, nil
}

// agentMCPFiles lists other agents' MCP config files relative to the project
// root; userAgentMCPFiles lists user-global ones (relative to $HOME) discovered
// only with --user. All share the { "mcpServers": … } shape (VS Code's "servers"
// variant is folded in by ParseMCPConfig).
var (
	agentMCPFiles = []string{
		filepath.Join(".cursor", "mcp.json"), // Cursor (project)
		filepath.Join(".vscode", "mcp.json"), // VS Code / Copilot
		"cline_mcp_settings.json",            // Cline
	}
	userAgentMCPFiles = []string{
		filepath.Join(".cursor", "mcp.json"),                     // Cursor (user-global)
		filepath.Join(".codeium", "windsurf", "mcp_config.json"), // Windsurf
	}
)

// mcpConfigTargets discovers other agents' MCP config files and returns one
// target per present, non-empty file, carrying only its servers so the MCP
// rules fire (settings-shape and instruction rules stay inert). Findings are
// attributed to the source file via ProjectMCPFile.
func mcpConfigTargets(dir string, includeUser bool) ([]*rules.Target, error) {
	var targets []*rules.Target
	add := func(path string, scope finding.Scope) error {
		servers, err := loadMCPConfigOptional(path)
		if err != nil {
			return err
		}
		if len(servers) == 0 {
			return nil
		}
		targets = append(targets, &rules.Target{
			Scope:          scope,
			ProjectMCP:     servers,
			ProjectMCPFile: path,
		})
		return nil
	}
	for _, rel := range agentMCPFiles {
		if err := add(filepath.Join(dir, rel), finding.ScopeProject); err != nil {
			return nil, err
		}
	}

	// Zed declares its MCP servers inside the project settings file rather than a
	// dedicated MCP config, so it needs its own loader: a different key
	// (context_servers) and JSONC, which Zed's settings allow.
	zedPath := filepath.Join(dir, ".zed", "settings.json")
	zedServers, err := loadZedServersOptional(zedPath)
	if err != nil {
		return nil, err
	}
	if len(zedServers) > 0 {
		targets = append(targets, &rules.Target{
			Scope:          finding.ScopeProject,
			ProjectMCP:     zedServers,
			ProjectMCPFile: zedPath,
		})
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		for _, rel := range userAgentMCPFiles {
			if err := add(filepath.Join(home, rel), finding.ScopeUser); err != nil {
				return nil, err
			}
		}
	}
	return targets, nil
}

// ruleSet is a flag.Value that collects rule IDs from one or more occurrences
// of a flag. Each occurrence may pass a comma-separated list. Whitespace and
// empty entries are tolerated. Used by `--only` and `--skip`.
type ruleSet map[string]bool

func (rs *ruleSet) String() string {
	if rs == nil || *rs == nil {
		return ""
	}
	ids := make([]string, 0, len(*rs))
	for id := range *rs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func (rs *ruleSet) Set(v string) error {
	if *rs == nil {
		*rs = ruleSet{}
	}
	for _, raw := range strings.Split(v, ",") {
		id := strings.TrimSpace(raw)
		if id != "" {
			(*rs)[id] = true
		}
	}
	return nil
}

// ruleFilter builds the `accept` predicate that rules.Run consults.
// only takes precedence: when non-empty, a rule must appear in it to run.
// skip then excludes any remaining matches.
// A nil return means "no filtering" (all rules run).
func ruleFilter(only, skip ruleSet) func(rules.Rule) bool {
	if len(only) == 0 && len(skip) == 0 {
		return nil
	}
	return func(r rules.Rule) bool {
		id := r.ID()
		if len(only) > 0 && !only[id] {
			return false
		}
		return !skip[id]
	}
}

// unknownRuleIDs returns any IDs in only or skip that no registered rule reports.
// Used to warn the user about typos like `--only CFG999`.
func unknownRuleIDs(only, skip ruleSet, all []rules.Rule) []string {
	known := make(map[string]bool, len(all))
	for _, r := range all {
		known[r.ID()] = true
	}
	seen := map[string]bool{}
	var unknown []string
	for _, set := range []ruleSet{only, skip} {
		for id := range set {
			if !known[id] && !seen[id] {
				seen[id] = true
				unknown = append(unknown, id)
			}
		}
	}
	sort.Strings(unknown)
	return unknown
}
