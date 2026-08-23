package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// commandSite is one location that holds a shell command string Claude Code (or
// another agent) executes. The content rules (CFG008/009/014/015/…) inspect every
// site uniformly: hooks are not the only place a repo-controlled config can
// smuggle a command — credential helpers (apiKeyHelper, awsCredentialExport, …),
// the status line and its subagent twin, OTEL headers, file-suggestion scripts
// (CVE-2025-59536 attack class), and each MCP server's headersHelper all run a
// shell command too.
//
// subagentStatusLine is undocumented in the settings reference; the client's own
// diagnostics are what put it on this list ("Skipping subagentStatusLine
// execution - workspace trust not accepted", plus its exit and output-schema
// errors). Same value shape and same trust gate as statusLine.
type commandSite struct {
	// Label is the finding-friendly origin of the command, already phrased as a
	// noun ending in "command" (e.g. "hooks.SessionStart command", "apiKeyHelper
	// command") so rules can append their verb directly.
	Label string
	// File is the config file the command was declared in, so a finding is
	// attributed correctly (settings.json vs an MCP config such as .mcp.json).
	File    string
	Command string
}

// commandSites returns every non-empty command-bearing site in the target, in a
// stable order: settings.json hooks (by event name), then its credential/runtime
// helpers, then each MCP server's headersHelper (attributed to the MCP source
// file). Returns nil for a nil target.
func commandSites(t *Target) []commandSite {
	if t == nil {
		return nil
	}
	var sites []commandSite

	if s := t.Settings; s != nil {
		events := make([]string, 0, len(s.Hooks))
		for e := range s.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range s.Hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "hooks." + event + " command", File: t.SettingsFile, Command: h.Command})
					}
				}
			}
		}

		add := func(label, cmd string) {
			if cmd != "" {
				sites = append(sites, commandSite{Label: label + " command", File: t.SettingsFile, Command: cmd})
			}
		}
		add("apiKeyHelper", s.StringField("apiKeyHelper"))
		add("awsCredentialExport", s.StringField("awsCredentialExport"))
		add("awsAuthRefresh", s.StringField("awsAuthRefresh"))
		add("gcpAuthRefresh", s.StringField("gcpAuthRefresh"))
		add("otelHeadersHelper", s.StringField("otelHeadersHelper"))
		add("statusLine", s.CommandHelperField("statusLine"))
		add("subagentStatusLine", s.CommandHelperField("subagentStatusLine"))
		add("fileSuggestion", s.CommandHelperField("fileSuggestion"))
	}

	for _, ref := range t.mcpServerRefs() {
		if cmd := ref.Server.HeadersHelper; cmd != "" {
			sites = append(sites, commandSite{Label: "mcpServers." + ref.Name + ".headersHelper command", File: ref.File, Command: cmd})
		}
	}

	// Devin CLI .devin/config.json hooks. The shape matches Claude Code's — event
	// name → groups of {type, command} — and the file is committed to version
	// control by design, so the same command-content rules apply. Labelled
	// distinctly so a finding names the file the command actually came from.
	if t.Devin != nil && len(t.Devin.Hooks) > 0 {
		events := make([]string, 0, len(t.Devin.Hooks))
		for e := range t.Devin.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range t.Devin.Hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "Devin hooks." + event + " command", File: t.DevinFile, Command: h.Command})
					}
				}
			}
		}
	}

	// Zed .zed/tasks.json. Only a task carrying a `hooks` entry is a command site:
	// Zed spawns those itself, so the command runs without the user invoking it.
	// A plain task is one the user picks from the task list, which is no more a
	// committed-execution surface than a Makefile target. The trigger is CFG047's;
	// this is the command text behind it.
	if zt := t.ZedTasks; zt != nil {
		for _, task := range zt.Tasks {
			if len(task.AutoRunHooks()) == 0 || task.Command == "" {
				continue
			}
			cmd := task.Command
			if len(task.Args) > 0 {
				cmd += " " + strings.Join(task.Args, " ")
			}
			sites = append(sites, commandSite{Label: "Zed hook task \"" + task.Name() + "\" command", File: t.ZedTasksFile, Command: cmd})
		}
	}

	// Zed .zed/settings.json: terminal.shell, lsp.<name>.binary and dap.<name>.
	// Each names an executable Zed launches with its argv, so the command-content
	// family applies exactly as it does to a hook.
	//
	// Unlike tasks.json above, this file IS worktree-trust gated: the same
	// SettingsObserver match gates LocalSettingsKind::Settings on
	// can_trust_worktree while LocalSettingsKind::Tasks is ungated. So these are
	// not zero-click, and the label says "on trust" rather than implying they run
	// on open. Reported anyway on the footing cfgaudit already applies to
	// context_servers in this same file: trust is one prompt covering the whole
	// worktree, granted for any Zed functionality at all, not consent to a
	// specific binary.
	if zs := t.ZedSettings; zs != nil {
		for _, site := range zs.CommandSites() {
			if site.Command == "" {
				continue
			}
			sites = append(sites, commandSite{
				Label:   "Zed " + site.Label + " command (runs on worktree trust)",
				File:    t.ZedSettingsFile,
				Command: site.Command,
			})
		}
	}

	// Continue CLI hooks (.continue/settings.json, .continue/settings.local.json).
	// Same event → matcher groups → {type, command} nesting as Claude Code's, by
	// design: Continue's loader reads "settings files in the same locations as
	// Claude Code". Only the "command" handler runs a shell command — "http"
	// carries a url (CFG088) and "prompt"/"agent" carry prompt text (instruction
	// sources). disableAllHooks turns the file off.
	if ch := t.ContinueHooks; ch != nil && !ch.DisableAllHooks && len(ch.Hooks) > 0 {
		for _, event := range sortedKeys2(ch.Hooks) {
			for _, group := range ch.Hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "Continue hooks." + event + " command", File: t.ContinueHooksFile, Command: h.Command})
					}
				}
			}
		}
	}

	// OpenAI Codex CLI hooks: .codex/hooks.json, or the inline [hooks] table of
	// .codex/config.toml. Same event → matcher groups → {type, command} nesting as
	// Claude Code's, and `hooks` is deliberately absent from Codex's
	// PROJECT_LOCAL_CONFIG_DENYLIST, so a committed table is discovered.
	//
	// Only the "command" handler carries a shell string: Codex's discovery skips
	// "prompt" and "agent" handlers with the warning that they "are not supported
	// yet", so neither is a command site. The Windows spelling (commandWindows /
	// command_windows) is collected too, since a hook that sets only that still
	// runs a command.
	//
	// These are command sites, not triggers. Codex runs a non-managed hook only
	// when the user's own config layer records a trusted_hash equal to the hook's
	// current content hash (codex-rs/hooks/src/engine/discovery.rs), and a project
	// layer cannot write that state. So the command text is what is worth showing
	// a reviewer, at exactly the moment Codex asks them to trust it, while the
	// zero-click (CFG086) and auto-approve (CFG087) rules stay off Codex.
	if ch := t.CodexHooks; ch != nil {
		for _, event := range ch.EventNames() {
			for _, group := range ch.Events[event] {
				for _, h := range group.Hooks {
					for _, cmd := range h.Commands() {
						sites = append(sites, commandSite{Label: "Codex hooks." + event + " command", File: t.CodexHooksFile, Command: cmd})
					}
				}
			}
		}
	}

	// Claude Code subagent frontmatter hooks (.claude/agents/*.md `hooks:`, #428).
	// Same event → matcher groups → {type, command} nesting as settings.json, and
	// the agent file is committed, so the command text runs on whoever uses the
	// subagent. Labelled distinctly because the trigger is narrower than a
	// settings.json hook: these fire when the agent is spawned through the Agent
	// tool or an @-mention, or when it runs as the main session via --agent or the
	// `agent` setting — not merely on opening the repo. Since 2.1.218 they
	// additionally require the agent file's folder to have accepted workspace
	// trust. Neither caveat changes the command content, which is what these rules
	// judge; the trigger is why CFG067 and CFG086 are deliberately not extended
	// here (see instructionSources and CFG086's doc).
	if len(t.SubagentHooks) > 0 {
		events := make([]string, 0, len(t.SubagentHooks))
		for e := range t.SubagentHooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range t.SubagentHooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "subagent frontmatter hooks." + event + " command", File: t.SubagentHooksFile, Command: h.Command})
					}
				}
			}
		}
	}

	// xAI Grok CLI .grok/hooks/*.json. The hook file has the same event → matcher
	// groups → {type, command} shape as Claude Code's, and Grok's user guide marks
	// these committable, so the command handlers are command sites. Only the
	// "command" handler type runs a shell command; "http" handlers carry a url and
	// no command, so they are skipped here.
	if gh := t.GrokHooks; gh != nil && len(gh.Hooks) > 0 {
		events := make([]string, 0, len(gh.Hooks))
		for e := range gh.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range gh.Hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "Grok hooks." + event + " command", File: t.GrokHooksFile, Command: h.Command})
					}
				}
			}
		}
	}

	// Gemini CLI .gemini/settings.json hooks. Same event → matcher groups →
	// {type, command} nesting as Claude Code's, and the file is project-committed,
	// so the command handlers are command sites. Only the "command" handler type
	// runs a shell command (a "runtime"/"plugin" handler carries no command).
	// hooksConfig.enabled: false turns the whole system off; hooksConfig.disabled
	// switches off individual hooks by name — a handler Gemini would not run is not
	// a command site.
	if g := t.Gemini; g != nil && !g.HooksDisabled() && len(g.Hooks) > 0 {
		disabled := g.DisabledHookNames()
		events := make([]string, 0, len(g.Hooks))
		for e := range g.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range g.Hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" && !disabled[h.Name] {
						sites = append(sites, commandSite{Label: "Gemini hooks." + event + " command", File: t.GeminiFile, Command: h.Command})
					}
				}
			}
		}
	}

	// qwen-code .qwen/settings.json hooks. Same event → matcher groups →
	// {type, command} nesting as Gemini's; the settings.json validator allows only
	// "command" and "http" handler types, and only "command" carries a shell string
	// (an "http" handler has a url and no command). disableAllHooks turns the whole
	// system off. Committed and — because qwen ships folder trust off by default —
	// applied unprompted, so the command-content rules apply.
	if q := t.Qwen; q != nil && !q.HooksDisabled() {
		hooks := q.HookGroups()
		events := make([]string, 0, len(hooks))
		for e := range hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, group := range hooks[event] {
				for _, h := range group.Hooks {
					if h.Command != "" {
						sites = append(sites, commandSite{Label: "qwen hooks." + event + " command", File: t.QwenFile, Command: h.Command})
					}
				}
			}
		}
	}

	// Cursor .cursor/hooks.json and Copilot .github/hooks/*.json. Cursor's docs
	// say these are "stored in version control alongside your code", and Copilot's
	// are read from the repository, so both are committed shell commands running
	// on someone else's machine. disableAllHooks turns the whole Copilot file off,
	// so nothing in it runs.
	if ah := t.AgentHooks; ah != nil && !ah.DisableAllHooks && len(ah.Hooks) > 0 {
		events := make([]string, 0, len(ah.Hooks))
		for e := range ah.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, event := range events {
			for _, h := range ah.Hooks[event] {
				if cmd := h.ShellCommand(); cmd != "" {
					sites = append(sites, commandSite{Label: t.AgentHooksKind + " hooks." + event + " command", File: t.AgentHooksFile, Command: cmd})
				}
			}
		}
	}

	// OpenAI Codex config.toml `notify` — a program (argv) Codex spawns on events.
	if t.Codex != nil && len(t.Codex.Notify) > 0 {
		sites = append(sites, commandSite{Label: "Codex notify command", File: t.CodexFile, Command: strings.Join(t.Codex.Notify, " ")})
	}

	return sites
}

// credentialHelper names a settings key whose command exists to mint or refresh
// authentication material. Its mere presence in a project-scoped settings file is
// suspicious regardless of content (CFG016): a cloned repo should never ship the
// script that produces your credentials.
type credentialHelper struct {
	Key     string
	Command string
}

// credentialHelpers returns the credential-helper keys present (non-empty) in s,
// in a fixed order.
func credentialHelpers(s *parser.Settings) []credentialHelper {
	if s == nil {
		return nil
	}
	var out []credentialHelper
	add := func(key, cmd string) {
		if cmd != "" {
			out = append(out, credentialHelper{Key: key, Command: cmd})
		}
	}
	add("apiKeyHelper", s.StringField("apiKeyHelper"))
	add("awsCredentialExport", s.StringField("awsCredentialExport"))
	add("awsAuthRefresh", s.StringField("awsAuthRefresh"))
	add("gcpAuthRefresh", s.StringField("gcpAuthRefresh"))
	return out
}
