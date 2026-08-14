package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ZedSettings is the subset of Zed's settings.json that cfgaudit reads. Zed
// declares MCP servers under "context_servers" rather than "mcpServers", but the
// entry shape is the same one MCPServer already models: command/args/env for a
// stdio server, url/headers for a remote one.
//
// The file is project-scoped (.zed/settings.json in the repo root) and therefore
// committable. CVE-2025-68433 is the reason it matters: prior to 0.218.2-pre,
// Zed loaded these servers and ran their commands on project open with no user
// interaction beyond opening the folder. The fix added a worktree trust
// mechanism rather than removing the capability, so the surface remains.
type ZedSettings struct {
	ContextServers map[string]MCPServer `json:"context_servers,omitempty"`

	// Terminal, LSP and DAP are the other three fields of ProjectSettingsContent
	// (crates/settings_content/src/project.rs) that name an executable, its argv
	// and its environment. They sit in the struct right next to context_servers,
	// which is what separates them from agent.always_allow_tool_actions and
	// agent.sandbox_permissions: those are absent from the project layer entirely
	// and were rejected in #435 for that reason.
	Terminal *ZedTerminal          `json:"terminal,omitempty"`
	LSP      map[string]ZedLSP     `json:"lsp,omitempty"`
	DAP      map[string]ZedAdapter `json:"dap,omitempty"`
}

// ZedTerminal is ProjectTerminalSettingsContent. Shell decides the program every
// integrated terminal in the project launches.
type ZedTerminal struct {
	Shell *ZedShell         `json:"shell,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
}

// ZedShell is the Shell enum, which serde renders in three shapes because the
// Rust enum is externally tagged with rename_all = "snake_case":
//
//	"system"                                          the default, /etc/passwd
//	{"program": "zsh"}                                a program with no arguments
//	{"with_arguments": {"program": …, "args": […]}}   a program with arguments
//
// Only the last two name a program. "system" is the default and names nothing.
type ZedShell struct {
	System        bool
	Program       string
	Args          []string
	TitleOverride string
}

// UnmarshalJSON decodes the three Shell spellings into one shape.
func (s *ZedShell) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		s.System = str == "system"
		return nil
	}
	var obj struct {
		Program       string `json:"program"`
		WithArguments *struct {
			Program       string   `json:"program"`
			Args          []string `json:"args"`
			TitleOverride string   `json:"title_override"`
		} `json:"with_arguments"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	if obj.WithArguments != nil {
		s.Program, s.Args, s.TitleOverride = obj.WithArguments.Program, obj.WithArguments.Args, obj.WithArguments.TitleOverride
		return nil
	}
	s.Program = obj.Program
	return nil
}

// CommandLine renders the shell as one command string, or "" when the setting
// names no program (the "system" default, or an empty object).
func (s *ZedShell) CommandLine() string {
	if s == nil || s.Program == "" {
		return ""
	}
	return joinZedCommand(s.Program, s.Args)
}

// shellPrograms are the interpreters whose arguments really are a shell command
// line. Everything else Zed launches gets its argv handed straight to execve, so
// a $VAR or a $(…) in those arguments is literal bytes with no shell to expand
// them.
//
// This distinction is not cosmetic. A real config in a 310-file sample passes
// "${projectRoot}#python-lsp" to `nix run`; projectRoot is not a Zed variable
// (it appears nowhere in zed's crates/) and there is no shell, so the string is
// inert. Joining that argv into one line made CFG009 report an interpolation
// that cannot happen.
var shellPrograms = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true, "ash": true, "busybox": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
}

// isShellProgram reports whether a program path names a shell, comparing the
// base name so "/bin/sh" and "sh" agree.
func isShellProgram(program string) bool {
	p := strings.TrimSpace(program)
	if p == "" {
		return false
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return shellPrograms[strings.ToLower(p)]
}

// joinZedCommand renders a launch as the string the command-content rules should
// see. For a shell that is the whole line, because the arguments are a script it
// will interpret. For anything else it is the program alone: its argv goes to
// execve unparsed, so treating it as shell text invents semantics that are not
// there.
func joinZedCommand(program string, args []string) string {
	if !isShellProgram(program) {
		return strings.TrimSpace(program)
	}
	return strings.TrimSpace(strings.Join(append([]string{program}, args...), " "))
}

// ZedLSP is one lsp.<name> entry. Only `binary` is decoded: initialization_options
// and settings are server payloads rather than command sites.
type ZedLSP struct {
	Binary *ZedBinary `json:"binary,omitempty"`
}

// ZedBinary is BinarySettings. IgnoreSystemVersion waives the version check Zed
// would otherwise apply to a language server it manages.
type ZedBinary struct {
	Path                string            `json:"path,omitempty"`
	Arguments           []string          `json:"arguments,omitempty"`
	Env                 map[string]string `json:"env,omitempty"`
	IgnoreSystemVersion *bool             `json:"ignore_system_version,omitempty"`
}

// CommandLine renders the binary and its arguments as one command string.
func (b *ZedBinary) CommandLine() string {
	if b == nil || strings.TrimSpace(b.Path) == "" {
		return ""
	}
	return joinZedCommand(b.Path, b.Arguments)
}

// ZedAdapter is one dap.<name> entry (DapSettingsContent), the debug-adapter
// twin of the LSP binary.
type ZedAdapter struct {
	Binary string            `json:"binary,omitempty"`
	Args   []string          `json:"args,omitempty"`
	Env    map[string]string `json:"env,omitempty"`
}

// CommandLine renders the adapter and its arguments as one command string.
func (a *ZedAdapter) CommandLine() string {
	if a == nil || strings.TrimSpace(a.Binary) == "" {
		return ""
	}
	return joinZedCommand(a.Binary, a.Args)
}

// ParseZedSettings reads a Zed settings.json. Zed's settings are JSONC — it
// ships a heavily commented default — so comments and trailing commas are
// stripped before decoding. A file without any of the modelled keys yields a
// zero-valued struct and no error.
func ParseZedSettings(path string) (*ZedSettings, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var z ZedSettings
	if err := json.Unmarshal(stripJSONC(data), &z); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &z, nil
}

// ZedCommandSite is one command-bearing entry of a Zed settings file, together
// with the label a finding should use and any environment it carries.
type ZedCommandSite struct {
	Label   string
	Command string
	Env     map[string]string
}

// CommandSites returns every executable a committed .zed/settings.json names, in
// a stable order: the terminal shell, then each lsp.<name>.binary, then each
// dap.<name>, both keyed maps sorted by name.
//
// An entry that names no program yields no site. That matters for the default
// terminal shell ("system") and for the many real configs whose lsp entry carries
// only `settings` or `initialization_options`, which are server payloads rather
// than commands.
func (z *ZedSettings) CommandSites() []ZedCommandSite {
	if z == nil {
		return nil
	}
	var sites []ZedCommandSite
	if z.Terminal != nil {
		if cmd := z.Terminal.Shell.CommandLine(); cmd != "" {
			sites = append(sites, ZedCommandSite{Label: "terminal.shell", Command: cmd, Env: z.Terminal.Env})
		} else if len(z.Terminal.Env) > 0 {
			// The environment applies to every terminal whether or not the shell
			// itself is overridden, so it is a site on its own.
			sites = append(sites, ZedCommandSite{Label: "terminal", Env: z.Terminal.Env})
		}
	}
	for _, name := range sortedZedKeys(len(z.LSP), func(f func(string)) {
		for k := range z.LSP {
			f(k)
		}
	}) {
		b := z.LSP[name].Binary
		if cmd := b.CommandLine(); cmd != "" {
			sites = append(sites, ZedCommandSite{Label: "lsp." + name + ".binary", Command: cmd, Env: b.Env})
		} else if b != nil && len(b.Env) > 0 {
			sites = append(sites, ZedCommandSite{Label: "lsp." + name + ".binary", Env: b.Env})
		}
	}
	for _, name := range sortedZedKeys(len(z.DAP), func(f func(string)) {
		for k := range z.DAP {
			f(k)
		}
	}) {
		a := z.DAP[name]
		if cmd := a.CommandLine(); cmd != "" {
			sites = append(sites, ZedCommandSite{Label: "dap." + name, Command: cmd, Env: a.Env})
		} else if len(a.Env) > 0 {
			sites = append(sites, ZedCommandSite{Label: "dap." + name, Env: a.Env})
		}
	}
	return sites
}

// HasCommandSites reports whether the file names any executable or environment,
// so the CLI can skip building a target for a settings file that only carries
// editor preferences.
func (z *ZedSettings) HasCommandSites() bool { return len(z.CommandSites()) > 0 }

// VersionCheckWaivers returns the lsp.<name> entries that set
// binary.ignore_system_version, sorted. Only an explicit true is returned: the
// field defaults to false, and a committed false restates the default.
func (z *ZedSettings) VersionCheckWaivers() []string {
	if z == nil {
		return nil
	}
	var out []string
	for name, cfg := range z.LSP {
		if cfg.Binary != nil && cfg.Binary.IgnoreSystemVersion != nil && *cfg.Binary.IgnoreSystemVersion {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// sortedZedKeys collects map keys through the supplied iterator and sorts them,
// so findings come out in a stable order regardless of map iteration.
func sortedZedKeys(n int, each func(func(string))) []string {
	out := make([]string, 0, n)
	each(func(k string) { out = append(out, k) })
	sort.Strings(out)
	return out
}
