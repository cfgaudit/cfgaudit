package rules

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg020 struct{}

var CFG020 = &cfg020{}

func init() { All = append(All, CFG020) }

func (r *cfg020) ID() string { return "CFG020" }

// envCodeExecVar describes an env var that runs attacker-controlled code when set
// on an MCP server process. A presence var (valueRe nil) is dangerous with any
// non-empty value; a value-gated var only when the value carries a code-loading
// flag — these have legitimate non-code uses (NODE_OPTIONS=--max-old-space-size,
// RUBYOPT=-W0) so blindly flagging them would false-positive.
type envCodeExecVar struct {
	valueRe   *regexp.Regexp
	valueFn   func(string) bool
	mechanism string
}

const linkerMechanism = "the dynamic linker loads this shared library into the process before its own code runs"

var (
	// Node loads a module at startup via --require/--import/-r (but not benign
	// flags like --max-old-space-size); Ruby via -r; Perl via -M/-m.
	nodeRequireRe = regexp.MustCompile(`(?i)(^|\s)(--require|--import|-r)(\s|=|$)`)
	rubyRequireRe = regexp.MustCompile(`(?i)(^|\s)-r`)
	perlModuleRe  = regexp.MustCompile(`(?i)(^|\s)-[Mm]`)

	// The JVM reads its option variables at startup. Heap and property flags
	// (-Xmx, -Dfile.encoding) are the common, harmless use; an agent, a boot
	// class path or an OnError / OnOutOfMemoryError command loads or runs code.
	jvmCodeRe = regexp.MustCompile(`(?i)(^|\s)(-javaagent:|-agentpath:|-agentlib:|-Xbootclasspath|-XX:\+?OnError=|-XX:OnOutOfMemoryError=)`)

	// codeExecEnvVars maps an upper-cased env key to how it injects code. Covers
	// dynamic-linker injection (LD_*/DYLD_*) and the interpreter startup vectors
	// of CVE-2026-44995 (NODE_OPTIONS/BASH_ENV/RUBYOPT/PYTHONSTARTUP/PERL5OPT).
	//
	// ZDOTDIR is BASH_ENV's zsh twin and was added alongside CFG107: upstream
	// Codex strips exactly the pair ZDOTDIR/BASH_ENV from a project config's
	// shell environment, which is the clearest statement available that the two
	// belong together. It reaches CFG020's MCP surface as well, where it was
	// measured first: of the committed settings.json files carrying both ZDOTDIR
	// and mcpServers, none puts ZDOTDIR in a server env (two are Zed terminal
	// settings, one is an i18n locale file), and no committed .mcp.json carries
	// the key at all.
	codeExecEnvVars = map[string]envCodeExecVar{
		"LD_PRELOAD":            {mechanism: linkerMechanism},
		"LD_LIBRARY_PATH":       {mechanism: linkerMechanism},
		"LD_AUDIT":              {mechanism: linkerMechanism},
		"DYLD_INSERT_LIBRARIES": {mechanism: linkerMechanism},
		"DYLD_LIBRARY_PATH":     {mechanism: linkerMechanism},
		"BASH_ENV":              {mechanism: "bash sources this file as its non-interactive startup script"},
		"ZDOTDIR":               {mechanism: "zsh reads its startup files (.zshenv, .zshrc) from this directory instead of the home directory"},
		"PYTHONSTARTUP":         {mechanism: "Python executes this script at interpreter startup"},
		"NODE_OPTIONS":          {valueRe: nodeRequireRe, mechanism: "Node.js loads a module at startup via --require/--import"},
		"RUBYOPT":               {valueRe: rubyRequireRe, mechanism: "Ruby requires a module at interpreter startup via -r"},
		"PERL5OPT":              {valueRe: perlModuleRe, mechanism: "Perl loads a module at startup via -M/-m"},
		// Added for #610. These are among the variables Claude Code's own
		// dangerous-environment list carries (2.1.288 binary), and
		// CVE-2026-101884 (GHSA-hf34-gmq4-h679) is an agent environment sanitizer
		// that missed DOTNET_STARTUP_HOOKS, JAVA_TOOL_OPTIONS and GIT_CONFIG_*.
		"DOTNET_STARTUP_HOOKS": {mechanism: "the .NET runtime loads these assemblies and runs their startup hook before the program's Main"},
		"JAVA_TOOL_OPTIONS":    {valueRe: jvmCodeRe, mechanism: "every JVM reads these options at startup, and -javaagent/-agentpath/-agentlib/-Xbootclasspath/-XX:OnError load or run code"},
		"_JAVA_OPTIONS":        {valueRe: jvmCodeRe, mechanism: "every JVM reads these options at startup, and -javaagent/-agentpath/-agentlib/-Xbootclasspath/-XX:OnError load or run code"},
		"JDK_JAVA_OPTIONS":     {valueRe: jvmCodeRe, mechanism: "the java launcher reads these options at startup, and -javaagent/-agentpath/-agentlib/-Xbootclasspath/-XX:OnError load or run code"},
		"GIT_SSH_COMMAND":      {valueFn: gitSSHRunsCode, mechanism: "git runs this command instead of ssh for every remote operation over SSH"},
	}

	// sshCommandOptionRe matches the ssh options that run a local command of
	// their own, so `ssh -o ProxyCommand=...` counts even though the program is
	// ssh.
	sshCommandOptionRe = regexp.MustCompile(`(?i)(ProxyCommand|LocalCommand|KnownHostsCommand)`)

	// gitConfigKeyRe matches git config keys whose value is a command git runs,
	// or a file git reads more configuration from. GIT_CONFIG_KEY_<n> naming one
	// of these lets an environment block choose that command.
	gitConfigKeyRe    = regexp.MustCompile(`(?i)^(core\.(sshcommand|fsmonitor|hookspath|pager|editor|askpass|gitproxy)|credential\.(.+\.)?helper|sequence\.editor|diff\.external|diff\..+\.(textconv|command)|merge\..+\.driver|filter\..+\.(clean|smudge|process)|gpg\.(.+\.)?program|pager\..+|alias\..+|uploadpack\.packobjectshook|include\.path|includeif\..+\.path)$`)
	gitConfigKeyVarRe = regexp.MustCompile(`(?i)^GIT_CONFIG_KEY_([0-9]+)$`)
)

// gitSSHRunsCode reports whether a GIT_SSH_COMMAND value runs something other
// than plain ssh: a different program, or ssh with an option that runs a local
// command. `ssh -i ./deploy_key -o IdentitiesOnly=yes` is the ordinary use and
// stays silent.
func gitSSHRunsCode(v string) bool {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return false
	}
	prog := strings.ToLower(fields[0])
	if i := strings.LastIndexAny(prog, `/\`); i >= 0 {
		prog = prog[i+1:]
	}
	if prog != "ssh" && prog != "ssh.exe" {
		return true
	}
	return sshCommandOptionRe.MatchString(v)
}

// gitConfigValueIsCommand reports whether a git config value names something
// git would run. An empty value resets the key (`credential.helper=` clears the
// helper list, the common use in real settings), and a boolean switches a
// feature such as core.fsmonitor off or to its built-in daemon.
func gitConfigValueIsCommand(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false", "true", "0", "1", "no", "yes", "off", "on":
		return false
	}
	return true
}

// envLookup returns env[key], matching the key case-insensitively the way the
// variable tables above do.
func envLookup(env map[string]string, key string) string {
	if v, ok := env[key]; ok {
		return v
	}
	for k, v := range env {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// envHit is one code-execution variable found in an environment block.
type envHit struct {
	Key       string
	Mechanism string
}

// codeExecEnvHits returns the code-execution variables an environment block
// sets, sorted by key. gateSearchPath applies the CFG107 rule to
// LD_LIBRARY_PATH / DYLD_LIBRARY_PATH (reported only with a relative or empty
// entry), for surfaces that prepare ordinary build and test shells.
//
// GIT_CONFIG_KEY_<n> is reported when GIT_CONFIG_COUNT makes the pair live
// (git ignores pairs at or above the count) and the key it names is one whose
// value git runs as a command. Measured on Claude Code 2.1.288: a project
// settings env with GIT_CONFIG_COUNT=1, GIT_CONFIG_KEY_0=core.fsmonitor and a
// command as GIT_CONFIG_VALUE_0 ran that command on a `git status` in a hook.
func codeExecEnvHits(env map[string]string, gateSearchPath bool) []envHit {
	var hits []envHit
	count := -1
	for k, v := range env {
		if strings.EqualFold(k, "GIT_CONFIG_COUNT") {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				count = n
			}
		}
	}
	for k, v := range env {
		if strings.TrimSpace(v) == "" {
			continue
		}
		upper := strings.ToUpper(k)
		if m := gitConfigKeyVarRe.FindStringSubmatch(k); m != nil {
			n, err := strconv.Atoi(m[1])
			if err == nil && n < count && gitConfigKeyRe.MatchString(strings.TrimSpace(v)) &&
				gitConfigValueIsCommand(envLookup(env, "GIT_CONFIG_VALUE_"+m[1])) {
				hits = append(hits, envHit{Key: k, Mechanism: "together with GIT_CONFIG_COUNT this sets the git config key " + strings.TrimSpace(v) + ", whose value git runs as a command"})
			}
			continue
		}
		spec, ok := codeExecEnvVars[upper]
		if !ok {
			continue
		}
		if spec.valueRe != nil && !spec.valueRe.MatchString(v) {
			continue
		}
		if spec.valueFn != nil && !spec.valueFn(v) {
			continue
		}
		if gateSearchPath && searchPathEnvVars[upper] && !hasRelativeEntry(v) {
			continue
		}
		hits = append(hits, envHit{Key: k, Mechanism: spec.mechanism})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Key < hits[j].Key })
	return hits
}

// Check flags MCP servers whose env injects code into the server process at
// startup — a dynamic-linker shared library, or an interpreter startup
// file/flag (CVE-2026-44995). Covers both settings.json mcpServers and the
// project .mcp.json.
func (r *cfg020) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		for _, hit := range codeExecEnvHits(ref.Server.Env, false) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG020",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + ".env sets " + hit.Key + " — " + hit.Mechanism +
					", running attacker-controlled code when the server process starts; remove it",
			})
		}
	}
	return findings
}
