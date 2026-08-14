package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg023 struct{}

var CFG023 = &cfg023{}

func init() { All = append(All, CFG023) }

func (r *cfg023) ID() string { return "CFG023" }

// allowCat describes why a binary is dangerous to allow-list with open-ended args.
type allowCat struct {
	sev    finding.Severity
	reason string
}

// dangerousAllowGroups maps binaries to the risk they carry when granted in
// permissions.allow with a wildcard. Standard build/dev tooling (npm, pip,
// docker, make, go, cargo, …) is deliberately excluded: allow-listing those with
// args is normal practice, and CFG001 already covers the catch-all Bash(*).
var dangerousAllowGroups = []struct {
	cat   allowCat
	names []string
}{
	{allowCat{finding.Error, "an unrestricted outbound network channel — it can exfiltrate data or fetch and run remote payloads"},
		[]string{"curl", "wget"}},
	{allowCat{finding.Error, "privilege escalation"},
		[]string{"sudo", "doas"}},
	{allowCat{finding.Error, "a runner for arbitrary remote packages"},
		[]string{"npx", "bunx"}},
	{allowCat{finding.Error, "a shell interpreter — open-ended args grant arbitrary command execution"},
		[]string{"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "powershell", "pwsh", "cmd"}},
	{allowCat{finding.Error, "a Windows living-off-the-land binary used to download and execute remote code"},
		[]string{"certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"}},
	{allowCat{finding.Warn, "a language interpreter — open-ended args can execute arbitrary code"},
		[]string{"python", "python3", "perl", "ruby", "node", "deno"}},
	{allowCat{finding.Warn, "exec-capable through its flags (e.g. find -exec, sed e///, awk system(), env/xargs, tar --checkpoint-action)"},
		[]string{"find", "sed", "awk", "gawk", "xargs", "env", "tar"}},
	{allowCat{finding.Warn, "a remote-execution and lateral-movement tool"},
		[]string{"ssh", "scp", "rsync"}},
}

var dangerousAllowLookup = func() map[string]allowCat {
	m := map[string]allowCat{}
	for _, g := range dangerousAllowGroups {
		for _, n := range g.names {
			m[n] = g.cat
		}
	}
	return m
}()

var bashAllowRe = regexp.MustCompile(`^Bash\((.*)\)$`)

// gitExecSubcmds maps a git subcommand to the way it runs an arbitrary command
// through its own arguments. git's headline exec vector sits in the flags that
// come *before* the subcommand (`git -c core.pager=<cmd> log`), so an allow entry
// that pins a subcommand only carries risk when that subcommand brings a vector of
// its own: Bash(git rebase:*) does, Bash(git add:*) does not (#507).
//
// Every vector below was reproduced against git 2.43, except send-email, which
// ships in a separate package and is taken from git's documentation. Two vectors
// that look plausible are deliberately absent because they do not hold: `git
// mergetool` has no --extcmd (only difftool does), and an `ext::<cmd>` remote URL
// is refused by default ("transport 'ext' not allowed"), which is what would
// otherwise make every remote-taking subcommand exec-capable.
var gitExecSubcmds = map[string]string{
	"rebase":        "git rebase -x <cmd> runs a command per commit",
	"bisect":        "git bisect run <cmd> runs a command per revision",
	"submodule":     "git submodule foreach <cmd> runs a command per submodule",
	"filter-branch": "git filter-branch --tree-filter <cmd> runs a command per commit",
	"difftool":      "git difftool --extcmd=<cmd> runs a command per changed file",
	"grep":          "git grep -O<cmd> runs a command over the matching files",
	"clone":         "git clone --upload-pack=<cmd> runs a command, and --template=<dir> installs hooks that run during the clone",
	"fetch":         "git fetch --upload-pack=<cmd> runs a command",
	"pull":          "git pull --upload-pack=<cmd> runs a command",
	"ls-remote":     "git ls-remote --upload-pack=<cmd> runs a command",
	"push":          "git push --receive-pack=<cmd> runs a command",
	"archive":       "git archive --remote=<repo> --exec=<cmd> runs a command",
	"config":        "git config writes alias.x=!<cmd> or core.pager=<cmd>, which a later git run executes",
	"daemon":        "git daemon --access-hook=<cmd> runs a command per request",
	"instaweb":      "git instaweb --httpd=<cmd> runs a command",
	"send-email":    "git send-email --sendmail-cmd=<cmd> runs a command",
}

// gitFirstSubcmd returns the lowercased first token after "git" in an allow
// pattern's inner text (e.g. "git status:*" → "status"). An unscoped entry
// ("git *", "git:*") yields ""; an entry that starts with a flag ("git -c …")
// yields that flag.
func gitFirstSubcmd(inner string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(inner), "git"))
	if i := strings.IndexAny(rest, " \t:*"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

// gitAllowEntry classifies a Bash(git …*) allow entry. An entry that leaves the
// pre-subcommand flag position open — unscoped (Bash(git *), Bash(git:*)) or
// already spelling a flag (Bash(git -c …:*)) — reaches git's exec-capable flags
// and is always reported. An entry that pins a subcommand is reported only when
// that subcommand carries a vector of its own.
func gitAllowEntry(inner string) (string, allowCat, bool) {
	sub := gitFirstSubcmd(inner)
	if sub == "" || strings.HasPrefix(sub, "-") {
		return "git", allowCat{finding.Warn,
			"exec-capable through the flags it takes before a subcommand (git -c core.pager=<cmd>, git -c alias.x=!<cmd>)"}, true
	}
	vector, ok := gitExecSubcmds[sub]
	if !ok {
		return "", allowCat{}, false
	}
	return "git " + sub, allowCat{finding.Warn, "exec-capable through its own arguments (" + vector + ")"}, true
}

// Check flags permissions.allow entries that grant a command which — when allowed
// with open-ended arguments — yields arbitrary code execution, unrestricted
// network access, privilege escalation, or lateral movement. Exactly-pinned
// commands (no wildcard) are exempt: the user spelled out precisely what may run.
func (r *cfg023) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		bin, cat, ok := dangerousAllowBinary(entry)
		if !ok {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG023",
			Severity: cat.sev,
			File:     t.SettingsFile,
			Message: "permissions.allow grants \"" + entry + "\" — \"" + bin + "\" is " + cat.reason +
				"; allow only an exact command (no wildcard) instead" + userScopeNote(t),
		})
	}
	return findings
}

// dangerousAllowBinary returns the dangerous binary and its category for a
// Bash(...) allow entry that grants wildcard arguments. Returns ok=false for
// non-Bash entries, exactly-pinned commands (no `*`), and binaries not on the
// list (including the bare `*`, which CFG001 owns).
func dangerousAllowBinary(entry string) (string, allowCat, bool) {
	m := bashAllowRe.FindStringSubmatch(strings.TrimSpace(entry))
	if m == nil {
		return "", allowCat{}, false
	}
	inner := strings.TrimSpace(m[1])
	if !strings.Contains(inner, "*") {
		return "", allowCat{}, false
	}
	tok := inner
	if i := strings.IndexAny(tok, " \t:"); i >= 0 {
		tok = tok[:i]
	}
	if i := strings.LastIndexAny(tok, `/\`); i >= 0 {
		tok = tok[i+1:]
	}
	tok = strings.ToLower(strings.TrimSpace(tok))
	// git is judged per subcommand rather than per binary: the pin decides which
	// of git's exec vectors the entry can still reach.
	if tok == "git" {
		return gitAllowEntry(inner)
	}
	if cat, ok := dangerousAllowLookup[tok]; ok {
		return tok, cat, true
	}
	return "", allowCat{}, false
}
