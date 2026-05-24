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
	{allowCat{finding.Error, "unrestricted outbound network — can exfiltrate data or fetch and run remote payloads"},
		[]string{"curl", "wget"}},
	{allowCat{finding.Error, "privilege escalation"},
		[]string{"sudo", "doas"}},
	{allowCat{finding.Error, "runs arbitrary remote packages"},
		[]string{"npx", "bunx"}},
	{allowCat{finding.Error, "a shell interpreter — open-ended args grant arbitrary command execution"},
		[]string{"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "powershell", "pwsh", "cmd"}},
	{allowCat{finding.Error, "a Windows living-off-the-land binary used to download and execute remote code"},
		[]string{"certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"}},
	{allowCat{finding.Warn, "a language interpreter — open-ended args can execute arbitrary code"},
		[]string{"python", "python3", "perl", "ruby", "node", "deno"}},
	{allowCat{finding.Warn, "executes arbitrary commands through flags (e.g. find -exec, sed e///, awk system(), env/xargs, tar --checkpoint-action, git -c)"},
		[]string{"find", "sed", "awk", "gawk", "xargs", "env", "tar", "git"}},
	{allowCat{finding.Warn, "enables remote command execution / lateral movement"},
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
	if cat, ok := dangerousAllowLookup[tok]; ok {
		return tok, cat, true
	}
	return "", allowCat{}, false
}
