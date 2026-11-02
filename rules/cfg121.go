// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg121 struct{}

var CFG121 = &cfg121{}

func init() { All = append(All, CFG121) }

func (r *cfg121) ID() string { return "CFG121" }

// NestedRepo is a committed directory that looks like a bare git repository:
// HEAD and config files next to objects/ and refs/ (#994).
type NestedRepo struct {
	Dir, ConfigFile, Config string
}

// gitCommandKeyRe matches a git config key whose value git runs as a command:
// core.fsmonitor, core.hooksPath (a directory of hooks), core.sshCommand,
// core.pager, core.editor, core.askPass, diff.external, sequence.editor,
// credential.helper, the clean/smudge/process filters and
// uploadpack.packObjectsHook. Section and key names are case-insensitive in
// git; a subsection ([filter "lfs"]) is kept in the name.
var gitCommandKeyRe = regexp.MustCompile(`(?i)^(?:core\.(?:fsmonitor|hookspath|sshcommand|pager|editor|askpass)|diff\.external|sequence\.editor|credential\.helper|filter\..+\.(?:clean|smudge|process)|uploadpack\.packobjectshook)$`)

// gitForges are hosts a lookalike submodule URL imitates.
var gitForges = []string{"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}

// Check reports committed git metadata that makes an agent's git call run a
// command or fetch from an impostor (#994). An agent runs git on its own:
// inside a committed bare repository, git reads that repository's config, so
// a core.fsmonitor there runs on the next `git status` (CVE-2026-45033,
// CVE-2026-72718); and `git submodule update` fetches whatever .gitmodules
// names (CVE-2026-47284).
func (r *cfg121) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	for _, repo := range t.NestedRepos {
		keys := gitCommandKeys(repo.Config)
		if len(keys) > 0 {
			out = append(out, finding.Finding{RuleID: "CFG121", Severity: finding.Error, File: repo.ConfigFile,
				Message: "a committed bare git repository sets " + quoteList(keys) + ", which git runs as a command — an agent that runs git inside the directory, or lets git find it, runs it. A working tree has no use for a nested repository; remove the directory, or keep a fixture as an archive the tests unpack"})
			continue
		}
		out = append(out, finding.Finding{RuleID: "CFG121", Severity: finding.Warn, File: repo.ConfigFile,
			Message: "a committed directory is a bare git repository (HEAD, config, objects/, refs/) — git reads its config when it runs inside the directory, so a later change to that config runs on an agent's next git call. Remove it, or keep a fixture as an archive the tests unpack"})
	}
	for _, sub := range gitModuleURLs(t.GitModules) {
		if why := submoduleURLRisk(sub.url); why != "" {
			out = append(out, finding.Finding{RuleID: "CFG121", Severity: finding.Warn, File: t.GitModulesFile, Line: sub.line, Col: 1,
				Message: ".gitmodules submodule URL " + sub.url + " " + why + " — an agent that runs `git submodule update` fetches it without asking. Point the submodule at the real host over HTTPS"})
		}
	}
	return out
}

// gitCommandKeys returns the command-running keys a git config sets, as
// section.key, in file order.
func gitCommandKeys(cfg string) []string {
	var out []string
	section := ""
	for _, line := range strings.Split(cfg, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if strings.HasPrefix(l, "[") {
			if end := strings.IndexByte(l, ']'); end > 0 {
				head := strings.Fields(l[1:end])
				section = ""
				if len(head) > 0 {
					section = head[0]
					if len(head) > 1 {
						section += "." + strings.Trim(strings.Join(head[1:], " "), `"`)
					}
				}
			}
			continue
		}
		key, val, _ := strings.Cut(l, "=")
		key, val = strings.TrimSpace(key), strings.ToLower(strings.TrimSpace(val))
		name := section + "." + key
		if !gitCommandKeyRe.MatchString(name) {
			continue
		}
		// core.fsmonitor = true / false selects the built-in daemon.
		if strings.EqualFold(name, "core.fsmonitor") && (val == "true" || val == "false" || val == "") {
			continue
		}
		out = append(out, name)
	}
	return out
}

type gitModuleURL struct {
	url  string
	line int
}

// gitModuleURLs returns the url values of a .gitmodules file.
func gitModuleURLs(s string) []gitModuleURL {
	var out []gitModuleURL
	for i, line := range strings.Split(s, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "url") {
			out = append(out, gitModuleURL{strings.Trim(strings.TrimSpace(val), `"`), i + 1})
		}
	}
	return out
}

// submoduleURLRisk says what is wrong with a submodule URL, or "".
func submoduleURLRisk(u string) string {
	lower := strings.ToLower(u)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "git://") {
		return "is fetched without encryption, so anyone on the network path can serve other code"
	}
	host := submoduleHost(u)
	if host == "" {
		return ""
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return "has a host with non-ASCII characters (" + host + "), the shape of a homoglyph lookalike"
		}
	}
	if strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--") {
		return "has a punycode host (" + host + "), the shape of a homoglyph lookalike"
	}
	for _, forge := range gitForges {
		if host == forge || strings.HasSuffix(host, "."+forge) {
			return ""
		}
	}
	for _, forge := range gitForges {
		if strings.HasPrefix(host, forge+".") || levenshtein(host, forge) <= 2 {
			return "has the host " + host + ", a lookalike of " + forge
		}
	}
	return ""
}

// submoduleHost returns the lowercased host of an https, ssh or scp-like git
// URL ("git@github.com:org/repo.git").
func submoduleHost(u string) string {
	if strings.Contains(u, "://") {
		p, err := url.Parse(u)
		if err != nil {
			return ""
		}
		return strings.ToLower(p.Hostname())
	}
	if at := strings.IndexByte(u, '@'); at >= 0 {
		if colon := strings.IndexByte(u[at:], ':'); colon > 0 {
			return strings.ToLower(u[at+1 : at+colon])
		}
	}
	return ""
}
