package rules

import (
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg106 struct{}

// CFG106 reports a committed Codex config that grants the agent browser or
// desktop-application access.
var CFG106 = &cfg106{}

func init() { All = append(All, CFG106) }

func (r *cfg106) ID() string { return "CFG106" }

// Check reports [browser_use] and [computer_use] values set to "allow".
//
// The value type is an enum of exactly allow and deny, so "allow" is the only
// weakening direction and a "deny" is hardening. Neither table is on Codex's
// PROJECT_LOCAL_CONFIG_DENYLIST, and neither is touched by the project-layer
// sanitizer, whose removals are confined to parts of the features table, two TUI
// permission-mode keybindings, and shell_environment_policy under the credential
// broker. The keybinding removal carries the comment "Repository contents must
// not turn an ordinary key into a permission increase" — a line upstream draws
// around two keybindings while leaving these tables readable from the same file.
//
// Verified at the artifact against codex 0.150.0-alpha.7: a committed
// .codex/config.toml in a trusted directory comes back through the app server's
// config/read carrying the repository's own values, and contributes nothing in
// an untrusted one, the same folder-trust caveat CFG063 and CFG064 carry.
//
// No version gate is needed. Codex 0.149.0 has no such field in its config
// surface, so on that build there is no value to read and the rule is silent by
// construction; on a build that has it, the value applies.
func (r *cfg106) Check(t *Target) []finding.Finding {
	if t == nil || t.Codex == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG106",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CodexFile,
			Message:  msg + userScopeNote(t),
		})
	}

	if b := t.Codex.BrowserUse; b != nil {
		if b.AllowHistoryAccess != nil && *b.AllowHistoryAccess {
			add(finding.Warn, "browser_use.allow_history_access is true — the agent may read the browser's history, which is a record of everywhere the person has been rather than anything this repository needs. Remove the key and let each user decide")
		}
		checkOrigin := func(where string, p *parser.CodexBrowserOriginPolicy) {
			if p == nil {
				return
			}
			if parser.CodexAllows(p.FullCDPAccess) {
				add(finding.Error, where+".full_cdp_access is \"allow\" — full Chrome DevTools Protocol access to that origin, which is script execution, cookie and storage access in the browser session, granted by a file in the repository rather than by the person browsing")
			}
			for _, f := range []struct{ key, value, what string }{
				{"access", p.Access, "the agent may drive that origin"},
				{"downloads", p.Downloads, "the agent may download from that origin"},
				{"uploads", p.Uploads, "the agent may upload to that origin, which is an exfiltration path out of the machine"},
			} {
				if parser.CodexAllows(f.value) {
					add(finding.Warn, where+"."+f.key+" is \"allow\" — "+f.what+" with no prompt, decided by the repository")
				}
			}
		}
		checkOrigin("browser_use.default_origin_policy", b.DefaultOriginPolicy)
		for _, origin := range sortedOrigins(b.Origins) {
			policy := b.Origins[origin]
			checkOrigin("browser_use.origins.\""+origin+"\"", &policy)
		}
	}

	if c := t.Codex.ComputerUse; c != nil {
		if parser.CodexAllows(c.DefaultAppAccess) {
			add(finding.Error, "computer_use.default_app_access is \"allow\" — every desktop application on the machine may be driven by the agent, chosen by a committed file. Name the applications the project needs, or leave the key out")
		}
		if m := c.Macos; m != nil {
			for _, id := range sortedStringKeys(m.BundleIDs) {
				if parser.CodexAllows(m.BundleIDs[id]) {
					add(finding.Warn, "computer_use.macos.bundle_ids.\""+id+"\" is \"allow\" — the repository grants the agent control of that application")
				}
			}
		}
		if w := c.Windows; w != nil {
			for _, id := range sortedStringKeys(w.AUMIDs) {
				if parser.CodexAllows(w.AUMIDs[id]) {
					add(finding.Warn, "computer_use.windows.aumids.\""+id+"\" is \"allow\" — the repository grants the agent control of that application")
				}
			}
			for _, exe := range w.Exes {
				if !parser.CodexAllows(exe.Access) {
					continue
				}
				name := strings.TrimSpace(exe.BinaryName)
				if name == "" {
					name = strings.TrimSpace(exe.ProductName)
				}
				add(finding.Warn, "computer_use.windows.exes entry \""+name+"\" is \"allow\" — the repository grants the agent control of that application")
			}
		}
	}
	return findings
}

func sortedOrigins(m map[string]parser.CodexBrowserOrigin) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
