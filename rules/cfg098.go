package rules

import (
	"net/url"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg098 struct{}

var CFG098 = &cfg098{}

func init() { All = append(All, CFG098) }

func (r *cfg098) ID() string { return "CFG098" }

// defaultNPMRegistryHosts are the registries an npm source reaches without the
// author choosing anything. Naming one explicitly is a no-op, and the only npm
// `registry` value in a 292-file sample is exactly "https://registry.npmjs.org",
// so treating any registry as a finding would have been a false positive on the
// one real occurrence.
var defaultNPMRegistryHosts = map[string]bool{
	"registry.npmjs.org": true,
	"www.npmjs.org":      true,
}

// Check flags a committed .claude-plugin/marketplace.json whose plugin entries
// fetch code in a way nothing pins.
//
// The manifest is the supply-chain document of the plugin system: one `source`
// per entry saying where the code comes from when someone installs it. cfgaudit
// audits it author-side, the same footing as .claude-plugin/plugin.json.
//
// Only two cases are reported, and the restraint is deliberate. An unpinned git
// source (github / url / git-subdir with no `sha`) is NOT reported: under 9% of
// committed marketplaces mention any `sha` at all, and upstream documents the
// omission as the intended normal case for internal or actively-developed
// plugins. A finding at that rate would report documented usage, the lesson
// CFG095's build-cache warn already taught this project.
func (r *cfg098) Check(t *Target) []finding.Finding {
	if t == nil || t.Marketplace == nil {
		return nil
	}
	var findings []finding.Finding
	for _, s := range t.Marketplace.ExternalSources() {
		where := "marketplace.json plugin \"" + s.Plugin + "\""
		switch s.Source.Kind() {
		case "archive":
			if strings.TrimSpace(s.Source.SHA256) != "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG098",
				Severity: finding.Error,
				Scope:    t.Scope,
				File:     t.MarketplaceFile,
				Message: where + " installs from the archive " + quoteURL(s.Source.URL) + " with no sha256." +
					" An archive source has no git object model behind it: no history, no ref, nothing that names a fixed revision, so the plugin is whatever the server serves at install time and it can serve something else tomorrow." +
					" Claude Code compares the hash only when the entry declares one, so an absent sha256 means the download is never checked. Upstream documents this as users getting an update \"whenever the hosted zip file's bytes change\"." +
					" Add the sha256 of the archive you published",
			})
		case "command":
			findings = append(findings, finding.Finding{
				RuleID:   "CFG098",
				Severity: finding.Error,
				Scope:    t.Scope,
				File:     t.MarketplaceFile,
				Message: where + " is produced by running a shell command on the installing machine, not fetched from a source anything can pin." +
					" Upstream describes the type as a \"Shell command that prints the absolute path of the plugin directory on stdout (exactly one line) and exits 0\", so the plugin is whatever that command leaves behind when it runs." +
					" The command is shown and accepted at explicit install or update, and it is then re-resolved in the background for as long as it stays byte-identical, so the consent covers the command text rather than what the command does on any later run." +
					modeNote(s.Source.Mode) +
					" Publish the plugin from a source that names a fixed revision instead",
			})
		case "npm":
			registry := strings.TrimSpace(s.Source.Registry)
			if registry == "" || isDefaultNPMRegistry(registry) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG098",
				Severity: finding.Warn,
				Scope:    t.Scope,
				File:     t.MarketplaceFile,
				Message: where + " resolves its npm package from " + quoteURL(registry) +
					" rather than the public registry, so installing it fetches code from a host this manifest chose. That is legitimate for an internal registry and worth a reader's attention either way: confirm the host is one you control, and that it is reachable for everyone you publish to",
			})
		}
	}
	return findings
}

// modeNote spells out the extra property of a link-mode command source: the
// produced directory is used in place rather than copied into the plugin cache,
// so its content stays under the producer's control after the install.
func modeNote(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "link") {
		return " This entry sets mode \"link\", so the produced directory is used where it lies instead of being copied into the plugin cache, and its contents can change after install without any re-resolve."
	}
	return ""
}

// isDefaultNPMRegistry reports whether a registry URL points at the public npm
// registry, comparing hosts so a trailing slash or a path does not matter. A
// value that does not parse as a URL is not the default.
func isDefaultNPMRegistry(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return defaultNPMRegistryHosts[strings.ToLower(u.Hostname())]
}

// quoteURL renders a URL for a message, standing in for an empty value so the
// sentence still reads when the manifest omits it.
func quoteURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return "(no url)"
	}
	return "\"" + u + "\""
}
