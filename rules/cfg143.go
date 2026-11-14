// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg143 struct{}

// CFG143 reports an MCP server, hook, task or `!` block that has npm, npx,
// pnpm, yarn, bun, uv, uvx, pip or pipx fetch packages from a registry or
// index the repository chooses, or with TLS verification turned off (#1683).
var CFG143 = &cfg143{}

func init() { All = append(All, CFG143) }

func (r *cfg143) ID() string { return "CFG143" }

// registrySite is one command as words, with the environment it runs in.
type registrySite struct {
	label, file string
	words       []string
	env         map[string]string
}

// registrySource is one package source a command sets.
type registrySource struct {
	shown, why string
	sev        finding.Severity
}

func (r *cfg143) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	seen := map[string]bool{}
	for _, site := range registrySites(t) {
		sources := packageSources(site)
		if len(sources) == 0 {
			continue
		}
		sev := finding.Warn
		var parts []string
		for _, s := range sources {
			if s.sev == finding.Error {
				sev = finding.Error
			}
			parts = append(parts, "\""+s.shown+"\" ("+s.why+")")
		}
		msg := site.label + " fetches packages with " + strings.Join(parts, ", ") +
			". The code that runs comes from wherever this source serves it, not from the public registry. Remove the option, or pin the package to a hash from a source you control" + userScopeNote(t)
		if key := site.file + "\x00" + msg; !seen[key] {
			seen[key] = true
			findings = append(findings, finding.Finding{RuleID: "CFG143", Severity: sev, File: site.file, Message: msg})
		}
	}
	return findings
}

// registrySites returns every command of t, as words with its environment:
// command sites, VS Code tasks and MCP server launches with their env. A
// VAR=value or env VAR=value prefix is read as environment.
func registrySites(t *Target) []registrySite {
	var sites []registrySite
	for _, s := range commandWordSites(t) {
		words, env := splitEnvPrefix(s.words)
		sites = append(sites, registrySite{label: s.label, file: s.file, words: words, env: env})
	}
	for _, ref := range t.mcpServerRefs() {
		if ref.Server.Command == "" {
			continue
		}
		words, env := splitEnvPrefix(append(shellWords(ref.Server.Command), ref.Server.Args...))
		for k, v := range ref.Server.Env {
			if env == nil {
				env = map[string]string{}
			}
			env[k] = v
		}
		sites = append(sites, registrySite{label: "mcpServers." + ref.Name + " command", file: ref.File, words: words, env: env})
	}
	return sites
}

var envPrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// splitEnvPrefix takes the VAR=value words before a command, and those after
// env, off the words.
func splitEnvPrefix(words []string) ([]string, map[string]string) {
	var env map[string]string
	i := 0
	for i < len(words) {
		w := words[i]
		if i == 0 && executableName(w) == "env" {
			i++
			continue
		}
		if !envPrefixRe.MatchString(w) {
			break
		}
		if env == nil {
			env = map[string]string{}
		}
		k, v, _ := strings.Cut(w, "=")
		env[k] = v
		i++
	}
	return words[i:], env
}

// packageTool returns the package manager words start and the words after it
// that carry its options: the options of npx run up to the package, those of
// pip install run to the end. "" when words start none.
func packageTool(words []string) (kind string, opts []string, stopAtPackage bool) {
	if len(words) == 0 {
		return "", nil, false
	}
	name := executableName(words[0])
	rest := words[1:]
	sub := ""
	if len(rest) > 0 {
		sub = rest[0]
	}
	switch name {
	case "npx", "pnpx", "bunx":
		return "npm", rest, true
	case "npm", "pnpm", "yarn", "bun":
		switch sub {
		case "exec", "x", "dlx":
			return "npm", rest[1:], true
		case "install", "i", "add", "ci", "update", "up":
			return "npm", rest[1:], false
		}
	case "uvx":
		return "py", rest, true
	case "uv":
		if sub == "tool" && len(rest) > 1 && (rest[1] == "run" || rest[1] == "install") {
			return "py", rest[2:], true
		}
		if sub == "pip" || sub == "add" || sub == "sync" || sub == "lock" {
			return "py", rest[1:], false
		}
		if sub == "run" {
			return "py", rest[1:], true
		}
	case "pip", "pip3":
		if sub == "install" || sub == "download" {
			return "py", rest[1:], false
		}
	case "pipx":
		if sub == "run" || sub == "install" {
			return "py", rest[1:], true
		}
	case "python", "python3", "py":
		if len(rest) > 2 && rest[0] == "-m" && (rest[1] == "pip" || rest[1] == "pip3") && (rest[2] == "install" || rest[2] == "download") {
			return "py", rest[3:], false
		}
	}
	if strings.HasPrefix(name, "python3.") && len(rest) > 2 && rest[0] == "-m" && rest[1] == "pip" {
		return "py", rest[3:], false
	}
	return "", nil, false
}

// packageValueFlags are the options of these tools that take the next word
// as their value; others are read as switches, so an unknown option can only
// end the scan early.
var packageValueFlags = map[string]bool{
	"--registry": true, "--package": true, "-p": true, "-c": true, "--call": true, "--cache": true, "--userconfig": true,
	"--index-url": true, "-i": true, "--extra-index-url": true, "--index": true, "--default-index": true, "--find-links": true, "-f": true,
	"--trusted-host": true, "--allow-insecure-host": true, "--from": true, "--with": true, "--with-requirements": true, "--with-editable": true,
	"--python": true, "--index-strategy": true, "--keyring-provider": true, "--exclude-newer": true, "--exclude-newer-package": true,
	"--link-mode": true, "--cache-dir": true, "--config-file": true, "--directory": true, "--project": true, "--constraints": true,
	"--overrides": true, "--prerelease": true, "--resolution": true, "--spec": true, "--pip-args": true, "--target": true, "-t": true,
	"--requirement": true, "-r": true, "--strict-ssl": true,
}

// packageSources returns the sources the site's package manager is pointed at.
func packageSources(site registrySite) []registrySource {
	kind, opts, stopAtPackage := packageTool(site.words)
	if kind == "" {
		return nil
	}
	var out []registrySource
	for i := 0; i < len(opts); i++ {
		w := opts[i]
		if w == "--" {
			break
		}
		if !strings.HasPrefix(w, "-") {
			if stopAtPackage {
				break // the package: what follows is the server's
			}
			continue
		}
		name, value, hasValue := strings.Cut(w, "=")
		if !hasValue && packageValueFlags[name] && i+1 < len(opts) {
			value = opts[i+1]
			i++
		}
		if s, ok := flagSource(kind, name, value); ok {
			out = append(out, s)
		}
	}
	for _, k := range sortedKeys(site.env) {
		if s, ok := envSource(kind, k, site.env[k]); ok {
			out = append(out, s)
		}
	}
	return out
}

// flagSource judges one option of a package manager.
func flagSource(kind, name, value string) (registrySource, bool) {
	shown := name
	if value != "" {
		shown = name + " " + value
	}
	switch {
	case kind == "npm" && (name == "--registry" || scopedRegistryRe.MatchString(name)):
		return judgeIndex(shown, value, false)
	case kind == "npm" && (name == "--strict-ssl" && falseValue(value) || name == "--no-strict-ssl"):
		return registrySource{shown, "turns off TLS verification for the registry", finding.Error}, true
	case kind == "py" && (name == "--index-url" || name == "-i" || name == "--default-index"):
		return judgeIndex(shown, value, false)
	case kind == "py" && (name == "--extra-index-url" || name == "--index"):
		return judgeIndex(shown, indexURL(value), true)
	case kind == "py" && (name == "--find-links" || name == "-f"):
		return judgeIndex(shown, value, false)
	case kind == "py" && (name == "--trusted-host" || name == "--allow-insecure-host"):
		return registrySource{shown, "turns off TLS verification for that host", finding.Error}, true
	}
	return registrySource{}, false
}

// scopedRegistryRe is npm's per-scope registry option: --@org:registry.
var scopedRegistryRe = regexp.MustCompile(`^--@[\w.-]+:registry$`)

// envSource judges one environment variable for the package manager kind.
func envSource(kind, key, value string) (registrySource, bool) {
	shown := key + "=" + value
	k := strings.ToUpper(key)
	switch {
	case kind == "npm" && k == "NPM_CONFIG_REGISTRY":
		return judgeIndex(shown, value, false)
	case kind == "npm" && k == "NPM_CONFIG_STRICT_SSL" && falseValue(value):
		return registrySource{shown, "turns off TLS verification for the registry", finding.Error}, true
	case kind == "py" && (k == "UV_INDEX_URL" || k == "UV_DEFAULT_INDEX" || k == "PIP_INDEX_URL" || k == "UV_FIND_LINKS" || k == "PIP_FIND_LINKS"):
		return judgeEach(shown, value, false)
	case kind == "py" && (k == "UV_EXTRA_INDEX_URL" || k == "UV_INDEX" || k == "PIP_EXTRA_INDEX_URL"):
		return judgeEach(shown, value, true)
	case kind == "py" && (k == "PIP_TRUSTED_HOST" || k == "UV_INSECURE_HOST") && value != "":
		return registrySource{shown, "turns off TLS verification for that host", finding.Error}, true
	}
	return registrySource{}, false
}

func falseValue(v string) bool {
	v = strings.ToLower(strings.Trim(v, `"'`))
	return v == "false" || v == "0" || v == "no"
}

// judgeEach judges a space-separated list of indexes, keeping the worst.
func judgeEach(shown, value string, extra bool) (registrySource, bool) {
	var best registrySource
	found := false
	for _, v := range strings.Fields(value) {
		if s, ok := judgeIndex(shown, indexURL(v), extra); ok && (!found || s.sev == finding.Error) {
			best, found = s, true
		}
	}
	return best, found
}

// indexURL is the URL of a uv --index name=url value.
func indexURL(v string) string {
	if i := strings.Index(v, "="); i > 0 && !strings.Contains(v[:i], "/") {
		return v[i+1:]
	}
	return v
}

// defaultRegistryHosts are the public registries the tools use anyway.
var defaultRegistryHosts = map[string]bool{
	"registry.npmjs.org": true, "registry.npmjs.com": true, "registry.yarnpkg.com": true,
	"pypi.org": true, "pypi.python.org": true, "files.pythonhosted.org": true,
}

// judgeIndex grades a registry or index URL. A value from a variable or a
// prompt (${input:…}, $VAR) is the user's choice and is not reported, nor is
// a default registry.
func judgeIndex(shown, value string, extra bool) (registrySource, bool) {
	value = strings.Trim(value, `"'`)
	if value == "" || strings.Contains(value, "$") {
		return registrySource{}, false
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		if !strings.Contains(value, "://") {
			return registrySource{}, false // a local folder for --find-links
		}
		return registrySource{shown, "a registry the repository chooses", finding.Warn}, true
	}
	host := strings.ToLower(u.Hostname())
	if defaultRegistryHosts[host] {
		return registrySource{}, false
	}
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	switch {
	case strings.EqualFold(u.Scheme, "http") && !loopback:
		return registrySource{shown, "over cleartext http, so anyone on the network path can swap the package", finding.Error}, true
	case extra:
		return registrySource{shown, "an extra index: uv checks it before PyPI and pip takes the highest version from either, so a package of the same name there replaces the real one", finding.Error}, true
	}
	return registrySource{shown, "a registry the repository chooses instead of the public one", finding.Warn}, true
}
