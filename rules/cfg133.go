// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg133 struct{}

// CFG133 reports a committed VS Code settings file that relaxes the agent
// sandbox (#751).
var CFG133 = &cfg133{}

func init() { All = append(All, CFG133) }

func (r *cfg133) ID() string { return "CFG133" }

// The chat.agent.sandbox.* settings of VS Code 1.145.2. All are registered
// with `restricted: true` and no scope (ConfigurationScope.WINDOW), so VS Code
// applies a workspace value once the folder is trusted, and a workspace value
// wins over the user's own (terminalChatAgentToolsConfiguration.ts,
// platform/sandbox/common/settings.ts). Only a managed policy outranks it.
const (
	sandboxEnabledKey      = "chat.agent.sandbox.enabled"
	sandboxAdvancedRuntime = "chat.agent.sandbox.advanced.runtime"
	sandboxUserPathsKey    = "chat.agent.sandbox.fileSystem.userConfiguredPaths"
	localNetworkKey        = "chat.agent.sandbox.network.allowLocalNetwork"
	// sandboxCredentialEnvVars maps a variable name to the HTTPS hosts the
	// sandbox proxy injects its value at (VS Code 1.146.0, #1637).
	sandboxCredentialEnvVars = "chat.agent.sandbox.credentials.envVars"
)

// sandboxBoolKeys are the boolean sandbox settings, each with the value that
// loosens the sandbox and whether that value is also the default. A default
// value in a workspace file changes nothing for a user who kept the default,
// but it overrides a user who chose the stricter value, so it is `info`.
var sandboxBoolKeys = []struct {
	key       string
	loose     bool
	isDefault bool
	what      string
}{
	{"chat.agent.sandbox.allowUnsandboxedCommands", true, true, "lets the agent run a command outside the sandbox"},
	{"chat.agent.sandbox.network.allowNetwork", true, true, "turns off the sandbox's network restrictions for terminal commands"},
	{localNetworkKey, true, false, "lets sandboxed commands reach hosts on the local network"},
	{"chat.agent.sandbox.mcpServers", false, false, "takes MCP servers out of the sandbox"},
	{"chat.agent.sandbox.lspServers", false, false, "takes language servers out of the sandbox"},
	{"chat.agent.sandbox.credentials.authenticategit", true, true, "hands the user's git credentials to sandboxed commands"},
	{"chat.agent.sandbox.credentials.authenticategh", true, true, "hands the user's GitHub CLI credentials to sandboxed commands"},
	{"chat.agent.sandbox.fileSystem.allowDevToolAccess", true, true, "gives sandboxed commands access to developer tool folders"},
}

// sandboxFileSystemKeys are the deprecated per-OS filesystem settings, which
// the terminal sandbox still reads (terminalSandboxEngine.ts, 1.145.2).
var sandboxFileSystemKeys = []string{
	"chat.agent.sandbox.fileSystem.linux",
	"chat.agent.sandbox.fileSystem.mac",
}

// Check reports each sandbox setting of a committed VS Code settings file
// that loosens the sandbox.
func (r *cfg133) Check(t *Target) []finding.Finding {
	if t == nil || t.VSCodeSettings == nil || t.Scope == finding.ScopeUser {
		return nil
	}
	s := t.VSCodeSettings
	var out []finding.Finding
	add := func(sev finding.Severity, msg string) {
		out = append(out, finding.Finding{RuleID: "CFG133", Severity: sev, Scope: t.Scope, File: t.VSCodeSettingsFile, Message: msg})
	}
	const applied = " VS Code applies this workspace value once the folder is trusted, over the user's own setting"

	// sandboxSettingsReader.ts reads a boolean false as "off".
	if v, _ := s.StringField(sandboxEnabledKey); v == "off" || isJSONFalse(s, sandboxEnabledKey) {
		add(finding.Warn, sandboxEnabledKey+" is off: it switches off the agent's terminal sandbox for a user who turned it on."+applied+". Remove the key")
	}
	for _, k := range sandboxBoolKeys {
		val, present := s.BoolField(k.key)
		if !present || val != k.loose {
			continue
		}
		sev, note := finding.Warn, ""
		switch {
		case k.isDefault:
			sev, note = finding.Info, " This is the default, so it matters only for a user who chose the stricter value."
		case k.key == localNetworkKey:
			// VS Code's own description: Windows needs it whenever a proxy,
			// host rules or credential masking is in use.
			sev, note = finding.Info, " Windows needs it when a proxy, host rules or credential masking is in use."
		}
		add(sev, k.key+" is "+strconv.FormatBool(val)+": it "+k.what+"."+applied+"."+note+" Remove the key and leave the choice to the user")
	}
	for _, key := range sandboxFileSystemKeys {
		obj, ok := s.ObjectField(key)
		if !ok {
			continue
		}
		for _, p := range outsidePaths(obj["allowWrite"]) {
			if !tempPath(p) {
				add(finding.Warn, key+".allowWrite names \""+p+"\", outside the repository: sandboxed terminal commands may write it."+applied+". Remove the entry")
			}
		}
		for _, p := range outsidePaths(obj["allowRead"]) {
			add(readSeverity(p), key+".allowRead names \""+p+"\", outside the repository: sandboxed terminal commands may read it, though the sandbox keeps the home directory closed otherwise."+applied+". Remove the entry")
		}
	}
	if obj, ok := s.ObjectField(sandboxUserPathsKey); ok {
		for _, p := range outsidePaths(obj["readwritePaths"]) {
			if !tempPath(p) {
				add(finding.Warn, sandboxUserPathsKey+".readwritePaths names \""+p+"\", outside the repository: the agent host sandbox lets the agent write it."+applied+". Remove the entry")
			}
		}
		for _, p := range outsidePaths(obj["readonlyPaths"]) {
			add(readSeverity(p), sandboxUserPathsKey+".readonlyPaths names \""+p+"\", outside the repository: the agent host sandbox lets the agent read it."+applied+". Remove the entry")
		}
	}
	if obj, ok := s.ObjectField(sandboxCredentialEnvVars); ok {
		names := make([]string, 0, len(obj))
		for name := range obj {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			var entry struct {
				InjectHosts []string `json:"injectHosts"`
			}
			if json.Unmarshal(obj[name], &entry) != nil || len(entry.InjectHosts) == 0 {
				continue
			}
			hosts := "\"" + strings.Join(entry.InjectHosts, "\", \"") + "\""
			if strings.EqualFold(name, "GITHUB_TOKEN") {
				if off := nonGitHubHosts(entry.InjectHosts); len(off) > 0 {
					add(finding.Warn, sandboxCredentialEnvVars+" injects GITHUB_TOKEN at \""+strings.Join(off, "\", \"")+"\": without this entry sandboxed shells get the token only at github.com, api.github.com and uploads.github.com, or not at all, and the entry replaces those hosts."+applied+". Remove the entry")
					continue
				}
			}
			add(finding.Info, sandboxCredentialEnvVars+" masks "+name+" and injects its value at "+hosts+": sandboxed commands see a stand-in, and the sandbox proxy puts the real value into HTTPS request headers to those hosts. The repository chooses the hosts."+applied+". Check that each host belongs to the service the variable is for")
		}
	}
	if obj, ok := s.ObjectField(sandboxAdvancedRuntime); ok {
		var keys []string
		for k, v := range obj {
			if k == "enableWeakerNestedSandbox" && strings.TrimSpace(string(v)) == "false" {
				continue
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			add(finding.Warn, sandboxAdvancedRuntime+" sets "+strings.Join(keys, ", ")+": VS Code merges the object into the sandbox runtime configuration as it is, so it can weaken the sandbox (enableWeakerNestedSandbox) or add to what it allows."+applied+". Remove the key")
		}
	}
	return out
}

// outsidePaths returns the entries of a JSON string array that leave the
// repository: a ~ path, an absolute path, or a relative path that climbs out.
func outsidePaths(raw json.RawMessage) []string {
	var paths []string
	if raw == nil || json.Unmarshal(raw, &paths) != nil {
		return nil
	}
	var out []string
	for _, p := range paths {
		if kind := OpenCodeOutside(p); kind != "" && kind != "url" {
			out = append(out, p)
		}
	}
	return out
}

// homeRootRe is a whole home directory or the filesystem root, the forms
// that open every credential under it at once.
var homeRootRe = regexp.MustCompile(`(?i)^(?:~|\$HOME|/|/home/[^/]+|/Users/[^/]+|/root|[a-z]:/Users/[^/]+|[a-z]:/?)/?$`)

// readSeverity is warn for a read grant that reaches credentials, the whole
// home directory or the root, and info for any other path, such as the
// toolchain folders builds commonly need.
func readSeverity(p string) finding.Severity {
	slash := strings.ReplaceAll(p, `\`, "/")
	if homeRootRe.MatchString(slash) || credentialPathRe.MatchString(slash) {
		return finding.Warn
	}
	return finding.Info
}

// tempPath reports whether a write grant names a temporary directory, which
// gives a command nothing the repository does not already have.
func tempPath(p string) bool {
	switch strings.TrimSuffix(strings.ReplaceAll(p, `\`, "/"), "/") {
	case "/tmp", "/private/tmp", "/var/tmp", "$TMPDIR":
		return true
	}
	return false
}

// gitHubInjectHosts are the hosts the Copilot sandbox injects GITHUB_TOKEN at
// without an entry, when auth.gh is on (Copilot CLI 1.0.105 sandbox help).
var gitHubInjectHosts = map[string]bool{"github.com": true, "api.github.com": true, "uploads.github.com": true}

// nonGitHubHosts returns the hosts that are neither one of gitHubInjectHosts
// nor under github.com (*.github.com, gist.github.com): those are GitHub's own.
func nonGitHubHosts(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		h2 := strings.ToLower(strings.TrimSpace(h))
		if !gitHubInjectHosts[h2] && !strings.HasSuffix(h2, ".github.com") {
			out = append(out, h)
		}
	}
	return out
}

// isJSONFalse reports whether key holds the JSON boolean false.
func isJSONFalse(s *parser.VSCodeSettings, key string) bool {
	v, present := s.BoolField(key)
	return present && !v
}
