// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg138 struct{}

var CFG138 = &cfg138{}

func init() { All = append(All, CFG138) }

func (r *cfg138) ID() string { return "CFG138" }

// browserMCPServerRe matches the package or program of a browser MCP server:
// Playwright MCP, Chrome DevTools MCP, Firefox DevTools MCP, browser-use and
// the Puppeteer servers (#1634). Only these are read, because their attach
// switches have generic names (--extension) that mean something else on other
// servers.
var browserMCPServerRe = regexp.MustCompile(`(?i)(?:^|[/\\\s"'])(?:@playwright/mcp|playwright-mcp|chrome-devtools-mcp|firefox-devtools-mcp|browser-use|@modelcontextprotocol/server-puppeteer|puppeteer-mcp(?:-server)?)(?:@[\w.^~-]*)?(?:\.exe|\.cmd)?(?:$|[\s"'\[])`)

// browserAttachModes are the switches that attach the server to the browser
// the user is already running, with its logged-in sessions: Playwright MCP's
// browser extension and Chrome DevTools MCP's auto-connect.
var browserAttachModes = map[string]string{
	"--extension":    "connects through the browser extension to the browser the user is already running",
	"--autoconnect":  "connects to the Chrome the user is already running",
	"--auto-connect": "connects to the Chrome the user is already running",
}

// browserEndpointFlags take the address of a running browser's debugging
// endpoint (CDP or WebSocket).
var browserEndpointFlags = map[string]bool{
	"--cdp-endpoint": true, "--browserurl": true, "--browser-url": true,
	"--wsendpoint": true, "--ws-endpoint": true,
}

// browserProfileFlags take the profile folder the browser starts with.
var browserProfileFlags = []string{"--user-data-dir", "--userdatadir"}

// realBrowserProfileRe matches the default profile folder of Chrome, Chromium,
// Edge, Brave or Firefox on Linux, macOS and Windows. Paths are compared with
// forward slashes.
var realBrowserProfileRe = regexp.MustCompile(`(?i)(?:\.config/(?:google-chrome[\w-]*|chromium|microsoft-edge[\w-]*|bravesoftware/brave-browser[\w-]*)|\.mozilla/firefox|snap/chromium/|application support/(?:google/chrome[\w ]*|chromium|microsoft edge[\w ]*|bravesoftware/brave-browser[\w-]*|firefox)|(?:appdata/local|localappdata%?)/(?:google/chrome[\w ]*|chromium|microsoft/edge[\w ]*|bravesoftware/brave-browser[\w-]*)/user data|appdata/roaming/mozilla/firefox)`)

// playwrightEnvFlags maps Playwright MCP's environment variables to the
// switch each one stands for.
var playwrightEnvFlags = map[string]string{
	"PLAYWRIGHT_MCP_EXTENSION":     "--extension",
	"PLAYWRIGHT_MCP_CDP_ENDPOINT":  "--cdp-endpoint",
	"PLAYWRIGHT_MCP_USER_DATA_DIR": "--user-data-dir",
}

// Check reports a browser MCP server that is attached to a browser the user
// already runs, or to the user's own browser profile (#1634). The agent then
// acts with the user's cookies and logged-in sessions.
func (r *cfg138) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		s := ref.Server
		if !browserMCPServerRe.MatchString(" " + s.Command + " " + strings.Join(s.Args, " ") + " ") {
			continue
		}
		prefix := "mcpServers." + ref.Name + " "
		add := func(sev finding.Severity, msg string) {
			findings = append(findings, finding.Finding{
				RuleID: "CFG138", Severity: sev, File: ref.File,
				Message: prefix + msg + userScopeNote(t),
			})
		}
		for _, a := range browserAttachArgs(s.Args, s.Env) {
			sev, msg, ok := judgeBrowserAttach(a.flag, a.value, a.from)
			if ok {
				add(sev, msg)
			}
		}
	}
	return findings
}

type browserAttachArg struct{ flag, value, from string }

// browserAttachArgs collects the attach switches of one server from its args
// (--flag=value, --flag value) and from Playwright MCP's environment variables.
// A switch passed on to Chrome (--chrome-arg=--user-data-dir=...) counts too.
func browserAttachArgs(args []string, env map[string]string) []browserAttachArg {
	var out []browserAttachArg
	for i := 0; i < len(args); i++ {
		tok := unquoteArg(args[i])
		if j := strings.LastIndex(tok, "=--"); j >= 0 {
			tok = tok[j+1:] // --chrome-arg=--user-data-dir=...
		}
		flag, value, hasValue := strings.Cut(tok, "=")
		lf := strings.ToLower(flag)
		_, mode := browserAttachModes[lf]
		takesValue := browserEndpointFlags[lf] || isBrowserProfileFlag(lf)
		switch {
		case mode || lf == "--connect-existing":
			if hasValue && strings.EqualFold(value, "false") {
				continue
			}
			out = append(out, browserAttachArg{flag: lf, from: flag})
		case takesValue:
			if !hasValue && i+1 < len(args) && !strings.HasPrefix(strings.TrimSpace(args[i+1]), "-") {
				value = args[i+1]
				i++
			}
			out = append(out, browserAttachArg{flag: lf, value: unquoteArg(value), from: flag})
		}
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		flag, ok := playwrightEnvFlags[strings.ToUpper(k)]
		if !ok {
			continue
		}
		v := unquoteArg(env[k])
		if flag == "--extension" {
			if v == "" || strings.EqualFold(v, "false") || v == "0" {
				continue
			}
			v = ""
		}
		out = append(out, browserAttachArg{flag: flag, value: v, from: "env " + k})
	}
	return out
}

func isBrowserProfileFlag(f string) bool {
	for _, p := range browserProfileFlags {
		if f == p {
			return true
		}
	}
	return false
}

// judgeBrowserAttach grades one attach switch: warn for a mode that joins the
// running browser, a real profile or a debugging endpoint on another host;
// info for a loopback endpoint; nothing for a project profile folder or a
// switch without a value.
func judgeBrowserAttach(flag, value, from string) (finding.Severity, string, bool) {
	const tail = "; the agent then acts with the user's cookies and logged-in sessions (mail, admin consoles, banking). Use an isolated profile the server starts itself unless the project needs the user's own browser"
	if why, ok := browserAttachModes[flag]; ok {
		return finding.Warn, "uses " + from + ", which " + why + tail, true
	}
	if flag == "--connect-existing" {
		return finding.Info, "uses " + from + ", which connects to a Firefox that is already running on this machine. Make sure it is a browser started for the agent, not the one the user is logged in with", true
	}
	if value == "" {
		return "", "", false
	}
	if isBrowserProfileFlag(flag) {
		if realBrowserProfileRe.MatchString(strings.ReplaceAll(value, `\`, "/")) {
			return finding.Warn, "starts the browser with " + from + " \"" + value + "\", the user's own browser profile" + tail, true
		}
		return "", "", false
	}
	if isSecretReference(value) {
		return finding.Info, "attaches to the running browser at " + from + " " + value + ", a value set at run time that cfgaudit cannot judge. Make sure it is a browser started for the agent, not the one the user is logged in with", true
	}
	if host := browserEndpointHost(value); host != "" && !loopbackHost(host) {
		return finding.Warn, "attaches to the browser debugging endpoint " + value + " on another host (" + from + "). The debugging protocol has no authentication, and the agent drives whatever browser listens there", true
	}
	return finding.Info, "attaches to the running browser at " + value + " (" + from + "). Make sure it is a browser started for the agent with its own profile, not the one the user is logged in with", true
}

// browserEndpointHost returns the host of a debugging endpoint given as a URL or as
// host:port, or "" when none can be read.
func browserEndpointHost(v string) string {
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// loopbackHost reports a host that names this machine.
func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}
