// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "strings"

// A stdio MCP server can be a proxy that connects to a remote server, so the
// remote URL sits in its arguments instead of a url field (#1406). CVE-2025-6514
// (mcp-remote before 0.1.16) let such a remote server run commands on the
// client through its OAuth metadata.

// mcpRemoteBoolFlags are the mcp-remote flags that take no value, from its
// README (0.16.5). Every other --flag before the URL takes the next argument,
// unless it is written as --flag=value.
var mcpRemoteBoolFlags = map[string]bool{
	"--allow-http":   true,
	"--debug":        true,
	"--silent":       true,
	"--enable-proxy": true,
}

// stdioProxyRemote returns the proxy and the remote URL for a server that
// starts mcp-remote or supergateway, directly or through a package runner
// (npx, bunx, pnpm dlx, npm exec, cmd /c). It returns "" for any other server.
//
//   - mcp-remote <url> [callback-port] [flags]: the first positional argument.
//   - supergateway --sse <url> or --streamableHttp <url>: the flag's value.
//     With --stdio the gateway serves a local command and connects to nothing.
func stdioProxyRemote(command string, args []string) (string, string) {
	if len(args) == 0 && strings.ContainsAny(command, " \t") {
		fields := strings.Fields(command)
		command, args = fields[0], fields[1:]
	}
	runner, args := windowsRunner(command, args)
	tool, rest := "", args
	if p := proxyName(runner); p != "" {
		tool = p
	} else if npmPackageRunners[runner] {
		for i, a := range args {
			if p := proxyName(packageName(a)); p != "" {
				tool, rest = p, args[i+1:]
				break
			}
		}
	}
	switch tool {
	case "mcp-remote":
		return tool, mcpRemoteURL(rest)
	case "supergateway":
		return tool, supergatewayURL(rest)
	}
	return "", ""
}

// proxyName returns the proxy a program or package name is, or "".
func proxyName(name string) string {
	base := strings.ToLower(name[strings.LastIndex(name, "/")+1:])
	if base == "mcp-remote" || base == "supergateway" {
		return base
	}
	return ""
}

// packageName drops the version from an npm package spec: mcp-remote@0.1.16
// is mcp-remote. A scope's leading @ stays.
func packageName(spec string) string {
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

func mcpRemoteURL(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue // the end of the runner's own options
		}
		if strings.HasPrefix(a, "-") {
			if !mcpRemoteBoolFlags[a] && !strings.Contains(a, "=") {
				i++ // the flag's value
			}
			continue
		}
		if proxyName(a) == "mcp-remote" {
			continue // the bin name after npx --package mcp-remote
		}
		return a
	}
	return ""
}

func supergatewayURL(args []string) string {
	for i, a := range args {
		for _, flag := range []string{"--sse", "--streamableHttp"} {
			if a == flag && i+1 < len(args) {
				return args[i+1]
			}
			if v, ok := strings.CutPrefix(a, flag+"="); ok {
				return v
			}
		}
	}
	return ""
}
