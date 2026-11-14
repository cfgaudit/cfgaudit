// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func mcpDockerTarget(args ...string) *Target {
	return &Target{
		ProjectMCPFile: ".mcp.json",
		ProjectMCP:     map[string]parser.MCPServer{"srv": {Command: "docker", Args: args}},
	}
}

// Each flag of #1682 as MCP args, at its severity; a plain container, a
// folder inside the repository and harmless options are not reported.
func TestCFG142_MCPArgs1682(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want finding.Severity
	}{
		{[]string{"run", "-i", "--rm", "--privileged", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--rm", "--privileged=true", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "/var/run/docker.sock:/var/run/docker.sock", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--volume=/run/user/1000/podman/podman.sock:/s", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", `\\.\pipe\docker_engine:\\.\pipe\docker_engine`, "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--cap-add", "SYS_ADMIN", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--cap-add=ALL", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--cap-add", "cap_sys_admin", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--cap-add", "SYS_PTRACE", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "--cap-add", "NET_ADMIN", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "--pid", "host", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--pid=host", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "--ipc", "host", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "--network", "host", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "--net=host", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "--security-opt", "seccomp=unconfined", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "--security-opt", "apparmor=unconfined", "mcp/x"}, finding.Warn},
		{[]string{"run", "-i", "-v", "/home/me/.ssh:/root/.ssh", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "~/.aws:/root/.aws:ro", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "${HOME}/.config/gcloud:/gcloud", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "$HOME:/host-home", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "/Users/me/:/h", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", `C:\Users\me\.ssh:/root/.ssh`, "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "/:/host", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "/etc:/host-etc:ro", "mcp/x"}, finding.Error},
		{[]string{"run", "-i", "-v", "/proc:/host/proc", "mcp/x"}, finding.Warn},
		{[]string{"run", "-itv", "/:/host", "mcp/x"}, finding.Error},
		{[]string{"container", "run", "--privileged", "mcp/x"}, finding.Error},
		{[]string{"--context", "remote", "run", "--privileged", "mcp/x"}, finding.Error},
		{[]string{"create", "--privileged", "mcp/x"}, finding.Error},
		{[]string{"run", "-v", "C:/:/host", "mcp/x"}, finding.Error},
		{[]string{"run", "-v", `C:\Users\me`, "mcp/x"}, finding.Error},
		{[]string{"run", "-v", "~/.ssh/id_ed25519:/key:ro", "mcp/x"}, finding.Error},
		{[]string{"run", "--mount", "type=bind,src=/,dst=/host", "mcp/x"}, finding.Error},
		{[]string{"run", "--cap-add", "SYS_MODULE", "mcp/x"}, finding.Warn},
		{[]string{"run", "--cap-add", "BPF", "mcp/x"}, finding.Warn},
	} {
		f := CFG142.Check(mcpDockerTarget(tc.args...))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%v: want one %s finding, got %+v", tc.args, tc.want, f)
		}
	}
	for _, args := range [][]string{
		{"run", "-i", "--rm", "mcp/x:1.0"},
		{"run", "-i", "--rm", "-v", "./data:/data", "mcp/x"},
		{"run", "-i", "--rm", "-v", "${workspaceFolder}:/workspace", "mcp/x"},
		{"run", "-i", "--rm", "-v", "$(pwd):/src", "mcp/x"},
		{"run", "-i", "--rm", "-v", "mcp-data:/data", "mcp/x"},
		{"run", "-i", "--rm", "-v", "/home/me/projects/site:/site", "mcp/x"},
		{"run", "-i", "--rm", "-v", "~/.config/myapp:/cfg", "mcp/x"},
		{"run", "-i", "--rm", "-v", "/tmp:/tmp", "mcp/x"},
		{"run", "-i", "--rm", "--cap-add", "NET_BIND_SERVICE", "mcp/x"},
		{"run", "-i", "--rm", "--cap-drop", "ALL", "mcp/x"},
		{"run", "-i", "--rm", "--privileged=false", "mcp/x"},
		{"run", "-i", "--rm", "--network", "bridge", "mcp/x"},
		{"run", "-i", "--rm", "--security-opt", "no-new-privileges", "mcp/x"},
		{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "mcp/x"},
		// Options after the image belong to the program in the container.
		{"run", "-i", "--rm", "mcp/x", "--privileged", "-v", "/:/host"},
		{"run", "-i", "--rm", "-e", "--privileged", "mcp/x"},
		{"pull", "--privileged"},
		{"ps", "-v", "/:/host"},
		{"run", "-v", `D:\data:/data`, "mcp/x"},
		{"run", "-v", "/srv/only", "mcp/x"},
		{"run", "--mount", "type=volume,target=/data", "mcp/x"},
		{"run", "-v", `"":/x`, "mcp/x"},
		{"run", "--cap-add", "CHOWN", "mcp/x"},
	} {
		if f := CFG142.Check(mcpDockerTarget(args...)); len(f) != 0 {
			t.Errorf("%v: want no finding, got %+v", args, f)
		}
	}
}

// Hooks, tasks and `!` blocks start containers too.
func TestCFG142_CommandSites1682(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want finding.Severity
	}{
		{`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine true`, finding.Error},
		{`cd "$CLAUDE_PROJECT_DIR" && sudo docker run --rm --privileged img`, finding.Error},
		{`podman run --rm --net=host img`, finding.Warn},
		{`docker run --rm --network host -v "$HOME/.ssh:/root/.ssh:ro" img`, finding.Error},
	} {
		f := CFG142.Check(hookTarget(t, tc.cmd))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s: want one %s finding, got %+v", tc.cmd, tc.want, f)
		}
	}
	for _, cmd := range []string{
		`docker run --rm -v "$CLAUDE_PROJECT_DIR:/src" img lint`,
		`echo "do not use docker run --privileged"`,
		`docker ps; docker run --rm img`,
		`docker build -t x . && docker run --rm x --privileged`,
	} {
		if f := CFG142.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("%s: want no finding, got %+v", cmd, f)
		}
	}

	tasks := &Target{
		VSCodeTasksFile: ".vscode/tasks.json",
		VSCodeTasks: &parser.VSCodeTasks{Tasks: []parser.VSCodeTask{
			{Label: "up", Command: "docker run --rm --pid=host img", RunOptions: &parser.VSCodeRunOptions{RunOn: "folderOpen"}},
			{Label: "dev", Command: "docker run --rm --ipc host img"},
		}},
	}
	f := CFG142.Check(tasks)
	if len(f) != 2 || f[0].Severity != finding.Error || f[1].Severity != finding.Warn || !strings.Contains(f[0].Message, `folderOpen task "up"`) {
		t.Errorf("tasks: %+v", f)
	}
}

// One finding per command lists every flag, at the highest severity, and
// quotes each flag so the finding lands on its line.
func TestCFG142_Message1682(t *testing.T) {
	f := CFG142.Check(mcpDockerTarget("run", "-i", "--network", "host", "--cap-add", "SYS_ADMIN", "mcp/x"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("got %+v", f)
	}
	for _, want := range []string{`mcpServers.srv command`, `"--network host"`, `"--cap-add SYS_ADMIN"`} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("message lacks %q: %s", want, f[0].Message)
		}
	}
	if CFG142.Check(nil) != nil {
		t.Error("nil target")
	}
	if CFG142.ID() != "CFG142" {
		t.Error(CFG142.ID())
	}
	// The same command twice in one site gives one finding; a server with
	// only a URL starts nothing.
	if f := CFG142.Check(hookTarget(t, `docker run --privileged a; docker run --privileged a`)); len(f) != 1 {
		t.Errorf("duplicate: %+v", f)
	}
	remote := &Target{ProjectMCPFile: ".mcp.json", ProjectMCP: map[string]parser.MCPServer{"r": {URL: "https://example.com/mcp"}}}
	if f := CFG142.Check(remote); len(f) != 0 {
		t.Errorf("remote: %+v", f)
	}
}
