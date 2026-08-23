package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ZedDebugScenario is one entry of a Zed `.zed/debug.json`, which its docs
// describe as "an array of configuration objects".
//
// Only the fields cfgaudit acts on are decoded. `program`, `args` and `env` name
// the binary the user asked to debug, which is the thing they picked rather than
// a side effect of picking it, so they are deliberately not modelled: that is
// the same line `.zed/tasks.json` already draws between a hook task and one the
// user invokes from the task list.
//
// `build` is the exception, and the reason this file is read at all. Upstream:
// "Zed will use the `build` field to run any necessary setup steps before the
// debugger starts", and "Zed allows embedding a Zed task in the `build` field
// that is run before the debugger starts". Pressing Debug on a configuration
// labelled "Debug server" therefore runs whatever command that field names,
// under a label that does not describe it.
type ZedDebugScenario struct {
	Label   string          `json:"label,omitempty"`
	Adapter string          `json:"adapter,omitempty"`
	Build   json.RawMessage `json:"build,omitempty"`
}

// ZedBuildTask is the embedded-task form of `build`, the same shape as a
// .zed/tasks.json entry.
type ZedBuildTask struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
}

// Name returns a finding-friendly identifier: the label, else the adapter.
func (s ZedDebugScenario) Name() string {
	if l := strings.TrimSpace(s.Label); l != "" {
		return l
	}
	if a := strings.TrimSpace(s.Adapter); a != "" {
		return a
	}
	return "(unnamed)"
}

// BuildTask returns the embedded build task, or nil when `build` is absent or
// carries the string form.
func (s ZedDebugScenario) BuildTask() *ZedBuildTask {
	if len(s.Build) == 0 {
		return nil
	}
	var task ZedBuildTask
	if err := json.Unmarshal(s.Build, &task); err != nil {
		return nil
	}
	if strings.TrimSpace(task.Command) == "" {
		return nil
	}
	return &task
}

// BuildTaskRef returns the label of an existing task the `build` field refers to
// ("Build tasks can also refer to the existing tasks by unsubstituted label"),
// or "" when `build` is absent or carries the embedded form.
func (s ZedDebugScenario) BuildTaskRef() string {
	if len(s.Build) == 0 {
		return ""
	}
	var label string
	if err := json.Unmarshal(s.Build, &label); err != nil {
		return ""
	}
	return strings.TrimSpace(label)
}

// CommandLine renders the embedded build task's command and arguments as one
// string for the command-content rules.
func (b *ZedBuildTask) CommandLine() string {
	if b == nil {
		return ""
	}
	cmd := b.Command
	if len(b.Args) > 0 {
		cmd += " " + strings.Join(b.Args, " ")
	}
	return cmd
}

// ZedDebug is a parsed .zed/debug.json.
type ZedDebug struct {
	Scenarios []ZedDebugScenario
}

// Empty reports whether the file declared no scenarios.
func (z *ZedDebug) Empty() bool { return z == nil || len(z.Scenarios) == 0 }

// ParseZedDebug reads and decodes a .zed/debug.json. Like tasks.json it is
// JSONC and the top level is an array.
func ParseZedDebug(path string) (*ZedDebug, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var scenarios []ZedDebugScenario
	if err := json.Unmarshal(stripJSONC(data), &scenarios); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &ZedDebug{Scenarios: scenarios}, nil
}
