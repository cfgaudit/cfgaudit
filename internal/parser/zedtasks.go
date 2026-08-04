package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ZedTask is one entry of a Zed `.zed/tasks.json`, which is a JSON array of task
// templates (crates/task/src/task_template.rs `TaskTemplates(pub Vec<TaskTemplate>)`).
// Only the fields cfgaudit inspects are decoded.
type ZedTask struct {
	Label   string            `json:"label,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`

	// Hooks names the lifecycle events that spawn this task without the user
	// asking for it. Zed's TaskHook enum currently has one variant, serialized
	// snake_case as "create_worktree", with "create_git_worktree" accepted as a
	// serde alias.
	Hooks []string `json:"hooks,omitempty"`

	// Reveal controls whether the task's terminal pane is shown. "never" keeps a
	// hook-spawned command out of sight.
	Reveal string `json:"reveal,omitempty"`
}

// createWorktreeHooks are the spellings Zed accepts for its one task hook.
var createWorktreeHooks = map[string]bool{
	"create_worktree":     true,
	"create_git_worktree": true, // serde alias, kept for compatibility upstream
}

// AutoRunHooks returns the task's hook names that spawn it automatically,
// normalized to the values Zed declares. Empty when the task only runs when
// invoked.
func (t ZedTask) AutoRunHooks() []string {
	var out []string
	for _, h := range t.Hooks {
		if name := strings.ToLower(strings.TrimSpace(h)); createWorktreeHooks[name] {
			out = append(out, name)
		}
	}
	return out
}

// Name returns a finding-friendly identifier: the label, else the command.
func (t ZedTask) Name() string {
	if l := strings.TrimSpace(t.Label); l != "" {
		return l
	}
	if c := strings.TrimSpace(t.Command); c != "" {
		return c
	}
	return "(unnamed)"
}

// ZedTasks is a parsed .zed/tasks.json.
type ZedTasks struct {
	Tasks []ZedTask
}

// Empty reports whether the file declared no tasks.
func (z *ZedTasks) Empty() bool {
	return z == nil || len(z.Tasks) == 0
}

// ParseZedTasks reads and decodes a .zed/tasks.json. Zed loads it with
// `parse_json_with_comments`, so the file is JSONC and comments and trailing
// commas are stripped before decoding, as for .vscode/tasks.json.
//
// The top level is an array, unlike VS Code's object with a "tasks" key.
func ParseZedTasks(path string) (*ZedTasks, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var tasks []ZedTask
	if err := json.Unmarshal(stripJSONC(data), &tasks); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &ZedTasks{Tasks: tasks}, nil
}
