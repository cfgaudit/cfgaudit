package parser

import "testing"

func TestParseZedTasks(t *testing.T) {
	path := writeNamedTemp(t, "tasks.json", `[
  // worktree bootstrap
  {
    "label": "setup",
    "command": "sh",
    "args": ["-c", "cp .env.example .env"],
    "hooks": ["create_worktree"],
    "reveal": "never",
  },
  {"label": "manual", "command": "cargo test"},
]`)
	z, err := ParseZedTasks(path)
	if err != nil {
		t.Fatalf("ParseZedTasks: %v", err)
	}
	if len(z.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(z.Tasks))
	}
	setup := z.Tasks[0]
	if setup.Command != "sh" || len(setup.Args) != 2 || setup.Reveal != "never" {
		t.Errorf("task not decoded: %+v", setup)
	}
	if got := setup.AutoRunHooks(); len(got) != 1 || got[0] != "create_worktree" {
		t.Errorf("hooks = %v", got)
	}
	if got := z.Tasks[1].AutoRunHooks(); len(got) != 0 {
		t.Errorf("a task without hooks must not auto-run, got %v", got)
	}
}

// Zed accepts create_git_worktree as a serde alias for the same variant, so a
// file using it must not slip through.
func TestZedTask_HookAliasAndUnknown(t *testing.T) {
	cases := map[string]int{
		"create_worktree":     1,
		"create_git_worktree": 1,
		"  Create_Worktree  ": 1,
		"not_a_hook":          0,
		"":                    0,
	}
	for hook, want := range cases {
		t.Run("hook="+hook, func(t *testing.T) {
			task := ZedTask{Hooks: []string{hook}}
			if got := len(task.AutoRunHooks()); got != want {
				t.Errorf("AutoRunHooks() = %d, want %d", got, want)
			}
		})
	}
}

func TestZedTask_Name(t *testing.T) {
	cases := []struct {
		task ZedTask
		want string
	}{
		{ZedTask{Label: "build"}, "build"},
		{ZedTask{Command: "cargo build"}, "cargo build"},
		{ZedTask{Label: "  ", Command: "make"}, "make"},
		{ZedTask{}, "(unnamed)"},
	}
	for _, c := range cases {
		if got := c.task.Name(); got != c.want {
			t.Errorf("Name(%+v) = %q, want %q", c.task, got, c.want)
		}
	}
}

// The top level is an array, unlike VS Code's object with a "tasks" key.
func TestParseZedTasks_Malformed(t *testing.T) {
	for name, body := range map[string]string{
		"truncated":       `[{"label":`,
		"vscode-shaped":   `{"version": "2.0.0", "tasks": []}`,
		"not json at all": `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseZedTasks(writeNamedTemp(t, "tasks.json", body)); err == nil {
				t.Errorf("expected an error for %s", name)
			}
		})
	}
}

func TestZedTasks_Empty(t *testing.T) {
	if !(*ZedTasks)(nil).Empty() {
		t.Error("nil must be empty")
	}
	z, err := ParseZedTasks(writeNamedTemp(t, "tasks.json", `[]`))
	if err != nil {
		t.Fatalf("ParseZedTasks: %v", err)
	}
	if !z.Empty() {
		t.Error("an empty array must be empty")
	}
}
