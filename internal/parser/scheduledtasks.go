package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ScheduledTasks is a committed .claude/scheduled_tasks.json — the on-disk store
// for Claude Code's cron scheduler (the CronCreate / ScheduleWakeup tools, /loop,
// and routines). Each entry carries a cron expression and a `prompt` that is
// enqueued into the session, as if typed, when the schedule fires.
//
// The file is Claude Code's own runtime state and is normally kept out of git
// (2.1.273 adds it to the repository's info/exclude via
// ensureClaudeRuntimeFilesExcluded), but committed copies exist in the wild, and
// a committed copy runs on a timer in every contributor's interactive session.
type ScheduledTasks struct {
	Tasks []ScheduledTask `json:"tasks"`
}

// ScheduledTask is one entry. Only the fields that decide whether it fires, and
// where its instruction goes, are modelled.
//
// The two identity fields are the crux (#583). The writer always stamps both,
// but the reader treats them as optional (`typeof x === "string" && ...`), and
// the fire gate `de(task)` in 2.1.273 keys on them:
//
//   - CreatedBySession absent → the task fires once this session holds the
//     scheduler lock, i.e. in ANY checkout;
//   - CreatedBySession equals the current session → fires;
//   - otherwise → only when CreatedInProject resolves to the current project path
//     and the pid/transcript still match, which a fresh clone fails.
//
// So a task carrying neither field (a "bare" task) fires on any clone, while a
// session-bound task stays inert on another machine.
type ScheduledTask struct {
	ID               string `json:"id"`
	Cron             string `json:"cron"`
	Prompt           string `json:"prompt"`
	Recurring        bool   `json:"recurring"`
	CreatedBySession string `json:"createdBySessionId"`
	CreatedInProject string `json:"createdInProject"`
}

// Bare reports whether the task carries no session identity, so the fire gate's
// first branch applies and it runs in any checkout.
func (t ScheduledTask) Bare() bool {
	return strings.TrimSpace(t.CreatedBySession) == "" && strings.TrimSpace(t.CreatedInProject) == ""
}

// Actionable reports whether the task would actually enqueue something: it needs
// both a prompt to enqueue and a cron to fire on. An entry missing either does
// nothing, so reporting it would be a false positive.
func (t ScheduledTask) Actionable() bool {
	return strings.TrimSpace(t.Prompt) != "" && strings.TrimSpace(t.Cron) != ""
}

// ParseScheduledTasks reads and decodes a scheduled_tasks.json. A missing file
// yields (nil, nil) so no empty target is built; a present-but-unparseable file
// is an error, like the other JSON config loaders.
func ParseScheduledTasks(path string) (*ScheduledTasks, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st ScheduledTasks
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &st, nil
}
