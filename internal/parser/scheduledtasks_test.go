package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSched(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scheduled_tasks.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseScheduledTasks(t *testing.T) {
	st, err := ParseScheduledTasks(writeSched(t, `{"tasks":[
      {"id":"a","cron":"* * * * *","prompt":"do it","recurring":true},
      {"id":"b","cron":"0 9 * * *","prompt":"p","createdBySessionId":"s1","createdInProject":"/x"}
    ]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(st.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(st.Tasks))
	}
	if !st.Tasks[0].Bare() || !st.Tasks[0].Actionable() || !st.Tasks[0].Recurring {
		t.Errorf("task a should be bare, actionable, recurring: %+v", st.Tasks[0])
	}
	if st.Tasks[1].Bare() {
		t.Errorf("task b carries a session id, so it is not bare: %+v", st.Tasks[1])
	}
}

func TestScheduledTask_Actionable(t *testing.T) {
	if (ScheduledTask{Cron: "* * * * *"}).Actionable() {
		t.Error("no prompt must not be actionable")
	}
	if (ScheduledTask{Prompt: "p"}).Actionable() {
		t.Error("no cron must not be actionable")
	}
	if !(ScheduledTask{Cron: "* * * * *", Prompt: "p"}).Actionable() {
		t.Error("prompt+cron must be actionable")
	}
}

func TestParseScheduledTasks_MissingAndMalformed(t *testing.T) {
	st, err := ParseScheduledTasks(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || st != nil {
		t.Errorf("missing file should be (nil, nil), got (%v, %v)", st, err)
	}
	if _, err := ParseScheduledTasks(writeSched(t, `{not json`)); err == nil {
		t.Error("malformed file should error")
	}
	// An empty tasks array parses to a non-nil store with no tasks.
	st, err = ParseScheduledTasks(writeSched(t, `{"tasks":[]}`))
	if err != nil || st == nil || len(st.Tasks) != 0 {
		t.Errorf("empty tasks: got (%+v, %v)", st, err)
	}
}
