// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

// workflows is the list the API returns: one file, and two that do not count.
const workflows = `{"workflows":[
	{"id":1,"path":".github/workflows/ci.yml","state":"active"},
	{"id":2,"path":".github/workflows/old.yml","state":"disabled_manually"},
	{"id":3,"path":"dynamic/dependabot/dependabot-updates","state":"active"}]}`

func isList(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/actions/workflows") }

func runJSON(id int, name, event, branch string, minutes float64) string {
	end := now.Add(time.Duration(minutes * float64(time.Minute)))
	return fmt.Sprintf(`{"id":%d,"name":%q,"event":%q,"head_branch":%q,"run_started_at":%q,"updated_at":%q}`,
		id, name, event, branch, now.Format(time.RFC3339), end.Format(time.RFC3339))
}

// api serves the runs of workflow 1, and two jobs for every run.
func api(t *testing.T, runs ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("no token on the request")
		}
		if isList(r) {
			_, _ = fmt.Fprint(w, workflows)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/jobs") {
			start, end := now.Format(time.RFC3339), now.Add(2*time.Minute).Format(time.RFC3339)
			_, _ = fmt.Fprintf(w, `{"jobs":[{"name":"Test","conclusion":"success","started_at":%q,"completed_at":%q},
				{"name":"Skipped","conclusion":"skipped","started_at":null,"completed_at":null}]}`, start, end)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/actions/workflows/1/runs") {
			t.Errorf("read %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("created"); got != ">=2026-11-02" {
			t.Errorf("created = %q", got)
		}
		_, _ = fmt.Fprintf(w, `{"workflow_runs":[%s]}`, strings.Join(runs, ","))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	opt := append([]string{"-now", now.Format(time.RFC3339)}, args...)
	code := realMain(opt, "secret", &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestWithinBudget(t *testing.T) {
	srv := api(t,
		runJSON(1, "CI", "pull_request", "fix/a", 3),
		runJSON(2, "CI", "push", "main", 4),
		runJSON(3, "CI", "push", "feature", 500),
		runJSON(4, "Release", "push", "v1.0.0", 500),
		runJSON(5, "Scorecard", "schedule", "main", 500),
	)
	path := filepath.Join(t.TempDir(), "record.jsonl")
	code, out, stderr := cli(t, "-api", srv.URL, "-record", path)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "within the budget of 15 minutes") || !strings.Contains(out, "| CI | 2 | 4.0 | 4.0 | 4.0 |") {
		t.Errorf("report:\n%s", out)
	}
	if strings.Contains(out, "Release") || strings.Contains(out, "Scorecard") {
		t.Errorf("report counts runs that aren't from pull requests or main:\n%s", out)
	}
	if strings.Contains(out, "Skipped") {
		t.Errorf("report lists a job that didn't succeed:\n%s", out)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: a temporary file of this test
	if err != nil {
		t.Fatal(err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Schema != schema || rec.Date != "2026-11-09T08:00:00Z" || len(rec.Workflows) != 1 || rec.Jobs[0].Runs != 2 {
		t.Errorf("record: %s", data)
	}
}

func TestOverBudget(t *testing.T) {
	var runs []string
	for i := range 5 {
		runs = append(runs, runJSON(i, "CI|main", "pull_request", "x", 16))
	}
	code, out, _ := cli(t, "-api", api(t, runs...).URL, "-jobs-of", "none")
	if code != exitBudget {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `Over the budget of 15 minutes (p90):** CI|main (16.0)`) || !strings.Contains(out, `| CI\|main | 5 |`) {
		t.Errorf("report:\n%s", out)
	}
}

func TestFewRunsDontCountAgainstTheBudget(t *testing.T) {
	code, _, _ := cli(t, "-api", api(t, runJSON(1, "CI", "push", "main", 60)).URL)
	if code != exitOK {
		t.Errorf("exit %d", code)
	}
}

func TestSampleLimitsJobRequests(t *testing.T) {
	code, out, _ := cli(t, "-api", api(t,
		runJSON(1, "CI", "push", "main", 3),
		runJSON(2, "CI", "push", "main", 3),
		runJSON(3, "CI", "push", "main", 3),
	).URL, "-sample", "2")
	if code != exitOK || !strings.Contains(out, "| Test | 2 |") {
		t.Errorf("exit %d, report:\n%s", code, out)
	}
}

func TestPagination(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isList(r) {
			_, _ = fmt.Fprint(w, workflows)
			return
		}
		pages++
		count := perPage
		if r.URL.Query().Get("page") == "2" {
			count = 1
		}
		_, _ = fmt.Fprintf(w, `{"workflow_runs":[%s]}`, strings.TrimSuffix(strings.Repeat(runJSON(1, "CI", "push", "main", 3)+",", count), ","))
	}))
	defer srv.Close()
	code, out, _ := cli(t, "-api", srv.URL, "-sample", "0")
	if code != exitOK || pages != 2 || !strings.Contains(out, fmt.Sprintf("| CI | %d |", perPage+1)) {
		t.Errorf("exit %d, %d pages, report:\n%s", code, pages, out)
	}
}

// A run the API would no longer list must not vanish from the record, so a
// workflow that does not fit into a search is an error.
func TestMoreRunsThanASearchReturns(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isList(r) {
			_, _ = fmt.Fprint(w, workflows)
			return
		}
		pages++
		_, _ = fmt.Fprintf(w, `{"workflow_runs":[%s]}`, strings.TrimSuffix(strings.Repeat(runJSON(1, "CI", "push", "main", 3)+",", perPage), ","))
	}))
	defer srv.Close()
	code, _, stderr := cli(t, "-api", srv.URL, "-sample", "0")
	if code != exitError || pages != maxPages || !strings.Contains(stderr, ".github/workflows/ci.yml") {
		t.Errorf("exit %d, %d pages: %s", code, pages, stderr)
	}
}

// Every workflow gets its own search, so a busy one cannot push another out.
func TestReadsEveryWorkflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isList(r):
			_, _ = fmt.Fprint(w, `{"workflows":[{"id":1,"path":".github/workflows/a.yml","state":"active"},{"id":2,"path":".github/workflows/b.yml","state":"active"}]}`)
		case strings.Contains(r.URL.Path, "/workflows/1/"):
			_, _ = fmt.Fprintf(w, `{"workflow_runs":[%s]}`, runJSON(1, "A", "push", "main", 3))
		default:
			_, _ = fmt.Fprintf(w, `{"workflow_runs":[%s]}`, runJSON(2, "B", "push", "main", 3))
		}
	}))
	defer srv.Close()
	code, out, stderr := cli(t, "-api", srv.URL, "-sample", "0")
	if code != exitOK || !strings.Contains(out, "| A | 1 |") || !strings.Contains(out, "| B | 1 |") {
		t.Errorf("exit %d: %s\n%s", code, stderr, out)
	}
}

// The list is not paged, because a workflow missing from it would go unnoticed.
func TestTooManyWorkflows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		one := `{"id":1,"path":".github/workflows/ci.yml","state":"active"}`
		_, _ = fmt.Fprintf(w, `{"workflows":[%s]}`, strings.TrimSuffix(strings.Repeat(one+",", perPage), ","))
	}))
	defer srv.Close()
	if code, _, stderr := cli(t, "-api", srv.URL); code != exitError {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestErrors(t *testing.T) {
	status := func(code int) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		t.Cleanup(srv.Close)
		return srv
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "not json") }))
	defer bad.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	runsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isList(r) {
			_, _ = fmt.Fprint(w, workflows)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer runsFail.Close()
	jobsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isList(r) {
			_, _ = fmt.Fprint(w, workflows)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/jobs") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"workflow_runs":[%s]}`, runJSON(1, "CI", "push", "main", 3))
	}))
	defer jobsFail.Close()

	for name, args := range map[string][]string{
		"not found":    {"-api", status(http.StatusNotFound).URL},
		"server error": {"-api", status(http.StatusBadGateway).URL},
		"not JSON":     {"-api", bad.URL},
		"no server":    {"-api", closed.URL},
		"bad URL":      {"-api", "http://bad host"},
		"runs fail":    {"-api", runsFail.URL},
		"jobs fail":    {"-api", jobsFail.URL},
		"bad flag":     {"-nonsense"},
		"bad now":      {"-now", "yesterday"},
		"record path":  {"-api", api(t).URL, "-record", filepath.Join(t.TempDir(), "missing", "record.jsonl")},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := cli(t, args...); code != exitError {
				t.Errorf("exit %d, want %d", code, exitError)
			}
		})
	}
}

func TestServerErrorIsRetried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, `{"workflows":[]}`)
	}))
	defer srv.Close()
	if code, _, stderr := cli(t, "-api", srv.URL); code != exitOK || calls != 2 {
		t.Errorf("exit %d after %d calls: %s", code, calls, stderr)
	}
}

func TestStatsPercentiles(t *testing.T) {
	var ten []float64
	for i := 1; i <= 10; i++ {
		ten = append(ten, float64(i))
	}
	got := stats(map[string][]float64{"b": ten, "a": {1, 2}, "c": {10}})
	if got[0].Name != "c" || got[1].Name != "b" || got[1].P90 != 9 || got[1].Median != 6 || got[1].Max != 10 {
		t.Errorf("%+v", got)
	}
	if got[2].Name != "a" || got[2].P90 != 2 {
		t.Errorf("%+v", got)
	}
	tied := stats(map[string][]float64{"z": {1}, "y": {1}})
	if tied[0].Name != "y" {
		t.Errorf("ties aren't sorted by name: %+v", tied)
	}
}
