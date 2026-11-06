// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIOCCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-file", "../../internal/maliciousioc/npm.json"}, &stdout, &stderr, time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC))
	if code != 0 || !strings.Contains(stdout.String(), "20 npm package-version IOCs") || !strings.Contains(stdout.String(), "last reviewed 2026-11-06") {
		t.Fatalf("ioccheck: exit %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
}

func TestIOCCheckErrorsAndStaleness(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		now  time.Time
		code int
		want string
	}{
		{"flags", []string{"-unknown"}, time.Time{}, 2, "flag provided"},
		{"missing", []string{"-file", filepath.Join(t.TempDir(), "missing.json")}, time.Time{}, 1, "ioccheck:"},
		{"invalid", []string{"-file", writeIOCCheckFile(t, `{`)}, time.Time{}, 1, "ioccheck:"},
		{"stale", []string{"-file", "../../internal/maliciousioc/npm.json"}, time.Date(2027, 2, 5, 0, 0, 0, 0, time.UTC), 1, "review is overdue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr, tc.now); got != tc.code || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d, stderr %q; want %d and %q", got, stderr.String(), tc.code, tc.want)
			}
		})
	}
}

func writeIOCCheckFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ioc.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
