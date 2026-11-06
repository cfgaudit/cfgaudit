// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Command ioccheck validates the reviewed offline malicious-package data.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cfgaudit/cfgaudit/internal/maliciousioc"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now().UTC()))
}

func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	flags := flag.NewFlagSet("ioccheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "internal/maliciousioc/npm.json", "IOC JSON file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	data, err := os.ReadFile(*file) //nolint:gosec // user-selected local validation input
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ioccheck:", err)
		return 1
	}
	dataset, err := maliciousioc.Parse(data)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "ioccheck:", err)
		return 1
	}
	versions := 0
	for _, entry := range dataset.Entries {
		versions += len(entry.Versions)
	}
	_, _ = fmt.Fprintf(stdout, "valid: %d npm package-version IOCs; last reviewed %s; review after %s; owner %s\n", versions, dataset.LastReviewed, dataset.ReviewAfter, dataset.Owner)
	reviewAfter, _ := time.Parse(time.DateOnly, dataset.ReviewAfter)
	if now.UTC().After(reviewAfter.Add(24*time.Hour - time.Nanosecond)) {
		_, _ = fmt.Fprintln(stderr, "ioccheck: data review is overdue; review every entry and advance last_reviewed/review_after")
		return 1
	}
	return 0
}
