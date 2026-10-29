// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/benchcorpus"
)

// benchArgs scans dir the way a CI job does. --claude-version pins the rule
// gating, so no claude subprocess runs inside the timed loop.
func benchArgs(dir string) []string {
	return []string{"cfgaudit", "--claude-version", "2.1.312", "--format", "json", dir}
}

// quietStderr sends os.Stderr to the null device until the benchmark ends.
// Some notices bypass run's stderr argument, and go test prints them into the
// middle of a result line, which benchstat then cannot read.
func quietStderr(b *testing.B) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = null
	b.Cleanup(func() {
		os.Stderr = saved
		_ = null.Close()
	})
}

func benchScan(b *testing.B, p benchcorpus.Profile) {
	quietStderr(b)
	dir := b.TempDir()
	if err := benchcorpus.Write(dir, p); err != nil {
		b.Fatal(err)
	}
	// The corpus settings carry a few ordinary findings (no deny entry for key
	// files, committed hooks), so 1 is expected; 2 means the scan itself failed.
	if code := run(benchArgs(dir), strings.NewReader(""), io.Discard, io.Discard); code > 1 {
		b.Fatalf("scan of the generated corpus failed with exit code %d", code)
	}
	b.ReportAllocs()
	for b.Loop() {
		run(benchArgs(dir), strings.NewReader(""), io.Discard, io.Discard)
	}
}

// BenchmarkScan_Repo is a whole scan, discovery to JSON output, of a project
// sized like a large agent repository (#1016).
func BenchmarkScan_Repo(b *testing.B) { benchScan(b, benchcorpus.Repo) }

// BenchmarkScan_Large is the same for a tree sized like a --user scan of a
// home directory with many skills and plugins.
func BenchmarkScan_Large(b *testing.B) { benchScan(b, benchcorpus.Large) }

var initTrace = regexp.MustCompile(`(?m)^init github\.com/cfgaudit/cfgaudit/rules @\S+ ms, ([0-9.]+) ms clock, (\d+) bytes, (\d+) allocs`)

// BenchmarkInit_Rules reports what the rules package costs at startup, mostly
// regexp compilation, which every invocation pays before it scans anything.
// Package init runs once per process, so each iteration starts this test
// binary again with GODEBUG=inittrace=1 and reads the rules line.
func BenchmarkInit_Rules(b *testing.B) {
	var ms, bytes, allocs float64
	for b.Loop() {
		cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^$") //nolint:gosec // G204: re-runs this test binary
		cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			b.Fatalf("%v: %s", err, out)
		}
		m := initTrace.FindSubmatch(out)
		if m == nil {
			b.Fatalf("no init trace for the rules package in:\n%s", out)
		}
		v, _ := strconv.ParseFloat(string(m[1]), 64)
		ms += v
		v, _ = strconv.ParseFloat(string(m[2]), 64)
		bytes += v
		v, _ = strconv.ParseFloat(string(m[3]), 64)
		allocs += v
	}
	n := float64(b.N)
	b.ReportMetric(ms/n, "init-ms/op")
	b.ReportMetric(bytes/n, "init-B/op")
	b.ReportMetric(allocs/n, "init-allocs/op")
}
