// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package benchcorpus

import (
	"os"
	"testing"
)

// TestWriteReleaseBenchInput writes the input that release-bench.yml scans with
// every release (#1619) to $CFGAUDIT_BENCH_INPUT. Without the variable it does
// nothing, so it never runs as part of the test suite.
func TestWriteReleaseBenchInput(t *testing.T) {
	dir := os.Getenv("CFGAUDIT_BENCH_INPUT")
	if dir == "" {
		t.Skip("CFGAUDIT_BENCH_INPUT is not set")
	}
	if err := Write(dir, Large); err != nil {
		t.Fatal(err)
	}
}
