// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/benchcorpus"
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// benchBody is one instruction file of about 4,000 lines, the size of the
// instruction content a scan of a large agent repository reads.
func benchBody() string { return benchcorpus.Instruction(4000) }

func benchRun(b *testing.B, targets ...*Target) {
	b.ReportAllocs()
	for b.Loop() {
		for _, t := range targets {
			Run(t, nil, nil)
		}
	}
}

// BenchmarkRun_InstructionContent runs every rule over neutral prose: the
// common case of a real scan, where a few percent of the lines pass the literal
// prefilter and none matches (#1016).
func BenchmarkRun_InstructionContent(b *testing.B) {
	benchRun(b, instructionTarget("CLAUDE.md", benchBody()))
}

// BenchmarkRun_Fixtures runs every rule over the settings fixtures, valid and
// invalid: the "many findings" case, which includes building the messages.
func BenchmarkRun_Fixtures(b *testing.B) {
	var targets []*Target
	for _, dir := range []string{"valid", "invalid"} {
		for _, path := range globFixtures(b, filepath.Join("..", "testdata", "settings", dir, "*.json")) {
			targets = append(targets, loadFixtureTarget(b, path))
		}
	}
	benchRun(b, targets...)
}

// BenchmarkRun_EdgeCases covers inputs where the cost per byte shows first: a
// pattern that turns expensive is visible here before it is in a whole scan.
func BenchmarkRun_EdgeCases(b *testing.B) {
	settings, err := parser.ParseSettingsBytes([]byte(benchcorpus.LargeSettings(2000)), "bench/settings.json")
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		target *Target
	}{
		{"LongLine", instructionTarget("CLAUDE.md", benchcorpus.LongLine(20000)+"\n")},
		{"DenseLine", instructionTarget("CLAUDE.md", benchcorpus.DenseLine(20000)+"\n")},
		{"LargeSettings", &Target{SettingsFile: "bench/settings.json", Settings: settings}},
	} {
		b.Run(c.name, func(b *testing.B) { benchRun(b, c.target) })
	}
}

// The benchmarks measure the no-match path only while the corpus stays clean
// and keeps reaching the regexps. These two tests hold both properties, so a
// rule change that starts matching the corpus, or a corpus change that stops
// exercising the prefilter, fails here instead of quietly moving the numbers.

func TestBenchCorpus_ScansClean(t *testing.T) {
	for _, c := range []struct{ name, content string }{
		{"Body", benchBody()},
		{"LongLine", benchcorpus.LongLine(20000)},
		{"DenseLine", benchcorpus.DenseLine(20000)},
	} {
		var got []string
		for _, f := range Run(instructionTarget("CLAUDE.md", c.content), nil, nil) {
			if f.Severity != finding.Info {
				got = append(got, f.String())
			}
		}
		if len(got) > 0 {
			t.Errorf("%s: the benchmark corpus must not produce findings, got:\n%s", c.name, strings.Join(got, "\n"))
		}
	}
}

func TestBenchCorpus_PrefilterPassRate(t *testing.T) {
	calls, pass := 0, 0
	for _, line := range strings.Split(benchBody(), "\n") {
		for _, f := range filtered {
			calls++
			if f.filter.MayMatch(line) {
				pass++
			}
		}
	}
	// A scan of a real agent repository measured 2.6% (#1016).
	if rate := float64(pass) / float64(calls); rate < 0.01 || rate > 0.06 {
		t.Errorf("prefilter pass rate on the corpus is %.2f%%, want 1%% to 6%%", 100*rate)
	}
}
