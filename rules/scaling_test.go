// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/cfgaudit/cfgaudit/internal/benchcorpus"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// scalingFactor is how much larger the second input is than the first.
const scalingFactor = 8

// scalingInput builds a target of size n.
type scalingInput struct {
	name  string
	small int
	build func(t *testing.T, n int) *Target
}

func scalingSettings(t *testing.T, json string) *Target {
	t.Helper()
	s, err := parser.ParseSettingsBytes([]byte(json), "scale/settings.json")
	if err != nil {
		t.Fatal(err)
	}
	return &Target{SettingsFile: "scale/settings.json", Settings: s}
}

var scalingInputs = []scalingInput{
	{"instruction lines", 400, func(_ *testing.T, n int) *Target {
		return instructionTarget("CLAUDE.md", benchcorpus.Instruction(n))
	}},
	{"permission entries", 50, func(t *testing.T, n int) *Target {
		return scalingSettings(t, benchcorpus.LargeSettings(n))
	}},
	{"MCP servers", 25, func(t *testing.T, n int) *Target {
		return scalingSettings(t, benchcorpus.ManyMCPServers(n))
	}},
	{"hook commands", 25, func(t *testing.T, n int) *Target {
		return scalingSettings(t, benchcorpus.ManyHooks(n))
	}},
}

// perCall is the time one call of f takes: after a garbage collection, f runs
// until a millisecond has passed, five times, and the fastest of the five
// averages counts. Single calls of a few microseconds, and a collection that
// happens to fall into one window, are too noisy to compare.
func perCall(f func()) time.Duration {
	best := time.Duration(1<<63 - 1)
	for range 5 {
		runtime.GC()
		calls := 0
		start := time.Now()
		for calls == 0 || time.Since(start) < time.Millisecond {
			f()
			calls++
		}
		if d := time.Since(start) / time.Duration(calls); d < best {
			best = d
		}
	}
	return best
}

// TestRulesScaleLinearly runs every rule on inputs of size n and 8·n and fails
// when its allocations or its run time grow clearly faster than the input
// (#1105). A nested loop over the servers, hooks, permission entries or lines
// of one file grows 64-fold here; a linear rule about 8-fold. The limits are
// generous so shared runners do not make the test flaky: allocations may grow
// 3·8-fold, and time 4·8-fold once one call on the larger input takes more
// than 100 µs. CI
// runs it under the race detector, which slows both sizes alike, so the
// ratio holds there too.
func TestRulesScaleLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("measures every rule on large inputs")
	}
	for _, in := range scalingInputs {
		small := in.build(t, in.small)
		large := in.build(t, in.small*scalingFactor)
		for _, r := range All {
			r := r
			t.Run(fmt.Sprintf("%s/%s", in.name, r.ID()), func(t *testing.T) {
				if exempt := scalingExempt[r.ID()+"/"+in.name]; exempt != "" {
					t.Skip(exempt)
				}
				sa := testing.AllocsPerRun(3, func() { r.Check(small) })
				la := testing.AllocsPerRun(3, func() { r.Check(large) })
				if la > 3*scalingFactor*sa+200 {
					t.Errorf("allocations grow %.0f-fold (%.0f -> %.0f) for an input %d times larger", la/max(sa, 1), sa, la, scalingFactor)
				}
				// A rule whose call on the larger input takes under 100 µs is
				// not worth timing precisely. Noise only makes a single call
				// slower, never faster, so one fast call is enough to tell.
				start := time.Now()
				r.Check(large)
				if time.Since(start) < 100*time.Microsecond {
					return
				}
				st := perCall(func() { r.Check(small) })
				lt := perCall(func() { r.Check(large) })
				if lt > 100*time.Microsecond && lt > 4*scalingFactor*st {
					t.Errorf("run time grows %.0f-fold (%v -> %v) for an input %d times larger", float64(lt)/float64(max(st, 1)), st, lt, scalingFactor)
				}
			})
		}
	}
}

// scalingExempt lists rule/input pairs that are superlinear by design, with
// the reason. Keep it empty unless there is no linear way to do the check.
var scalingExempt = map[string]string{}
