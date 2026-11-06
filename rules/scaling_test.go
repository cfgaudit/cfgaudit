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
// until window has passed, five times, and the fastest of the five averages
// counts. Single calls of a few microseconds, and a collection that happens to
// fall into one window, are too noisy to compare. Both sizes need the same
// window: on a busy machine a short one can fit between two preemptions while
// a long call cannot, which reads as growth however often it is repeated.
func perCall(f func(), window time.Duration) time.Duration {
	best := time.Duration(1<<63 - 1)
	for range 5 {
		runtime.GC()
		calls := 0
		start := time.Now()
		for calls == 0 || time.Since(start) < window {
			f()
			calls++
		}
		if d := time.Since(start) / time.Duration(calls); d < best {
			best = d
		}
	}
	return best
}

// scalingAttempts is how many times a run time over the limit is measured
// before the test fails.
const scalingAttempts = 3

// measureScalingTime reports the time one call takes on the small and the large
// input, and whether the ratio stays within the limit. An attempt over the
// limit is measured again: noise only makes a call slower, so one attempt
// within the limit shows the rule is, and a superlinear rule exceeds it every
// time. A stall can last longer than the windows of perCall, which is what a
// single attempt cannot tell from growth (#1484).
func measureScalingTime(measure func() (small, large time.Duration)) (st, lt time.Duration, ok bool) {
	for range scalingAttempts {
		st, lt = measure()
		if lt <= 100*time.Microsecond || lt <= 4*scalingFactor*st {
			return st, lt, true
		}
	}
	return st, lt, false
}

// TestRulesScaleLinearly runs every rule on inputs of size n and 8·n and fails
// when its allocations or its run time grow clearly faster than the input
// (#1105). A nested loop over the servers, hooks, permission entries or lines
// of one file grows 64-fold here; a linear rule about 8-fold. The limits are
// generous so shared runners do not make the test flaky: allocations may grow
// 3·8-fold, and time 4·8-fold once one call on the larger input takes more
// than 100 µs, on one of scalingAttempts attempts. CI runs it under the race
// detector, which slows both sizes alike, so the ratio holds there too.
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
				once := time.Since(start)
				if once < 100*time.Microsecond {
					return
				}
				window := max(once, time.Millisecond)
				st, lt, ok := measureScalingTime(func() (time.Duration, time.Duration) {
					return perCall(func() { r.Check(small) }, window), perCall(func() { r.Check(large) }, window)
				})
				if !ok {
					t.Errorf("run time grows %.0f-fold (%v -> %v) for an input %d times larger", float64(lt)/float64(max(st, 1)), st, lt, scalingFactor)
				}
			})
		}
	}
}

// TestMeasureScalingTime locks the retry: a slow attempt does not fail the test
// by itself, and every attempt has to exceed the limit.
func TestMeasureScalingTime(t *testing.T) {
	const us = time.Microsecond
	within := [2]time.Duration{100 * us, 800 * us}
	stalled := [2]time.Duration{us, 50 * time.Millisecond}
	cases := []struct {
		name      string
		attempts  [][2]time.Duration
		wantCalls int
		wantOK    bool
	}{
		{"within the limit", [][2]time.Duration{within}, 1, true},
		{"exactly the limit", [][2]time.Duration{{100 * us, 3200 * us}}, 1, true},
		{"large input too fast to compare", [][2]time.Duration{{us, 100 * us}}, 1, true},
		{"a stall in the first attempt", [][2]time.Duration{stalled, within}, 2, true},
		{"two stalls in a row", [][2]time.Duration{stalled, stalled, within}, 3, true},
		{"over the limit every time", [][2]time.Duration{stalled, stalled, stalled}, scalingAttempts, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			st, lt, ok := measureScalingTime(func() (time.Duration, time.Duration) {
				a := c.attempts[calls]
				calls++
				return a[0], a[1]
			})
			if ok != c.wantOK || calls != c.wantCalls {
				t.Fatalf("ok = %v after %d calls, want %v after %d", ok, calls, c.wantOK, c.wantCalls)
			}
			if last := c.attempts[calls-1]; st != last[0] || lt != last[1] {
				t.Errorf("got %v -> %v, want the last attempt %v -> %v", st, lt, last[0], last[1])
			}
		})
	}
}

// scalingExempt lists rule/input pairs that are superlinear by design, with
// the reason. Keep it empty unless there is no linear way to do the check.
var scalingExempt = map[string]string{}
