// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// A lock file records the trust-relevant agent configuration of a
// repository: every command that runs on its own, every MCP server, every
// script such a command starts, every instruction file and every approval
// setting (#999). A rule reports only what it knows, and about half of the
// repository-borne agent advisories matched no rule, so `cfgaudit lock
// --check` fails CI on any such change until the lock is updated on purpose,
// which puts the change in front of a reviewer.
type lockFile struct {
	Version int          `json:"version"`
	Entries []lockEntry  `json:"entries"`
	Files   []lockedFile `json:"files"`
}

// lockEntry is a rules.TrustEntry with its file relative to the scanned
// directory.
type lockEntry rules.TrustEntry

// lockedFile is a scanned agent file and the SHA-256 of its content, compared
// only with --strict-hash.
type lockedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

const lockVersion = 1

// defaultLockFile is the lock's name in the scanned directory.
const defaultLockFile = ".cfgaudit.lock"

// lockOutput runs `cfgaudit lock [--check] [--strict-hash] [-o file]
// [--plugins dir] [--user] [dir]`.
func lockOutput(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("lock", flag.ContinueOnError)
	fset.SetOutput(stderr)
	check := fset.Bool("check", false, "compare the current configuration with the lock file and exit 1 when they differ")
	strictHash := fset.Bool("strict-hash", false, "with --check, also compare the content of every agent file, so a prose edit is a difference too")
	var out string
	fset.StringVar(&out, "o", "", "lock file (default: .cfgaudit.lock in the scanned directory)")
	fset.StringVar(&out, "output", "", "same as -o")
	plugins := fset.String("plugins", "", "also lock a Claude Code plugin/skill package directory")
	user := fset.Bool("user", false, "also lock the user-global configuration")
	positional, err := parseInterleaved(fset, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(positional) > 1 {
		_, _ = fmt.Fprintln(stderr, "cfgaudit lock: at most one directory")
		return 2
	}
	dir := "."
	if len(positional) == 1 {
		dir = positional[0]
	}
	if out == "" {
		out = filepath.Join(dir, defaultLockFile)
	}
	if err := scanroot.Set(dir); err != nil {
		_, _ = fmt.Fprintf(stderr, "cfgaudit lock: %v\n", err)
		return 2
	}
	defer func() { _ = scanroot.Set("") }()
	targets, err := buildTargets(dir, *user)
	if err == nil {
		targets, err = withPackageTargets(dir, *plugins, *user, targets)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cfgaudit lock: %v\n", err)
		return 2
	}
	if errs := scanroot.ReadErrors(); len(errs) > 0 {
		_, _ = fmt.Fprintf(stderr, "cfgaudit lock: could not read %s; the lock would be incomplete\n", strings.Join(errs, ", "))
		return 2
	}
	current := buildLock(dir, targets)
	if !*check {
		data, _ := json.MarshalIndent(current, "", "  ")                     // strings and ints only
		if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil { // #nosec G306,G703 -- the user names the file; it is committed with the repository
			_, _ = fmt.Fprintf(stderr, "cfgaudit lock: %v\n", err)
			return 2
		}
		entries := "entries"
		if len(current.Entries) == 1 {
			entries = "entry"
		}
		_, _ = fmt.Fprintf(stderr, "cfgaudit: wrote %d %s for %d %s to %s\n", len(current.Entries), entries, len(current.Files), pluralize("file", len(current.Files)), out)
		return 0
	}
	locked, err := loadLock(out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cfgaudit lock: %v; write it with `cfgaudit lock`\n", err)
		return 2
	}
	diff := lockDiff(locked, current, *strictHash)
	if len(diff) == 0 {
		_, _ = fmt.Fprintf(stdout, "cfgaudit: the agent configuration matches %s\n", out)
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "cfgaudit: the agent configuration differs from %s:\n", out)
	for _, d := range diff {
		_, _ = fmt.Fprintf(stdout, "  %s\n", d)
	}
	_, _ = fmt.Fprintf(stdout, "Review the %s, then run `cfgaudit lock` and commit the lock with it.\n", pluralize("change", len(diff)))
	return 1
}

// buildLock collects the trust entries and the agent files of targets.
func buildLock(dir string, targets []*rules.Target) lockFile {
	l := lockFile{Version: lockVersion, Entries: []lockEntry{}, Files: []lockedFile{}}
	seen := map[lockEntry]bool{}
	files := map[string]bool{}
	for _, t := range targets {
		for _, e := range rules.TrustEntries(t) {
			e.File = baselinePath(dir, e.File)
			if le := lockEntry(e); !seen[le] {
				seen[le] = true
				l.Entries = append(l.Entries, le)
			}
		}
		for _, f := range targetFiles(t) {
			files[f] = true
		}
	}
	for f := range files {
		data, err := scanroot.ReadFile(f)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		l.Files = append(l.Files, lockedFile{Path: baselinePath(dir, f), SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(l.Entries, func(i, j int) bool {
		return lockKey(l.Entries[i])+"\x00"+l.Entries[i].Value < lockKey(l.Entries[j])+"\x00"+l.Entries[j].Value
	})
	sort.Slice(l.Files, func(i, j int) bool { return l.Files[i].Path < l.Files[j].Path })
	return l
}

// targetFiles returns the files a target was read from: every string field
// named like SettingsFile or VSCodeTasksFile, the instruction file and the
// launched scripts. Reading the fields keeps the list in step with the
// discovery when a new file kind is added.
func targetFiles(t *rules.Target) []string {
	var out []string
	v := reflect.ValueOf(t).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.Type.Kind() == reflect.String && strings.HasSuffix(f.Name, "File") {
			if s := v.Field(i).String(); s != "" {
				out = append(out, s)
			}
		}
	}
	for _, s := range t.LaunchedScripts {
		out = append(out, s.File)
	}
	return out
}

// loadLock reads a lock file written by lockOutput.
func loadLock(path string) (*lockFile, error) {
	data, err := os.ReadFile(path) // #nosec G304,G703 -- the user names the lock file
	if err != nil {
		return nil, err
	}
	var l lockFile
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if l.Version != lockVersion {
		return nil, fmt.Errorf("%s: unsupported lock version %d (want %d)", path, l.Version, lockVersion)
	}
	return &l, nil
}

// lockKey is the identity of an entry apart from its value.
func lockKey(e lockEntry) string {
	return e.File + "\x00" + e.Kind + "\x00" + e.Name
}

// lockKindNames phrase an entry kind in the difference list.
var lockKindNames = map[string]string{
	"command":      "command",
	"mcp":          "MCP server",
	"script":       "launched script",
	"instructions": "instruction file",
	"setting":      "setting",
}

// lockDiff lists the differences between the locked and the current state,
// one line per entry: what was added, removed or changed. A key with one
// value on each side is a change; otherwise the values are listed as added
// and removed. With strictHash the agent files are compared too.
func lockDiff(locked *lockFile, current lockFile, strictHash bool) []string {
	group := func(es []lockEntry) map[string][]string {
		m := map[string][]string{}
		for _, e := range es {
			m[lockKey(e)] = append(m[lockKey(e)], e.Value)
		}
		return m
	}
	before, after := group(locked.Entries), group(current.Entries)
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []string
	for _, k := range sorted {
		parts := strings.SplitN(k, "\x00", 3)
		what := lockKindNames[parts[1]] + " " + parts[2] + " in " + parts[0]
		switch parts[1] {
		case "instructions":
			what = lockKindNames[parts[1]] + " " + parts[0]
		case "script":
			what = lockKindNames[parts[1]] + " " + parts[0] + " (" + parts[2] + ")"
		}
		b, a := before[k], after[k]
		if len(b) == 1 && len(a) == 1 {
			if b[0] != a[0] {
				out = append(out, "changed "+what+": "+quoteValue(parts[1], b[0])+" -> "+quoteValue(parts[1], a[0]))
			}
			continue
		}
		for _, v := range minus(a, b) {
			out = append(out, "new "+what+withValue(parts[1], v))
		}
		for _, v := range minus(b, a) {
			out = append(out, "removed "+what+withValue(parts[1], v))
		}
	}
	if strictHash {
		bf, af := map[string]string{}, map[string]string{}
		for _, f := range locked.Files {
			bf[f.Path] = f.SHA256
		}
		for _, f := range current.Files {
			af[f.Path] = f.SHA256
			if old, ok := bf[f.Path]; !ok {
				out = append(out, "new file "+f.Path)
			} else if old != f.SHA256 {
				out = append(out, "changed file "+f.Path)
			}
		}
		for _, f := range locked.Files {
			if _, ok := af[f.Path]; !ok {
				out = append(out, "removed file "+f.Path)
			}
		}
	}
	return out
}

// minus returns the values of a that b does not have, counting repeats.
func minus(a, b []string) []string {
	left := map[string]int{}
	for _, v := range b {
		left[v]++
	}
	var out []string
	for _, v := range a {
		if left[v] > 0 {
			left[v]--
			continue
		}
		out = append(out, v)
	}
	return out
}

func withValue(kind, v string) string {
	if v == "" {
		return ""
	}
	return ": " + quoteValue(kind, v)
}

// quoteValue shows a script's hash as "content <first 12 hex>".
func quoteValue(kind, v string) string {
	if kind == "script" && len(v) > 12 {
		return "content " + v[:12]
	}
	return "`" + v + "`"
}
