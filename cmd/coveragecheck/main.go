// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Command coveragecheck fails when the Go lines a change adds are not covered
// by tests (#1442). It maps the lines added since a base commit onto the blocks
// of a coverage profile, so a change cannot hide behind a high repository
// total. It needs only git and the profile, which is why it also works for a
// pull request from a fork.
//
// Usage:
//
//	go test -coverpkg=./... -coverprofile=coverage.out ./...
//	go run ./cmd/coveragecheck -profile coverage.out -base origin/main
//
// The profile needs -coverpkg=./..., or a line that only another package's
// tests reach reads as uncovered. A line counts when a profile block spans it,
// so comments, declarations, tests and code that does not build on this
// platform do not.
//
// Generated files are skipped. A function that cannot be tested is excepted by
// an entry in the file named by -allow: one line each, the path, the function
// and a reason, as "cmd/x/main.go main # one-line os.Exit call". An entry
// without a reason, or for a function that no longer exists, is an error.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], ".", gitDiff, os.Stdout, os.Stderr))
}

// differ returns the unified diff, with no context lines, of the Go files in
// dir against the merge base of base and HEAD.
type differ func(dir, base string) (string, error)

// run is the whole command. It returns 0 when the change passes, 1 when it
// does not, and 2 when the check itself could not run.
func run(args []string, dir string, diff differ, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("coveragecheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "coverage.out", "coverage profile, from go test -coverpkg=./...")
	base := fs.String("base", "origin/main", "commit to compare with")
	allow := fs.String("allow", "", "file of excepted functions")
	minPercent := fs.Float64("min", 90, "lowest coverage of the changed lines, in percent")
	slack := fs.Int("slack", 5, "uncovered lines that always pass, however small the change")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r, err := check(dir, *profile, *base, *allow, diff)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "coveragecheck:", err)
		return 2
	}
	text, code := r.report(*minPercent, *slack)
	_, _ = io.WriteString(stdout, text)
	return code
}

// result is what a change adds: executable lines, and the uncovered ones per
// file.
type result struct {
	lines     int
	uncovered map[string][]int
}

func (r result) missed() int {
	n := 0
	for _, lines := range r.uncovered {
		n += len(lines)
	}
	return n
}

// report returns the text to print and the exit code. The slack keeps a small
// change from failing on one defensive error branch; the percentage is what
// stops a large one.
func (r result) report(minPercent float64, slack int) (string, int) {
	missed := r.missed()
	if r.lines == 0 {
		return "Changed coverage: no executable lines changed\n", 0
	}
	percent := 100 * float64(r.lines-missed) / float64(r.lines)
	pass := missed <= slack || percent >= minPercent
	var w strings.Builder
	fmt.Fprintf(&w, "Changed coverage: %d of %d changed lines covered, %.1f%% (needs %.1f%%, or at most %d uncovered)\n",
		r.lines-missed, r.lines, percent, minPercent, slack)
	files := make([]string, 0, len(r.uncovered))
	for f := range r.uncovered {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		for _, span := range spans(r.uncovered[f]) {
			fmt.Fprintf(&w, "  %s:%s\n", f, span)
		}
	}
	if pass {
		return w.String(), 0
	}
	return w.String(), 1
}

// spans turns sorted line numbers into "3" and "5-7".
func spans(lines []int) []string {
	var out []string
	for i := 0; i < len(lines); {
		j := i
		for j+1 < len(lines) && lines[j+1] == lines[j]+1 {
			j++
		}
		if i == j {
			out = append(out, strconv.Itoa(lines[i]))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", lines[i], lines[j]))
		}
		i = j + 1
	}
	return out
}

func check(dir, profile, base, allow string, diff differ) (result, error) {
	module, err := modulePath(filepath.Join(dir, "go.mod"))
	if err != nil {
		return result{}, err
	}
	blocks, err := readProfile(underDir(dir, profile), module)
	if err != nil {
		return result{}, err
	}
	excepted, err := readAllow(dir, allow)
	if err != nil {
		return result{}, err
	}
	text, err := diff(dir, base)
	if err != nil {
		return result{}, err
	}
	changed, err := parseDiff(text)
	if err != nil {
		return result{}, err
	}
	r := result{uncovered: map[string][]int{}}
	for file, lines := range changed {
		fileBlocks := blocks[file]
		if len(fileBlocks) == 0 {
			continue
		}
		skip, err := skipLines(dir, file, excepted[file])
		if err != nil {
			return result{}, err
		}
		if skip == nil {
			continue
		}
		for _, line := range lines {
			if skip[line] {
				continue
			}
			executable, covered := lineState(fileBlocks, line)
			if !executable {
				continue
			}
			r.lines++
			if !covered {
				r.uncovered[file] = append(r.uncovered[file], line)
			}
		}
	}
	return r, nil
}

// block is one statement block of a profile, with its hits summed over every
// test binary.
type block struct {
	start, end int
	hits       int
}

// lineState reports whether a block spans line, and whether one that does ran.
// A line can hold the end of one block and the start of the next: "if err !=
// nil {" belongs to the block before it and opens the one after it. Any block
// that ran counts, or that line would read as uncovered for an untaken branch
// whose body is what is really missing.
func lineState(blocks []block, line int) (executable, covered bool) {
	for _, b := range blocks {
		if b.start <= line && line <= b.end {
			executable = true
			covered = covered || b.hits > 0
		}
	}
	return executable, covered
}

func modulePath(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the module's own go.mod
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "module" {
			return f[1], nil
		}
	}
	return "", errors.New(path + ": no module line")
}

// profileLineRe is "path/file.go:12.3,14.2 1 0": the file, the start and end
// lines, the statements and the hits.
var profileLineRe = regexp.MustCompile(`^(.+\.go):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$`)

// readProfile returns the blocks per repository-relative file. With -coverpkg
// every test binary writes each block once, so the hits of equal blocks add up.
func readProfile(path, module string) (map[string][]block, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: a path the caller passes on the command line
	if err != nil {
		return nil, err
	}
	type key struct {
		file       string
		start, end int
	}
	hits := map[key]int{}
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if i == 0 {
			if !strings.HasPrefix(line, "mode: ") {
				return nil, errors.New(path + ": not a coverage profile")
			}
			continue
		}
		m := profileLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s:%d: malformed profile line", path, i+1)
		}
		k := key{file: strings.TrimPrefix(strings.TrimPrefix(m[1], module), "/")}
		k.start, _ = strconv.Atoi(m[2])
		k.end, _ = strconv.Atoi(m[3])
		h, _ := strconv.Atoi(m[4])
		hits[k] += h
	}
	blocks := map[string][]block{}
	for k, h := range hits {
		blocks[k.file] = append(blocks[k.file], block{start: k.start, end: k.end, hits: h})
	}
	return blocks, nil
}

// hunkRe is the header of a hunk: the old and the new start and length.
var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// parseDiff returns the added lines per file. The body of a hunk is counted,
// not read: an added line can itself look like a header.
func parseDiff(text string) (map[string][]int, error) {
	changed := map[string][]int{}
	file := ""
	skip := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, `\`) {
			continue // "\ No newline at end of file"
		}
		if skip > 0 {
			skip--
			continue
		}
		if name, ok := strings.CutPrefix(line, "+++ "); ok {
			file = strings.TrimPrefix(name, "b/")
			continue
		}
		m := hunkRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if file == "" {
			return nil, errors.New("diff has a hunk before a file name")
		}
		removed, added := 1, 1
		if m[1] != "" {
			removed, _ = strconv.Atoi(m[1])
		}
		if m[3] != "" {
			added, _ = strconv.Atoi(m[3])
		}
		start, _ := strconv.Atoi(m[2])
		for i := 0; i < added; i++ {
			changed[file] = append(changed[file], start+i)
		}
		skip = removed + added
	}
	return changed, nil
}

// underDir resolves a path from the command line, which may be absolute.
func underDir(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// readAllow returns the excepted functions per file. An unusable entry is an
// error, so the list can only hold what it says.
func readAllow(dir, path string) (map[string][]string, error) {
	excepted := map[string][]string{}
	if path == "" {
		return excepted, nil
	}
	data, err := os.ReadFile(underDir(dir, path)) //nolint:gosec // G304: a path the caller passes on the command line
	if err != nil {
		return nil, err
	}
	for i, line := range strings.Split(string(data), "\n") {
		entry, reason, _ := strings.Cut(line, "#")
		f := strings.Fields(entry)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 || strings.TrimSpace(reason) == "" {
			return nil, fmt.Errorf(`%s:%d: want "path function # reason"`, path, i+1)
		}
		fset, file, err := parseFile(dir, f[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		if funcLines(fset, file, f[1]) == nil {
			return nil, fmt.Errorf("%s:%d: %s has no function %s", path, i+1, f[0], f[1])
		}
		excepted[f[0]] = append(excepted[f[0]], f[1])
	}
	return excepted, nil
}

func parseFile(dir, file string) (*token.FileSet, *ast.File, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(dir, filepath.FromSlash(file)), nil, parser.ParseComments)
	return fset, f, err
}

// funcName is the name of a declaration as the allow file writes it: "run", or
// "Type.Method".
func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	t := d.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

// funcLines returns the lines of one function, nil when the file has none of
// that name.
func funcLines(fset *token.FileSet, f *ast.File, name string) map[int]bool {
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || funcName(d) != name {
			continue
		}
		lines := map[int]bool{}
		for l := fset.Position(d.Pos()).Line; l <= fset.Position(d.End()).Line; l++ {
			lines[l] = true
		}
		return lines
	}
	return nil
}

// skipLines returns the lines of file that do not count. It returns nil for a
// generated file, none of which counts.
func skipLines(dir, file string, excepted []string) (map[int]bool, error) {
	fset, f, err := parseFile(dir, file)
	if err != nil {
		return nil, err
	}
	if ast.IsGenerated(f) {
		return nil, nil
	}
	skip := map[int]bool{}
	for _, name := range excepted {
		for l := range funcLines(fset, f, name) {
			skip[l] = true
		}
	}
	return skip, nil
}

// gitDiff diffs the working tree against the merge base, so a change that is
// not committed yet counts too. The options fix what a user's git config could
// change about the format.
func gitDiff(dir, base string) (string, error) {
	mb, err := git(dir, "merge-base", base, "HEAD")
	if err != nil {
		return "", err
	}
	return git(dir, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
		"--diff-filter=ACMR", strings.TrimSpace(mb), "--", "*.go")
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed git subcommands; the base comes from the caller's own command line
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}
