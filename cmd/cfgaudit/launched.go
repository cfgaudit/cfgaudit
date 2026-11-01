// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// maxLaunchedScript caps how much of a launched script is read (#1217).
const maxLaunchedScript = 4 << 20

// launchedEdge is how much of each end of a script over maxLaunchedScript is
// read for CFG119 (#1270). A payload padded past the limit used to go unread;
// its decoder and the start of its data sit at the two ends.
const launchedEdge = 64 << 10

// scriptInterpreters start the file named by their first operand. A value of
// true means the interpreter takes a subcommand first (`bun run x.js`,
// `deno run x.ts`).
var scriptInterpreters = map[string]bool{
	"node": false, "nodejs": false, "tsx": false, "ts-node": false, "bun": true, "deno": true,
	"python": false, "python3": false, "bash": false, "sh": false, "zsh": false, "dash": false,
	"pwsh": false, "powershell": false, "ruby": false, "perl": false, "php": false,
}

// projectDirVars are the variables agents and editors set to the project
// root when they run a command.
var projectDirVarRe = regexp.MustCompile(`^\$\{?(?:CLAUDE_PROJECT_DIR|workspaceFolder|GEMINI_PROJECT_DIR|CURSOR_PROJECT_DIR|QWEN_PROJECT_DIR|PWD)\}?`)

// commandSplitRe splits a command line into its simple commands.
var commandSplitRe = regexp.MustCompile(`&&|\|\||[;|&\n]`)

// scriptExtRe matches the file name of a script a command may start directly.
var scriptExtRe = regexp.MustCompile(`\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|mts|rb|pl|php|ps1)$`)

// launchedPaths returns the repository-relative paths of the scripts a command
// starts: an interpreter followed by a path (`node .claude/x.mjs`, `bash
// scripts/x.sh`, `bun run x.js`, `pwsh -File x.ps1`), or a script path run
// directly (`./scripts/x.sh`). A path made of the project-root variable is
// resolved; one with any other variable, an absolute path and a home path are
// not, since they leave the repository or cannot be known.
func launchedPaths(command string) []string {
	var out []string
	for _, seg := range commandSplitRe.Split(command, -1) {
		f := strings.Fields(seg)
		i := 0
		for i < len(f) && (strings.Contains(f[i], "=") && !strings.HasPrefix(f[i], "-") || f[i] == "exec" || f[i] == "env" || f[i] == "sudo" || f[i] == "command") {
			i++
		}
		if i >= len(f) {
			continue
		}
		head := strings.Trim(trimGrouping(f[i]), `"'`)
		if f[i] == "npx" || f[i] == "bunx" {
			i++
			for i < len(f) && strings.HasPrefix(f[i], "-") {
				i++
			}
			if i >= len(f) || (f[i] != "tsx" && f[i] != "ts-node") {
				continue
			}
			head = f[i]
		}
		base := filepath.Base(head)
		if sub, ok := scriptInterpreters[base]; ok {
			j := i + 1
			if sub && j < len(f) && f[j] == "run" {
				j++
			}
			for j < len(f) {
				a := strings.Trim(trimGrouping(f[j]), `"'`)
				if a == "-File" || a == "-file" {
					j++
					continue
				}
				if strings.HasPrefix(a, "-") {
					// -c, -e, -m and the like take inline code or a module.
					if a == "-c" || a == "-e" || a == "-m" || a == "--eval" || a == "-Command" {
						j = len(f)
					}
					j++
					continue
				}
				if p := repoPath(a); p != "" {
					out = append(out, p)
				}
				break
			}
			continue
		}
		if p := repoPath(head); p != "" && scriptExtRe.MatchString(p) && (strings.Contains(head, "/") || strings.HasPrefix(head, ".")) {
			out = append(out, p)
		}
	}
	return out
}

// readEdges returns the first and last launchedEdge bytes of a large file,
// joined by a newline, or false when they are not text. A multi-byte
// character cut at an edge is dropped rather than failing the check.
func readEdges(path string, size int64) (string, bool) {
	f, err := scanroot.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, launchedEdge)
	tail := make([]byte, launchedEdge)
	if _, err := f.ReadAt(head, 0); err != nil {
		return "", false
	}
	if _, err := f.ReadAt(tail, size-launchedEdge); err != nil {
		return "", false
	}
	if bytes.IndexByte(head, 0) >= 0 || bytes.IndexByte(tail, 0) >= 0 {
		return "", false
	}
	return strings.ToValidUTF8(string(head), "") + "\n" + strings.ToValidUTF8(string(tail), ""), true
}

// trimGrouping drops the shell grouping around a word that is not part of
// it: the "(" or "{" that opens a subshell or group before an interpreter,
// and a ")" that closes one after a path, as in `(command -v node && node
// ./x.js) || ...` (#1265). A balanced pair inside a path, such as Next.js's
// `app/(site)/page.js`, stays.
func trimGrouping(w string) string {
	w = strings.TrimLeft(w, "{")
	for strings.HasPrefix(w, "(") && strings.Count(w, "(") > strings.Count(w, ")") {
		w = w[1:]
	}
	for strings.HasSuffix(w, ")") && strings.Count(w, ")") > strings.Count(w, "(") {
		w = w[:len(w)-1]
	}
	return strings.TrimRight(w, "}")
}

// repoPath turns a command operand into a repository-relative slash path, or
// "" when it leaves the repository or depends on a variable.
func repoPath(a string) string {
	a = strings.NewReplacer(`"`, "", "'", "").Replace(a)
	a = projectDirVarRe.ReplaceAllString(a, ".")
	switch {
	case a == "", strings.ContainsAny(a, "$`*?"), strings.HasPrefix(a, "~"), filepath.IsAbs(a), strings.HasPrefix(a, "/"):
		return ""
	}
	p := filepath.ToSlash(filepath.Clean(a))
	if p == "." || strings.HasPrefix(p, "../") || p == ".." {
		return ""
	}
	return p
}

// siblingRe matches a quoted file name with a script extension, the way a
// launcher names the file it runs next to it.
var siblingRe = regexp.MustCompile("[\"'`]([A-Za-z0-9_.-]+\\.(?:m?js|cjs|ts|py|sh))[\"'`]")

// runsFileRe matches code that starts another process or runtime.
var runsFileRe = regexp.MustCompile(`\b(?:execFileSync|execSync|spawnSync|spawn|execFile|child_process|subprocess|os\.system|Bun\.spawn|Deno\.Command)\b`)

// attachLaunchedScripts reads the repository scripts that the targets'
// auto-run commands start and attaches each to the first target that starts
// it (#1217). A script that names a sibling file and starts a process is
// followed one step further, for CFG119 only (#1218): a launcher that
// downloads a runtime to run the payload next to it is the usual shape.
func attachLaunchedScripts(dir string, targets []*rules.Target) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return
	}
	type script struct {
		owner     *rules.Target
		rel       string
		content   string
		partial   bool
		size      int64
		labels    []string
		launchers map[string]bool
		via       string
	}
	byPath := map[string]*script{}
	var order []string
	read := func(rel string) (content string, partial bool, size int64, ok bool) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if fi, err := scanroot.Stat(path); err == nil && fi.Mode().IsRegular() && fi.Size() > maxLaunchedScript {
			edges, ok := readEdges(path, fi.Size())
			return edges, true, fi.Size(), ok
		}
		data, err := scanroot.ReadFile(path)
		if err != nil || len(data) > maxLaunchedScript || !isTextFile(data) {
			return "", false, 0, false
		}
		return string(data), false, int64(len(data)), true
	}
	add := func(owner *rules.Target, rel, label, launcher, via string) {
		s, ok := byPath[rel]
		if !ok {
			content, partial, size, ok := read(rel)
			if !ok {
				return
			}
			s = &script{owner: owner, rel: rel, content: content, partial: partial, size: size, launchers: map[string]bool{}, via: via}
			byPath[rel] = s
			order = append(order, rel)
		}
		if label != "" && !slices.Contains(s.labels, label) {
			s.labels = append(s.labels, label)
		}
		if launcher != "" {
			if abs, err := filepath.Abs(launcher); err == nil {
				launcher = abs
			}
			s.launchers[relSlash(root, launcher)] = true
		}
	}
	for _, t := range targets {
		for _, lc := range rules.LaunchCommands(t) {
			for _, rel := range launchedPaths(lc.Command) {
				add(t, rel, "the "+lc.Label, lc.File, "")
			}
		}
	}
	for _, rel := range append([]string(nil), order...) {
		s := byPath[rel]
		if !runsFileRe.MatchString(s.content) {
			continue
		}
		for _, m := range siblingRe.FindAllStringSubmatch(s.content, -1) {
			sib := filepath.ToSlash(filepath.Join(filepath.Dir(rel), m[1]))
			if sib == rel {
				continue
			}
			add(s.owner, sib, "", "", rel)
			if t := byPath[sib]; t != nil && t.via == rel {
				for l := range s.launchers {
					t.launchers[l] = true
				}
			}
		}
	}
	for _, rel := range order {
		s := byPath[rel]
		launchers := make([]string, 0, len(s.launchers))
		for l := range s.launchers {
			launchers = append(launchers, l)
		}
		sort.Strings(launchers)
		label := "script " + rel + ", started by " + strings.Join(s.labels, " and ") + ","
		if s.via != "" {
			label = "file " + rel + ", run by the launched script " + s.via + ","
		}
		s.owner.LaunchedScripts = append(s.owner.LaunchedScripts, rules.LaunchedScript{
			Label: label, File: filepath.Join(dir, filepath.FromSlash(rel)), Content: s.content, Launchers: launchers, Via: s.via,
			Partial: s.partial, Size: s.size,
		})
	}
}
