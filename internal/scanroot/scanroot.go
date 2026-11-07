// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package scanroot keeps reads of repository content inside the scanned
// directory.
//
// A repository can commit a config file as a symbolic link. The operating
// system follows it for anyone who opens the path, so a link to a file outside
// the repository would make cfgaudit read a file on the scanning machine, quote
// fragments of it in parser errors, and report findings for content the
// repository does not contain (GHSA-x9h6-c6v9-v699). Every read of a discovered
// file goes through ReadFile or Open here: a path under the scanned directory
// whose real location is outside it is not opened, it is recorded, and the
// caller sees it as absent. CFG115 reports the recorded links.
//
// A path that exists but cannot be read, such as one without read permission,
// is recorded the same way and also reads as absent: the scan goes on, and the
// caller reports the recorded paths as an incomplete scan (#1043). It is not a
// property of the committed file, since git does not record read permissions.
// ReadDir, Stat, WalkDir and Glob do the same for directory listings.
//
// Paths outside the scanned directory are not checked. Those are the files the
// user names (--user, --config, --plugins), and a user-scope settings file that
// is a symlink into a dotfiles checkout is ordinary.
package scanroot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// Escape is a path under the scanned directory that resolves outside it.
// Link is the link text as committed (os.Readlink of the first link on the
// way), never the resolved location on the scanning machine.
type Escape struct {
	Path string
	Link string
	// Walked marks a link the repository walk found by its text (#1417), which
	// nothing has to open: its target usually does not exist on this machine.
	Walked bool
}

var (
	mu       sync.Mutex
	root     string // the scanned directory, absolute and cleaned
	resolved string // root with its own symlinks resolved
	escapes  []Escape
	seen     map[string]bool
	failed   map[string]bool // paths that exist but could not be read
	dangling map[string]bool // symlinks whose target does not exist
	// aliases maps a path cfgaudit looked for to the path committed under
	// another spelling of it (#990); listings caches directory names for
	// that lookup.
	aliases  map[string]string
	listings map[string][]string
)

// Set makes dir the scanned directory and forgets earlier escapes. An empty
// dir turns the check off.
func Set(dir string) error {
	mu.Lock()
	defer mu.Unlock()
	root, resolved, escapes, seen, failed, dangling = "", "", nil, nil, map[string]bool{}, map[string]bool{}
	aliases, listings = map[string]string{}, map[string][]string{}
	if dir == "" {
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	root, resolved, seen = filepath.Clean(abs), filepath.Clean(real), map[string]bool{}
	return nil
}

// Escapes returns the links recorded since the last Set, in the order found.
func Escapes() []Escape {
	mu.Lock()
	defer mu.Unlock()
	return append([]Escape(nil), escapes...)
}

// Aliases returns, for each path cfgaudit looked for that the repository
// commits under another spelling, that spelling (#990).
func Aliases() map[string]string {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]string, len(aliases))
	for k, v := range aliases {
		out[k] = v
	}
	return out
}

// caseResolve returns path as committed when it is absent under the spelling
// asked for but present under another spelling of its components, and
// records the alias (#990). On macOS and Windows the default filesystem
// ignores case, so an agent opens .Cursor/mcp.json as its .cursor/mcp.json;
// on a case-sensitive filesystem the scan would not find it. A component with
// more than one other spelling is left alone. Paths outside the scanned
// directory are returned as they are.
func caseResolve(path string) string {
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return path
	}
	mu.Lock()
	defer mu.Unlock()
	if root == "" {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil || !within(filepath.Clean(abs), root) || filepath.Clean(abs) == root {
		return path
	}
	cur, ok := aliases[abs]
	if !ok {
		if cur = resolveComponents(abs); cur == "" {
			return path
		}
		aliases[abs] = cur
	}
	if !filepath.IsAbs(path) {
		if wd, err := os.Getwd(); err == nil {
			if r, err := filepath.Rel(wd, cur); err == nil {
				return r
			}
		}
	}
	return cur
}

// resolveComponents returns abs with each component that is absent replaced
// by its one other spelling in the directory, or "" when there is none, more
// than one, or no component changed. mu is held.
func resolveComponents(abs string) string {
	rel, _ := filepath.Rel(root, filepath.Clean(abs))
	cur, changed := root, false
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		next := filepath.Join(cur, part)
		if _, err := os.Lstat(next); err == nil {
			cur = next
			continue
		}
		names, ok := listings[cur]
		if !ok {
			entries, _ := os.ReadDir(cur)
			for _, e := range entries {
				names = append(names, e.Name())
			}
			listings[cur] = names
		}
		match := ""
		for _, n := range names {
			if strings.EqualFold(n, part) {
				if match != "" {
					return ""
				}
				match = n
			}
		}
		if match == "" {
			return ""
		}
		cur, changed = filepath.Join(cur, match), true
	}
	if !changed {
		return ""
	}
	return cur
}

// ReadErrors returns the paths recorded since the last Set that exist but
// could not be read, sorted. A file inside a directory that cannot be listed
// or entered is recorded as that directory, so a locked .vscode/ is one entry
// rather than one per file cfgaudit looks for in it.
func ReadErrors() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(failed))
	for p := range failed {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// absentOrRecorded passes a nil or absent err through. Any other error is
// recorded against the path that blocks the read and comes back as a
// not-exist error, so every caller treats the path as absent.
func absentOrRecorded(err error, path string) error {
	if err == nil || IsAbsent(err) {
		return err
	}
	blocked := blocker(path)
	mu.Lock()
	if failed == nil {
		failed = map[string]bool{}
	}
	failed[blocked] = true
	mu.Unlock()
	return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// blocker is the path a failed read of path is reported against: path itself
// when it exists, otherwise its nearest ancestor that does, which is then a
// directory that cannot be entered.
func blocker(path string) string {
	for p := path; ; {
		if _, err := os.Lstat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		p = parent
	}
}

// ReadFile is os.ReadFile for repository content. A directory where a file is
// expected, and a path through a file where a directory is expected, read as
// absent (#828): a repository with a .rules folder or an empty .codex file
// used to stop the whole scan.
func ReadFile(path string) ([]byte, error) {
	path = caseResolve(path)
	if err := check(path); err != nil {
		return nil, err
	}
	if err := notADirectory(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is checked against the scanned directory above
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		recordDanglingLink(path)
	}
	return data, absentOrRecorded(absentErr(err, path), path)
}

// IsDanglingLink reports whether path is a symlink whose target does not exist.
func IsDanglingLink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return false
	}
	_, err = os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// recordDanglingLink records path when it is a symlink whose target does not
// exist. Every agent reads such a file as absent, so the scan does too: it is
// not a parse error (#1189) and not an incomplete scan, which would fail CI
// over a property of the repository (#1363). DanglingLinks names it.
func recordDanglingLink(path string) {
	if !IsDanglingLink(path) {
		return
	}
	mu.Lock()
	if dangling == nil {
		dangling = map[string]bool{}
	}
	dangling[path] = true
	mu.Unlock()
}

// DanglingLinks returns the symlinks read since the last Set whose target
// does not exist, sorted.
func DanglingLinks() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(dangling))
	for p := range dangling {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ReadOwnFile is ReadFile for cfgaudit's own inputs, such as a discovered
// .cfgaudit.yml: an error other than absence is returned, not recorded,
// because a config cfgaudit cannot read changes what the scan does and has to
// stop it.
func ReadOwnFile(path string) ([]byte, error) {
	if err := check(path); err != nil {
		return nil, err
	}
	if err := notADirectory(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is checked against the scanned directory above
	return data, absentErr(err, path)
}

// Open is os.Open for repository content, with ReadFile's handling of
// directories.
func Open(path string) (*os.File, error) {
	path = caseResolve(path)
	if err := check(path); err != nil {
		return nil, err
	}
	if err := notADirectory(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path) // #nosec G304 -- path is checked against the scanned directory above
	return f, absentOrRecorded(absentErr(err, path), path)
}

// ReadDir is os.ReadDir with ReadFile's handling of a path that exists but
// cannot be read.
func ReadDir(path string) ([]fs.DirEntry, error) {
	path = caseResolve(path)
	entries, err := os.ReadDir(path)
	return entries, absentOrRecorded(absentErr(err, path), path)
}

// Stat is os.Stat with ReadFile's handling of a path that exists but cannot be
// read.
func Stat(path string) (fs.FileInfo, error) {
	path = caseResolve(path)
	info, err := os.Stat(path)
	return info, absentOrRecorded(absentErr(err, path), path)
}

// WalkDir is filepath.WalkDir that records a directory it cannot list or a
// path it cannot stat, and skips it, instead of handing fn the error. Absent
// paths still reach fn, as before.
func WalkDir(root string, fn fs.WalkDirFunc) error {
	root = caseResolve(root)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil && !IsAbsent(err) {
			_ = absentOrRecorded(err, path)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		return fn(path, d, err)
	})
}

// Glob is filepath.Glob that records a directory it cannot list. filepath.Glob
// ignores such errors, so a locked .github/hooks/ matched nothing and the scan
// looked complete.
func Glob(pattern string) ([]string, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, err
	}
	return glob(pattern), nil
}

func glob(pattern string) []string {
	if !hasMeta(pattern) {
		pattern = caseResolve(pattern)
		if _, err := os.Lstat(pattern); absentOrRecorded(err, pattern) != nil {
			return nil
		}
		return []string{pattern}
	}
	dir, file := filepath.Split(pattern)
	dir = filepath.Clean(dir)
	dirs := []string{caseResolve(dir)}
	if hasMeta(dir) {
		dirs = glob(dir)
	}
	var out []string
	for _, d := range dirs {
		entries, err := ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if ok, _ := filepath.Match(file, e.Name()); ok {
				out = append(out, filepath.Join(d, e.Name()))
			}
		}
	}
	return out
}

// hasMeta reports whether path contains a filepath.Match metacharacter.
func hasMeta(path string) bool {
	magic := `*?[`
	if runtime.GOOS != "windows" {
		magic = `*?[\`
	}
	return strings.ContainsAny(path, magic)
}

// IsAbsent reports whether err means there is nothing to read at a path: it
// does not exist, or a component of it is a file rather than a directory.
func IsAbsent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// notADirectory returns a not-exist error when path is a directory.
func notADirectory(path string) error {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return nil
}

// absentErr turns an ENOTDIR from a read into a not-exist error.
func absentErr(err error, path string) error {
	if err != nil && errors.Is(err, syscall.ENOTDIR) {
		return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return err
}

// check returns a not-exist error for a path under the scanned directory whose
// real location is outside it, so every caller treats the file as absent.
func check(path string) error {
	mu.Lock()
	defer mu.Unlock()
	if root == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil || !within(filepath.Clean(abs), root) {
		return nil
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil // missing or unreadable: let the real open report it
	}
	if within(real, resolved) {
		return nil
	}
	if !seen[abs] {
		seen[abs] = true
		escapes = append(escapes, Escape{Path: abs, Link: firstLink(abs)})
	} else {
		// The walk may have got here first; a read makes it a config path.
		for i := range escapes {
			if escapes[i].Path == abs {
				escapes[i].Walked = false
			}
		}
	}
	return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// RecordLink records a symbolic link whose committed text leaves the scanned
// directory. The target is judged by that text alone and is never followed.
func RecordLink(path, link string) {
	mu.Lock()
	defer mu.Unlock()
	abs, err := filepath.Abs(path)
	if err != nil || seen[abs] {
		return
	}
	seen[abs] = true
	escapes = append(escapes, Escape{Path: abs, Link: link, Walked: true})
}

// LinkLeaves reports whether the link text of the symbolic link at path points
// outside the scanned directory. It reads the text only, so a target that does
// not exist on this machine counts as much as one that does. A leading ~ is not
// expanded by the operating system, but it is how a link names a home directory
// and no repository has a directory called that.
func LinkLeaves(path, link string) bool {
	mu.Lock()
	defer mu.Unlock()
	if root == "" {
		return false
	}
	link = filepath.FromSlash(strings.ReplaceAll(link, `\`, "/"))
	if strings.HasPrefix(link, "~") {
		return true
	}
	if isAbsLink(link) {
		clean := filepath.Clean(link)
		return !within(clean, root) && !within(clean, resolved)
	}
	abs, err := filepath.Abs(path)
	return err == nil && !within(filepath.Join(filepath.Dir(abs), link), root)
}

// isAbsLink reports an absolute link text, in the form of either system: a
// repository is written on one and scanned on another.
func isAbsLink(link string) bool {
	if filepath.IsAbs(link) || strings.HasPrefix(link, "/") || strings.HasPrefix(link, `\`) {
		return true
	}
	return len(link) > 2 && link[1] == ':' && (link[2] == '/' || link[2] == '\\')
}

// firstLink returns the text of the first symbolic link on the way from the
// scanned directory to path: the committed link that leads outside.
func firstLink(path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			if target, err := os.Readlink(cur); err == nil {
				return target
			}
			return ""
		}
	}
	return ""
}

func within(path, dir string) bool {
	if path == dir {
		return true
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
