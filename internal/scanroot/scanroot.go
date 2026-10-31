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
}

var (
	mu       sync.Mutex
	root     string // the scanned directory, absolute and cleaned
	resolved string // root with its own symlinks resolved
	escapes  []Escape
	seen     map[string]bool
	failed   map[string]bool // paths that exist but could not be read
)

// Set makes dir the scanned directory and forgets earlier escapes. An empty
// dir turns the check off.
func Set(dir string) error {
	mu.Lock()
	defer mu.Unlock()
	root, resolved, escapes, seen, failed = "", "", nil, nil, map[string]bool{}
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
	if err := check(path); err != nil {
		return nil, err
	}
	if err := notADirectory(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is checked against the scanned directory above
	return data, absentOrRecorded(absentErr(err, path), path)
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
	entries, err := os.ReadDir(path)
	return entries, absentOrRecorded(absentErr(err, path), path)
}

// Stat is os.Stat with ReadFile's handling of a path that exists but cannot be
// read.
func Stat(path string) (fs.FileInfo, error) {
	info, err := os.Stat(path)
	return info, absentOrRecorded(absentErr(err, path), path)
}

// WalkDir is filepath.WalkDir that records a directory it cannot list or a
// path it cannot stat, and skips it, instead of handing fn the error. Absent
// paths still reach fn, as before.
func WalkDir(root string, fn fs.WalkDirFunc) error {
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
		if _, err := os.Lstat(pattern); absentOrRecorded(err, pattern) != nil {
			return nil
		}
		return []string{pattern}
	}
	dir, file := filepath.Split(pattern)
	dir = filepath.Clean(dir)
	dirs := []string{dir}
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
	}
	return &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
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
