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
// Paths outside the scanned directory are not checked. Those are the files the
// user names (--user, --config, --plugins), and a user-scope settings file that
// is a symlink into a dotfiles checkout is ordinary.
package scanroot

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
)

// Set makes dir the scanned directory and forgets earlier escapes. An empty
// dir turns the check off.
func Set(dir string) error {
	mu.Lock()
	defer mu.Unlock()
	root, resolved, escapes, seen = "", "", nil, nil
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

// ReadFile is os.ReadFile for repository content.
func ReadFile(path string) ([]byte, error) {
	if err := check(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path) // #nosec G304 -- path is checked against the scanned directory above
}

// Open is os.Open for repository content.
func Open(path string) (*os.File, error) {
	if err := check(path); err != nil {
		return nil, err
	}
	return os.Open(path) // #nosec G304 -- path is checked against the scanned directory above
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
