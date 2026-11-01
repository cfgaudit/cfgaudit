// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package gitindex reads the paths a git repository tracks from its index
// file, without running git, so cfgaudit does not depend on a git binary
// (#1206).
package gitindex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// maxIndexSize bounds the index file that is read. A large monorepo index is
// tens of megabytes; anything bigger is not read.
const maxIndexSize = 256 << 20

// Tracked returns the slash-separated paths in the index of the repository
// whose working tree is dir. ok is false when dir has no readable index: no
// .git, a .git file that points outside dir, an index that is not a regular
// file, or one in a format this reader does not know. Callers then fall back
// to what they can see without git.
func Tracked(dir string) (paths map[string]bool, ok bool) {
	gitDir, ok := gitDirOf(dir)
	if !ok {
		return nil, false
	}
	index := filepath.Join(gitDir, "index")
	fi, err := os.Lstat(index)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxIndexSize {
		return nil, false
	}
	data, err := scanroot.ReadFile(index)
	if err != nil {
		return nil, false
	}
	paths, err = parse(data)
	if err != nil {
		return nil, false
	}
	return paths, true
}

// gitDirOf finds the git directory of the working tree dir: dir/.git, or the
// directory a .git file names ("gitdir: <path>"), which is used only when it
// lies inside dir.
func gitDirOf(dir string) (string, bool) {
	dotGit := filepath.Join(dir, ".git")
	fi, err := os.Lstat(dotGit)
	if err != nil {
		return "", false
	}
	if fi.IsDir() {
		return dotGit, true
	}
	if !fi.Mode().IsRegular() || fi.Size() > 4096 {
		return "", false
	}
	data, err := scanroot.ReadFile(dotGit)
	if err != nil {
		return "", false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	target, found := strings.CutPrefix(strings.TrimSpace(line), "gitdir:")
	if !found {
		return "", false
	}
	target = strings.TrimSpace(target)
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	rel, err := filepath.Rel(dir, filepath.Clean(target))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}

var errFormat = errors.New("not a git index")

// parse reads the entries of an index file in format version 2, 3 or 4.
func parse(data []byte) (map[string]bool, error) {
	if len(data) < 12 || !bytes.Equal(data[:4], []byte("DIRC")) {
		return nil, errFormat
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version < 2 || version > 4 {
		return nil, errFormat
	}
	count := binary.BigEndian.Uint32(data[8:12])
	paths := make(map[string]bool, min(count, 1<<16))
	pos := 12
	prev := ""
	for i := uint32(0); i < count; i++ {
		start := pos
		// ctime, mtime, dev, ino, mode, uid, gid, size, object id, flags.
		const fixed = 62
		if pos+fixed > len(data) {
			return nil, errFormat
		}
		flags := binary.BigEndian.Uint16(data[pos+60 : pos+62])
		pos += fixed
		if version >= 3 && flags&0x4000 != 0 {
			pos += 2 // extended flags
			if pos > len(data) {
				return nil, errFormat
			}
		}
		var name string
		if version == 4 {
			strip, n := varint(data[pos:])
			if n == 0 || strip > uint64(len(prev)) {
				return nil, errFormat
			}
			pos += n
			end := bytes.IndexByte(data[pos:], 0)
			if end < 0 {
				return nil, errFormat
			}
			name = prev[:len(prev)-int(strip)] + string(data[pos:pos+end]) // #nosec G115 -- strip <= len(prev), checked above
			pos += end + 1
		} else {
			end := bytes.IndexByte(data[pos:], 0)
			if end < 0 {
				return nil, errFormat
			}
			name = string(data[pos : pos+end])
			// The entry is padded with 1 to 8 NUL bytes to a multiple of 8.
			pos = start + (pos+end-start+8)&^7
			if pos > len(data) {
				return nil, errFormat
			}
		}
		paths[name] = true
		prev = name
	}
	return paths, nil
}

// varint decodes the offset encoding git uses for the prefix length of a
// version 4 path. It returns the value and the number of bytes read, 0 on
// malformed input.
func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	v := uint64(c & 0x7f)
	n := 1
	for c&0x80 != 0 {
		if n >= len(b) || n > 9 {
			return 0, 0
		}
		c = b[n]
		n++
		v = ((v + 1) << 7) | uint64(c&0x7f)
	}
	return v, n
}
