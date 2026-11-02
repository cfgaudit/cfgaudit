// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits for an archive scan target (#1002). A config file is small; the
// limits keep a zip bomb or a huge release archive from filling the disk.
const (
	maxArchiveEntries = 50000
	maxArchiveFile    = 32 << 20  // larger entries are listed, not extracted
	maxArchiveTotal   = 512 << 20 // bytes extracted in all
)

// archiveKind returns "zip" or "tar" (with gz true for a gzipped tar) for a
// scan target named like an archive, and "" otherwise.
func archiveKind(p string) (kind string, gz bool) {
	l := strings.ToLower(p)
	switch {
	case strings.HasSuffix(l, ".zip"):
		return "zip", false
	case strings.HasSuffix(l, ".tar"):
		return "tar", false
	case strings.HasSuffix(l, ".tar.gz"), strings.HasSuffix(l, ".tgz"):
		return "tar", true
	}
	return "", false
}

// archiveResult is what extraction found: every entry name (slash-separated,
// cleaned), the links it did not create, and the entries it skipped.
type archiveResult struct {
	Entries []string
	Links   []string
	Skipped []string
}

// safeEntryName cleans an archive entry name, or returns "" for one that
// would land outside the extraction root: absolute, a drive letter, or with a
// ".." component. Backslashes count as separators, as a Windows unzip reads
// them.
func safeEntryName(name string) string {
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") || (len(n) > 1 && n[1] == ':') {
		return ""
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return ""
		}
	}
	n = path.Clean(n)
	if n == "." || n == "" {
		return ""
	}
	return n
}

// extractor writes entries under root with the limits above.
type extractor struct {
	root    string
	total   int64
	entries int
	res     archiveResult
}

func (x *extractor) entry(name string, isDir, isLink bool, size int64, r io.Reader) error {
	x.entries++
	if x.entries > maxArchiveEntries {
		return fmt.Errorf("more than %d entries", maxArchiveEntries)
	}
	n := safeEntryName(name)
	if n == "" {
		x.res.Skipped = append(x.res.Skipped, name)
		return nil
	}
	x.res.Entries = append(x.res.Entries, n)
	dst := filepath.Join(x.root, filepath.FromSlash(n))
	switch {
	case isLink:
		x.res.Links = append(x.res.Links, n)
		return nil
	case isDir:
		return os.MkdirAll(dst, 0o750) // #nosec G703 -- dst is a cleaned entry name under the private root
	case size > maxArchiveFile:
		x.res.Skipped = append(x.res.Skipped, n)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil { // #nosec G703 -- dst is a cleaned entry name under the private root
		return err
	}
	// A directory entry or an earlier file may already sit at dst; the first
	// one wins, as an entry never replaces what is there.
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304,G703 -- dst is a cleaned name under the private root
	if err != nil {
		x.res.Skipped = append(x.res.Skipped, n)
		return nil
	}
	defer func() { _ = f.Close() }()
	written, err := io.Copy(f, io.LimitReader(r, maxArchiveFile+1))
	x.total += written
	if err != nil {
		return err
	}
	if written > maxArchiveFile {
		_ = f.Truncate(0)
		x.res.Skipped = append(x.res.Skipped, n)
	}
	if x.total > maxArchiveTotal {
		return fmt.Errorf("more than %d MiB extracted", maxArchiveTotal>>20)
	}
	return nil
}

// extractArchive unpacks the archive at p into a new private directory and
// returns it. Nothing in the archive is run, and no link is created: a link
// entry is listed in Links instead, so nothing can point a later read
// outside the directory. The caller removes the directory.
func extractArchive(p string) (string, archiveResult, error) {
	kind, gz := archiveKind(p)
	root, err := os.MkdirTemp("", "cfgaudit-archive-")
	if err != nil {
		return "", archiveResult{}, err
	}
	x := &extractor{root: root}
	switch kind {
	case "zip":
		err = x.zip(p)
	case "tar":
		err = x.tar(p, gz)
	default:
		err = errors.New("not an archive")
	}
	if err != nil {
		_ = os.RemoveAll(root)
		return "", archiveResult{}, fmt.Errorf("%s: %w", p, err)
	}
	return root, x.res, nil
}

func (x *extractor) zip(p string) error {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		mode := f.Mode()
		// Devices, named pipes and other irregular entries are skipped, as the
		// tar reader skips them (#1331): only files, directories and links
		// are entries.
		if !mode.IsRegular() && !mode.IsDir() && mode&os.ModeSymlink == 0 {
			continue
		}
		var rc io.ReadCloser
		if mode.IsRegular() {
			if rc, err = f.Open(); err != nil {
				return err
			}
		}
		size := int64(maxArchiveFile + 1)
		if f.UncompressedSize64 <= maxArchiveFile {
			size = int64(f.UncompressedSize64) // #nosec G115 -- bounded by maxArchiveFile
		}
		err = x.entry(f.Name, mode.IsDir(), mode&os.ModeSymlink != 0, size, rc)
		if rc != nil {
			_ = rc.Close()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (x *extractor) tar(p string, gz bool) error {
	f, err := os.Open(p) // #nosec G304,G703 -- the user names the archive to scan
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if gz {
		g, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		r = g
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink:
		default:
			continue // devices, fifos, pax and GNU metadata
		}
		link := h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink
		if err := x.entry(h.Name, h.Typeflag == tar.TypeDir, link, h.Size, tr); err != nil {
			return err
		}
	}
}

// archivePath reports file, a path under the extraction root, as a path
// inside the archive: "skill.zip/scripts/setup.sh".
func archivePath(archive, root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return file
	}
	if rel == "." {
		return archive
	}
	return archive + "/" + filepath.ToSlash(rel)
}
