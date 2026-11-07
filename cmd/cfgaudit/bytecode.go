// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/gitindex"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

const (
	// pycMinMagic is the magic number of Python 3.7, the first with the flags
	// word of PEP 552, and pycMaxMagic bounds Python 3: Python 2.7 has 62211.
	pycMinMagic = 3394
	pycMaxMagic = 4000
	// pycUncheckedHash is the flags word of an unchecked hash-based .pyc: hash
	// based, without check_source.
	pycUncheckedHash = 1
)

// pycHeader reads the first eight bytes of a .pyc: the magic number, CR LF and
// the flags word. ok is false for a file that is not one, or older than PEP 552.
func pycHeader(file string) (unchecked, ok bool) {
	f, err := scanroot.Open(file)
	if err != nil {
		return false, false
	}
	defer func() { _ = f.Close() }()
	var h [8]byte
	if _, err := io.ReadFull(f, h[:]); err != nil {
		return false, false
	}
	magic := binary.LittleEndian.Uint16(h[:2])
	if magic < pycMinMagic || magic >= pycMaxMagic || h[2] != '\r' || h[3] != '\n' {
		return false, false
	}
	return binary.LittleEndian.Uint32(h[4:]) == pycUncheckedHash, true
}

// committedPycs returns the .pyc files of dir, relative with forward slashes:
// the tracked ones in a git checkout, so a local __pycache__ does not count,
// and every one in a directory without an index, such as an unpacked download.
func committedPycs(dir string) []string {
	var out []string
	if tracked, ok := gitindex.Tracked(dir); ok {
		for p := range tracked {
			if strings.HasSuffix(p, ".pyc") {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out
	}
	root := filepath.Clean(dir)
	_ = scanroot.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".pyc") {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// classifyPyc says how the .pyc at rel can run, measured with CPython 3.12
// (#1398). In __pycache__ only an unchecked-hash file does, over the source
// beside the directory; a timestamp or checked-hash file is validated against
// the source, and without a source none is imported. Outside __pycache__ a
// source beside the file wins, and without one the file is imported in any
// mode. Header only: nothing is executed.
func classifyPyc(dir, rel string) (rules.BytecodeFile, bool) {
	file := filepath.Join(dir, filepath.FromSlash(rel))
	fi, err := scanroot.Stat(file)
	if err != nil || !fi.Mode().IsRegular() {
		return rules.BytecodeFile{}, false
	}
	unchecked, ok := pycHeader(file)
	if !ok {
		return rules.BytecodeFile{}, false
	}
	module := rules.PycModule(path.Base(rel))
	parent := path.Dir(rel)
	if path.Base(parent) == "__pycache__" {
		_, err := scanroot.Stat(filepath.Join(dir, filepath.FromSlash(path.Dir(parent)), module+".py"))
		switch {
		case !unchecked:
			return rules.BytecodeFile{}, false
		case err == nil:
			return rules.BytecodeFile{Path: rel, Module: module, Kind: rules.BytecodeReplacesSource}, true
		}
		return rules.BytecodeFile{Path: rel, Module: module, Kind: rules.BytecodeUncheckedNoSource}, true
	}
	if _, err := scanroot.Stat(filepath.Join(dir, filepath.FromSlash(parent), module+".py")); err == nil {
		return rules.BytecodeFile{}, false
	}
	return rules.BytecodeFile{Path: rel, Module: module, Kind: rules.BytecodeSourceless}, true
}

// bytecodeTargets returns a target with the committed .pyc files that can run
// instead of reviewed source (#1398). Nil when there is none.
func bytecodeTargets(dir string) []*rules.Target {
	t := &rules.Target{Scope: finding.ScopeProject, ProjectDir: dir}
	for _, rel := range committedPycs(dir) {
		if b, ok := classifyPyc(dir, rel); ok {
			t.Bytecode = append(t.Bytecode, b)
		}
	}
	if len(t.Bytecode) == 0 {
		return nil
	}
	return []*rules.Target{t}
}
