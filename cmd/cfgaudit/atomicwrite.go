// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// renameFile is os.Rename, replaced in tests to fail the last step.
var renameFile = os.Rename

// writeFileAtomic replaces path with data so that a reader sees either the old
// file or the new one, never a truncated mix (#1052). os.WriteFile truncates
// first, so a full disk or a killed process left settings.json empty, and
// Claude Code then drops the whole file, deny list included.
//
// The data goes to a temporary file in the target's directory, is synced, and
// is renamed over the target. A replaced file keeps its permission bits; a new
// one is 0o600. A symlinked target is resolved first and the file it points
// to is replaced, as os.WriteFile wrote through the link. The temporary file
// is removed on every error path.
func writeFileAtomic(path string, data []byte) (err error) {
	if target, evalErr := filepath.EvalSymlinks(path); evalErr == nil {
		path = target
	}
	mode := fs.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil { // #nosec G703 -- path from a user-supplied dir, by design
		if !info.Mode().IsRegular() {
			return &fs.PathError{Op: "write", Path: path, Err: errors.New("not a regular file")}
		}
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name()) // #nosec G703 -- the temporary file this function created
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return renameFile(tmp.Name(), path)
}
