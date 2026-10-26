// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/keyline"
)

// locateKeyLines gives findings in JSON and JSONC files the line of the key
// they report (#927). Without a line, SARIF has no region and GitHub shows
// the finding only in the Security tab, never on the pull request that adds
// the key; Code Climate points at line 1.
func locateKeyLines(all []finding.Finding) {
	docs := map[string]*keyline.Doc{}
	for i := range all {
		f := &all[i]
		if f.Line > 0 || !isJSONFile(f.File) {
			continue
		}
		d, seen := docs[f.File]
		if !seen {
			if data, err := os.ReadFile(f.File); err == nil { //nolint:gosec // a file the scan already read
				d = keyline.Parse(data)
			}
			docs[f.File] = d
		}
		msg := f.Message
		if f.Key != "" {
			msg = f.Key + " " + msg
		}
		f.Line, f.Col = d.Locate(msg)
	}
}

func isJSONFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonc":
		return true
	}
	return false
}
