// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg129 struct{}

var CFG129 = &cfg129{}

func init() { All = append(All, CFG129) }

func (r *cfg129) ID() string { return "CFG129" }

// BytecodeKind says how a committed .pyc can run in place of source.
type BytecodeKind int

const (
	// BytecodeReplacesSource is an unchecked-hash .pyc in __pycache__ with its
	// source beside the directory. Python imports it without reading the source.
	BytecodeReplacesSource BytecodeKind = iota
	// BytecodeUncheckedNoSource is the same file with no source yet. Python
	// does not import it, but it replaces any source added later.
	BytecodeUncheckedNoSource
	// BytecodeSourceless is a .pyc outside __pycache__ with no source beside
	// it, which Python imports in any invalidation mode.
	BytecodeSourceless
)

// BytecodeFile is one committed .pyc that can run instead of reviewed source
// (#1398). Path is relative to the scanned directory, with forward slashes,
// and Module is the module name it answers to.
type BytecodeFile struct {
	Path   string
	Module string
	Kind   BytecodeKind
}

// Check reports committed Python bytecode that runs in place of the source a
// reader reviews (#1398). It reads only the file header, which the scan
// classified; the bytecode itself is not analysed.
func (r *cfg129) Check(t *Target) []finding.Finding {
	if t == nil || t.ProjectDir == "" {
		return nil
	}
	var out []finding.Finding
	for _, b := range t.Bytecode {
		f := finding.Finding{RuleID: "CFG129", Severity: finding.Warn, File: filepath.Join(t.ProjectDir, filepath.FromSlash(b.Path))}
		src := b.Module + ".py"
		switch b.Kind {
		case BytecodeReplacesSource:
			f.Severity = finding.Error
			f.Message = b.Path + " is an unchecked-hash .pyc — Python imports it without reading " + src + ", so what runs is not the code a reviewer sees. Remove it"
		case BytecodeUncheckedNoSource:
			f.Message = b.Path + " is an unchecked-hash .pyc with no " + src + " beside " + path.Base(path.Dir(b.Path)) + "/ — Python does not import it today, but it would run in place of any " + src + " added there. Remove it"
		default:
			f.Message = b.Path + " is Python bytecode with no " + src + " beside it — Python imports it as module " + b.Module + ", and there is no source to review. Remove it or commit the source"
		}
		out = append(out, f)
	}
	return out
}

// PycModule returns the module a .pyc file name answers to:
// "helper.cpython-312.opt-1.pyc" in __pycache__ and "helper.pyc" outside it.
func PycModule(name string) string {
	m, _, _ := strings.Cut(name, ".")
	return m
}
