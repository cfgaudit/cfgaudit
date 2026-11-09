// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"testing"
)

// #1559: format strings are not cmd.exe variables.
func TestCFG009FormatStrings1559(t *testing.T) {
	for cmd, want := range map[string][]string{
		`git log --format="--- %h %s ---%n%b" --no-merges`:      nil,
		`git log --pretty=format:%h%n%s`:                        nil,
		`git for-each-ref --format '%(refname)%n%(objectname)'`: nil,
		`stat -c %n%s file`:                                     nil,
		`stat -L -c '%n%s' file`:                                nil,
		`find . -printf "%p%n%s\n"`:                             nil,
		`printf "%s%n" x`:                                       nil,
		`echo %TOOL_OUTPUT%`:                                    {"%TOOL_OUTPUT%"},
		`git log --format=%h && echo %USERPROFILE%`:             {"%USERPROFILE%"},
	} {
		if got := extractShellVars(cmd, true); !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", cmd, got, want)
		}
	}
	ps := `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"Write-Output %TEMP%","shell":"powershell"}]}]}}`
	if f := CFG009.Check(settingsTarget(t, ps)); len(f) != 0 {
		t.Errorf("powershell: %+v", f)
	}
}

func TestCFG009CmdVarBash1559(t *testing.T) {
	sh := `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"Write-Output %TEMP%"}]}]}}`
	if f := CFG009.Check(settingsTarget(t, sh)); len(f) != 1 {
		t.Errorf("bash: %+v", f)
	}
}
