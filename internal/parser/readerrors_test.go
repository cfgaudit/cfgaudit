package parser

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// fileParsers lists the parsers that report a missing file as an error rather
// than as an absent file. The error must still wrap fs.ErrNotExist, because
// callers that probe optional files test for it with errors.Is to tell "absent"
// apart from "present but unreadable".
var fileParsers = []struct {
	name  string
	parse func(path string) error
}{
	{"ParseAgentHooks", func(p string) error { _, err := ParseAgentHooks(p); return err }},
	{"ParseCodexHooksJSON", func(p string) error { _, err := ParseCodexHooksJSON(p); return err }},
	{"ParseContinueConfig", func(p string) error { _, err := ParseContinueConfig(p); return err }},
	{"ParseContinueHooks", func(p string) error { _, err := ParseContinueHooks(p); return err }},
	{"ParseContinueMCPJSON", func(p string) error { _, err := ParseContinueMCPJSON(p); return err }},
	{"ParseCopilotSettings", func(p string) error { _, err := ParseCopilotSettings(p); return err }},
	{"ParseCopilotLSP", func(p string) error { _, err := ParseCopilotLSP(p); return err }},
	{"ParseCursorCLIConfig", func(p string) error { _, err := ParseCursorCLIConfig(p); return err }},
	{"ParseCursorPermissions", func(p string) error { _, err := ParseCursorPermissions(p); return err }},
	{"ParseCursorSandbox", func(p string) error { _, err := ParseCursorSandbox(p); return err }},
	{"ParseDevinConfig", func(p string) error { _, err := ParseDevinConfig(p); return err }},
	{"ParseDevinHooksV1", func(p string) error { _, err := ParseDevinHooksV1(p); return err }},
	{"ParseDotEnv", func(p string) error { _, err := ParseDotEnv(p); return err }},
	{"ParseGeminiSettings", func(p string) error { _, err := ParseGeminiSettings(p); return err }},
	{"ParseGrokConfig", func(p string) error { _, err := ParseGrokConfig(p); return err }},
	{"ParseGrokHooks", func(p string) error { _, err := ParseGrokHooks(p); return err }},
	{"ParseGrokLSP", func(p string) error { _, err := ParseGrokLSP(p); return err }},
	{"ParseKimiPluginManifest", func(p string) error { _, err := ParseKimiPluginManifest(p); return err }},
	{"ParseMarketplace", func(p string) error { _, err := ParseMarketplace(p); return err }},
	{"ParsePluginManifest", func(p string) error { _, err := ParsePluginManifest(p); return err }},
	{"ParseQwenSettings", func(p string) error { _, err := ParseQwenSettings(p); return err }},
	{"ParseSkillsLock", func(p string) error { _, err := ParseSkillsLock(p); return err }},
	{"ParseZedDebug", func(p string) error { _, err := ParseZedDebug(p); return err }},
	{"ParseZedTasks", func(p string) error { _, err := ParseZedTasks(p); return err }},
}

func TestFileParsers_MissingFileWrapsNotExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, p := range fileParsers {
		err := p.parse(missing)
		if err == nil {
			t.Errorf("%s: expected an error for a missing file", p.name)
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: error must wrap fs.ErrNotExist, got %v", p.name, err)
		}
	}
}

// The loaders that treat a missing file as absent still report any other read
// failure. A directory in place of the file is the portable way to cause one.
func TestOptionalFileParsers_ReadFailure(t *testing.T) {
	dir := t.TempDir()
	if st, err := ParseScheduledTasks(dir); err == nil || st != nil {
		t.Errorf("ParseScheduledTasks on a directory: got %v, %v; want an error", st, err)
	}
	if lines, err := ParseIgnore(filepath.Join(dir, "missing")); err != nil || lines != nil {
		t.Errorf("ParseIgnore on a missing file: got %v, %v; want nothing", lines, err)
	}
}
