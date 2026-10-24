// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// yamlPanicDoc makes gopkg.in/yaml.v3 panic when decoded into a map or a
// struct (#846).
const yamlPanicDoc = "? -\n? <<\n"

func TestInstructionFrontmatter_DecoderPanic(t *testing.T) {
	if fm, ok := InstructionFrontmatter("---\n" + yamlPanicDoc + "...\n"); ok || fm != nil {
		t.Fatalf("got %v, %v; want no frontmatter", fm, ok)
	}
}

func TestParseContinueConfig_DecoderPanic(t *testing.T) {
	for _, doc := range []string{yamlPanicDoc, "models:\n  - ? -\n    ? <<\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseContinueConfig(path); err == nil {
			t.Errorf("expected a parse error for %q", doc)
		}
	}
}

func TestOpenCodeAgentPermission_DecoderPanic(t *testing.T) {
	_ = OpenCodeAgentPermission("---\n" + yamlPanicDoc + "---\n")
}
