// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEveryJobHasATimeout keeps a hanging job from running until GitHub's limit
// of six hours (#1489). A job that calls a reusable workflow cannot set one; the
// jobs of that workflow do.
func TestEveryJobHasATimeout(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file) //nolint:gosec // a file of this repository
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			Jobs map[string]struct {
				Uses    string `yaml:"uses"`
				Timeout *int   `yaml:"timeout-minutes"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for name, job := range workflow.Jobs {
			if job.Uses == "" && job.Timeout == nil {
				t.Errorf("%s: job %s has no timeout-minutes", filepath.Base(file), name)
			}
		}
	}
}
