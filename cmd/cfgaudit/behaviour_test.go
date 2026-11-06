// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The behaviour list (#1493): docs/agent-behaviour.yml records what an agent
// does with a file, with the evidence, and what cfgaudit therefore reports.

type agentBehaviour struct {
	ID       string            `yaml:"id"`
	Agent    string            `yaml:"agent"`
	Topic    string            `yaml:"topic"`
	Claim    string            `yaml:"claim"`
	Version  string            `yaml:"version"`
	Evidence string            `yaml:"evidence"`
	Issue    int               `yaml:"issue"`
	Files    map[string]string `yaml:"files"`
	Fires    map[string]string `yaml:"fires"`
	Silent   []string          `yaml:"silent"`
}

func loadBehaviours(t *testing.T) []agentBehaviour {
	t.Helper()
	data, err := os.ReadFile("../../docs/agent-behaviour.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Behaviours []agentBehaviour `yaml:"behaviours"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Behaviours) == 0 {
		t.Fatal("no behaviours listed")
	}
	return doc.Behaviours
}

var (
	behaviourTopics   = []string{"ignore", "malformed", "precedence"}
	behaviourVersion  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	behaviourEvidence = regexp.MustCompile(`^(measured|changelog|source|docs): \S`)
)

func checkBehaviourEntry(b agentBehaviour) error {
	switch {
	case !strings.HasPrefix(b.ID, b.Agent+"/") || b.Agent == "":
		return fmt.Errorf("id %q does not start with the agent %q", b.ID, b.Agent)
	case knownAgents[b.Agent] == "":
		return fmt.Errorf("unknown agent %q", b.Agent)
	case !slices.Contains(behaviourTopics, b.Topic):
		return fmt.Errorf("unknown topic %q", b.Topic)
	case b.Claim == "":
		return fmt.Errorf("no claim")
	case !behaviourVersion.MatchString(b.Version):
		return fmt.Errorf("version %q is not X.Y.Z", b.Version)
	case !behaviourEvidence.MatchString(b.Evidence):
		return fmt.Errorf("evidence %q does not say how it was checked", b.Evidence)
	case b.Issue == 0:
		return fmt.Errorf("no issue")
	case len(b.Files) == 0:
		return fmt.Errorf("no fixture")
	case len(b.Fires)+len(b.Silent) == 0:
		return fmt.Errorf("neither fires nor silent: the entry checks nothing")
	}
	return nil
}

// scanBehaviour scans the fixture and returns rule to severity.
func scanBehaviour(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	setHome(t, t.TempDir())
	for name, content := range files {
		mustWrite(t, filepath.Join(dir, filepath.FromSlash(name)), content)
	}
	var out, errb bytes.Buffer
	code := run([]string{"cfgaudit", "--format", "json", "--claude-version", "2.1.317", dir}, nil, &out, &errb)
	if code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var found []struct {
		RuleID   string
		Severity string
	}
	if err := json.Unmarshal(out.Bytes(), &found); err != nil {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	got := map[string]string{}
	for _, f := range found {
		got[f.RuleID] = f.Severity
	}
	return got
}

// Every entry holds: the rules it names fire at that severity, and the rules it
// says stay silent do.
func TestAgentBehaviours(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range loadBehaviours(t) {
		t.Run(b.ID, func(t *testing.T) {
			if err := checkBehaviourEntry(b); err != nil {
				t.Fatal(err)
			}
			if seen[b.ID] {
				t.Fatal("listed twice")
			}
			seen[b.ID] = true
			got := scanBehaviour(t, b.Files)
			for rule, severity := range b.Fires {
				if got[rule] != severity {
					t.Errorf("%s: got %q, want %q (%s)", rule, got[rule], severity, b.Claim)
				}
			}
			for _, rule := range b.Silent {
				if got[rule] != "" {
					t.Errorf("%s fired, want silent (%s)", rule, b.Claim)
				}
			}
		})
	}
}

// An agent on the list covers all three topics, so a list that names it is not
// mistaken for one that covers it.
func TestAgentBehavioursCoverEveryTopic(t *testing.T) {
	topics := map[string]map[string]bool{}
	for _, b := range loadBehaviours(t) {
		if topics[b.Agent] == nil {
			topics[b.Agent] = map[string]bool{}
		}
		topics[b.Agent][b.Topic] = true
	}
	for agent, covered := range topics {
		var got []string
		for topic := range covered {
			got = append(got, topic)
		}
		sort.Strings(got)
		if !slices.Equal(got, behaviourTopics) {
			t.Errorf("%s covers %v, want %v", agent, got, behaviourTopics)
		}
	}
}

// The entry check rejects what the list must not contain.
func TestCheckBehaviourEntry(t *testing.T) {
	good := agentBehaviour{
		ID: "codex/x", Agent: "codex", Topic: "ignore", Claim: "c", Version: "1.2.3", Evidence: "measured: x",
		Issue: 1, Files: map[string]string{"a": "b"}, Silent: []string{"CFG001"},
	}
	if err := checkBehaviourEntry(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*agentBehaviour){
		"id":       func(b *agentBehaviour) { b.ID = "other/x" },
		"agent":    func(b *agentBehaviour) { b.Agent, b.ID = "nope", "nope/x" },
		"topic":    func(b *agentBehaviour) { b.Topic = "x" },
		"claim":    func(b *agentBehaviour) { b.Claim = "" },
		"version":  func(b *agentBehaviour) { b.Version = "latest" },
		"evidence": func(b *agentBehaviour) { b.Evidence = "I think so" },
		"issue":    func(b *agentBehaviour) { b.Issue = 0 },
		"files":    func(b *agentBehaviour) { b.Files = nil },
		"checks":   func(b *agentBehaviour) { b.Silent = nil },
	} {
		bad := good
		change(&bad)
		if checkBehaviourEntry(bad) == nil {
			t.Errorf("%s: accepted %+v", name, bad)
		}
	}
}
