// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/safeyaml"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
)

// GooseRecipe is the part of a goose recipe that runs or connects to something
// (#1414): crates/goose/src/recipe/mod.rs Recipe, recipe_extension_adapter.rs and
// agents/types.rs RetryConfig. A recipe is YAML or JSON, and YAML reads both.
type GooseRecipe struct {
	// IsRecipe says the file has a recipe's required keys: title, description,
	// and instructions or prompt. A directory goose lists as a recipe library
	// needs no such proof; a YAML file at the repository root does.
	IsRecipe bool
	// Servers are the stdio and streamable_http extensions, as MCP servers.
	Servers map[string]MCPServer
	// Commands are the retry shell commands.
	Commands []GooseRecipeCommand
	// SubRecipes are the sub_recipes paths, as the recipe writes them.
	SubRecipes []string
}

// GooseRecipeCommand is a shell command in a recipe's retry block.
type GooseRecipeCommand struct {
	Key     string // retry.checks[0].command or retry.on_failure
	Command string
	Line    int // 0 when the command is not found as written
}

// ParseGooseRecipe reads a recipe file. The values are read loosely: goose would
// reject a recipe with a wrong type, and the rest of it can still be reported.
func ParseGooseRecipe(path string) (*GooseRecipe, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw map[string]any
	if err := safeyaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return gooseRecipeFrom(raw, string(data)), nil
}

func gooseRecipeFrom(raw map[string]any, text string) *GooseRecipe {
	r := &GooseRecipe{Servers: map[string]MCPServer{}}
	title, _ := raw["title"].(string)
	desc, _ := raw["description"].(string)
	instructions, _ := raw["instructions"].(string)
	prompt, _ := raw["prompt"].(string)
	r.IsRecipe = title != "" && desc != "" && (instructions != "" || prompt != "")

	exts, _ := raw["extensions"].([]any)
	for i, e := range exts {
		ext, _ := e.(map[string]any)
		name, _ := ext["name"].(string)
		if s, ok := gooseExtensionServer(ext); ok {
			// Two extensions can share a name, and each still starts.
			if _, dup := r.Servers[name]; dup || name == "" {
				name += "#" + strconv.Itoa(i)
			}
			r.Servers[name] = s
		}
	}

	retry, _ := raw["retry"].(map[string]any)
	checks, _ := retry["checks"].([]any)
	for i, c := range checks {
		check, _ := c.(map[string]any)
		if cmd, _ := check["command"].(string); cmd != "" {
			r.addCommand("retry.checks["+strconv.Itoa(i)+"].command", cmd, text)
		}
	}
	if cmd, _ := retry["on_failure"].(string); cmd != "" {
		r.addCommand("retry.on_failure", cmd, text)
	}

	subs, _ := raw["sub_recipes"].([]any)
	for _, s := range subs {
		sub, _ := s.(map[string]any)
		if p, _ := sub["path"].(string); p != "" {
			r.SubRecipes = append(r.SubRecipes, p)
		}
	}
	return r
}

func (r *GooseRecipe) addCommand(key, cmd, text string) {
	first, _, _ := strings.Cut(cmd, "\n")
	line := 0
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, first) {
			line = i + 1
			break
		}
	}
	r.Commands = append(r.Commands, GooseRecipeCommand{Key: key, Command: cmd, Line: line})
}

// gooseExtensionServer maps an extension to an MCP server. builtin and platform
// extensions ship inside goose and declare nothing to run.
func gooseExtensionServer(ext map[string]any) (MCPServer, bool) {
	kind, _ := ext["type"].(string)
	env := EnvMap{}
	for _, key := range []string{"envs", "env"} {
		m, _ := ext[key].(map[string]any)
		for k, v := range m {
			if s, ok := v.(string); ok {
				env[k] = s
			}
		}
	}
	switch kind {
	case "stdio":
		cmd, _ := ext["cmd"].(string)
		if cmd == "" {
			return MCPServer{}, false
		}
		s := MCPServer{Command: cmd, Env: env}
		args, _ := ext["args"].([]any)
		for _, a := range args {
			if v, ok := a.(string); ok {
				s.Args = append(s.Args, v)
			}
		}
		return s, true
	case "streamable_http":
		uri, _ := ext["uri"].(string)
		if uri == "" {
			return MCPServer{}, false
		}
		s := MCPServer{URL: uri, Type: "http", Env: env, Headers: map[string]string{}}
		h, _ := ext["headers"].(map[string]any)
		for k, v := range h {
			if v, ok := v.(string); ok {
				s.Headers[k] = v
			}
		}
		return s, true
	}
	return MCPServer{}, false
}
