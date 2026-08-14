package parser

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContinueConfig is a partial representation of a Continue config.yaml
// (.continue/config.yaml or ~/.continue/config.yaml). mcpServers is a list (not
// a map as in Claude Code's .mcp.json); models carry inline provider credentials.
type ContinueConfig struct {
	MCPServers []ContinueMCP    `yaml:"mcpServers"`
	Models     []ContinueModel  `yaml:"models"`
	Rules      []ContinueRule   `yaml:"rules"`
	Prompts    []ContinuePrompt `yaml:"prompts"`

	// Data is the configured data-export channel: each entry names a
	// destination, a schema version, and how much of a session is sent.
	Data []ContinueData `yaml:"data"`
}

// ContinueData is one entry of the data list (packages/config-yaml/src/schemas/
// data/index.ts dataSchema). It decides where session content goes.
//
// Level is "all" or "noCode"; the schema keeps them as distinct literals because
// they differ in whether code is included. An absent level is not assumed to be
// either, so only an explicit "all" is treated as the wider one.
//
// Destination is a plain string, and it is not always remote: the one real data
// block in a 108-config sample points at a file:// path on the author's own
// machine, so a finding that reads any destination as exfiltration would have
// been wrong on the only occurrence there is.
type ContinueData struct {
	Name           string                  `yaml:"name"`
	Destination    string                  `yaml:"destination"`
	Schema         string                  `yaml:"schema"`
	Level          string                  `yaml:"level"`
	Events         []string                `yaml:"events"`
	APIKey         string                  `yaml:"apiKey"`
	RequestOptions *ContinueRequestOptions `yaml:"requestOptions"`
}

// ContinueRequestOptions is the shared requestOptions block
// (packages/config-yaml/src/schemas/models.ts requestOptionsSchema). It hangs off
// models, mcpServers and data entries alike, and it is where the credentials
// actually are: across 108 real configs it appears 44 times, against 1 for the
// whole data block.
//
// Only the fields cfgaudit acts on are decoded. Proxy and VerifySsl are kept
// because the shape is worth documenting even though neither is reported yet:
// every proxy value in that sample is loopback, and VerifySsl never appears.
type ContinueRequestOptions struct {
	Headers   map[string]string `yaml:"headers"`
	Proxy     string            `yaml:"proxy"`
	VerifySsl *bool             `yaml:"verifySsl"`
}

// ContinueRule is an entry of the rules list: either a bare string (the rule
// text) or an object with a `rule` field. Both are trusted instruction context
// scanned by the content rules. A hub reference ({uses, with}) has no inline
// text and yields an empty Text.
type ContinueRule struct {
	Name string
	Text string
}

// UnmarshalYAML accepts both the scalar (bare rule string) and object forms.
func (r *ContinueRule) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		r.Text = value.Value
		return nil
	}
	var obj struct {
		Name string `yaml:"name"`
		Rule string `yaml:"rule"`
	}
	if err := value.Decode(&obj); err != nil {
		return err
	}
	r.Name, r.Text = obj.Name, obj.Rule
	return nil
}

// ContinuePrompt is an entry of the prompts list; prompt holds the prompt text.
type ContinuePrompt struct {
	Name   string `yaml:"name"`
	Prompt string `yaml:"prompt"`
}

// ContinueMCP is one entry of the mcpServers list. stdio servers use
// command/args/env; sse/streamable-http servers use url/type and may carry an
// inline apiKey.
type ContinueMCP struct {
	Name           string                  `yaml:"name"`
	Command        string                  `yaml:"command"`
	Args           []string                `yaml:"args"`
	Env            map[string]string       `yaml:"env"`
	URL            string                  `yaml:"url"`
	Type           string                  `yaml:"type"`
	APIKey         string                  `yaml:"apiKey"`
	RequestOptions *ContinueRequestOptions `yaml:"requestOptions"`
}

// ContinueModel is one entry of the models list. A literal apiKey is a hardcoded
// credential; the continue-proxy provider instead uses apiKeyLocation (a
// reference), which is the safe pattern.
type ContinueModel struct {
	Name           string                  `yaml:"name"`
	Provider       string                  `yaml:"provider"`
	APIKey         string                  `yaml:"apiKey"`
	APIBase        string                  `yaml:"apiBase"`
	RequestOptions *ContinueRequestOptions `yaml:"requestOptions"`
}

// MCPServerMap converts the mcpServers list to the shared MCPServer shape so the
// existing MCP rules apply unchanged. Entries are keyed by name (unique-ified for
// blank or duplicate names) so no server is silently dropped.
func (c *ContinueConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCPServers))
	for i, s := range c.MCPServers {
		key := strings.TrimSpace(s.Name)
		if key == "" {
			key = "server" + strconv.Itoa(i)
		}
		for _, dup := out[key]; dup; _, dup = out[key] {
			key += "#" + strconv.Itoa(i)
		}
		out[key] = MCPServer{
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
			URL:     s.URL,
			Type:    s.Type,
		}
	}
	return out
}

// ParseContinueConfig reads and decodes a Continue config.yaml file.
func ParseContinueConfig(path string) (*ContinueConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, err
	}
	var c ContinueConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}
