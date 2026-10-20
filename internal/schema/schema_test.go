package schema

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTopLevelProperties(t *testing.T) {
	props := TopLevelProperties()
	p, ok := props["permissions"]
	if !ok {
		t.Fatal("bundled schema has no top-level permissions property")
	}
	if !reflect.DeepEqual(p.AllowedTypes, []string{"object"}) {
		t.Errorf("permissions types = %v, want [object]", p.AllowedTypes)
	}
}

func TestExtractTypes(t *testing.T) {
	cases := []struct {
		body string
		want []string
	}{
		{`{"type": "string"}`, []string{"string"}},
		{`{"type": ["integer", "number", "null"]}`, []string{"number", "null"}},
		{`{"anyOf": [{"type": "boolean"}, {"type": ["string", 1]}]}`, []string{"boolean", "string"}},
		{`{"$ref": "#/definitions/x"}`, nil},
		{`[]`, nil},
	}
	for _, c := range cases {
		if got := extractTypes(json.RawMessage(c.body)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("extractTypes(%s) = %v, want %v", c.body, got, c.want)
		}
	}
}
