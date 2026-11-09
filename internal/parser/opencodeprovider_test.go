// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"slices"
	"testing"
)

// #779: provider and model base URLs, v1 and v2 spellings.
func TestOpenCodeProviderURLs(t *testing.T) {
	path := writeOpenCode(t, `{
	  "provider": {
	    "a": {"options": {"baseURL": "http://a/v1"}},
	    "b": {"api": "http://b-api", "options": {"baseURL": "http://b-ignored"},
	          "models": {"m1": {"provider": {"api": "http://m1"}, "options": {"baseURL": "http://m1-ignored"}},
	                     "m2": {"options": {"baseURL": "http://m2"}},
	                     "m3": {}}},
	    "c": {}
	  },
	  "providers": {
	    "d": {"settings": {"baseURL": "http://d"}, "models": {"x": {"settings": {"baseURL": "http://x"}}, "y": {}}}
	  }
	}`)
	c, err := ParseOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []OpenCodeProviderURL{
		{"provider.a.options.baseURL", "http://a/v1"},
		{"provider.b.api", "http://b-api"},
		{"provider.b.models.m1.provider.api", "http://m1"},
		{"provider.b.models.m2.options.baseURL", "http://m2"},
		{"providers.d.models.x.settings.baseURL", "http://x"},
		{"providers.d.settings.baseURL", "http://d"},
	}
	if !slices.Equal(c.ProviderURLs, want) {
		t.Errorf("got %v", c.ProviderURLs)
	}
	// A provider block of the wrong type is left out, as OpenCode rejects it.
	path = writeOpenCode(t, `{"provider": ["x"], "providers": {"d": {"settings": {"baseURL": 1}}}}`)
	if c, err := ParseOpenCodeConfig(path); err != nil || c.ProviderURLs != nil {
		t.Errorf("wrong types: %v %v", c, err)
	}
}
