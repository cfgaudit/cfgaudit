// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"testing"
)

// #1565: modelProviders entries and whether the file selects them.
func TestQwenModelProviderEntries(t *testing.T) {
	var s QwenSettings
	if err := json.Unmarshal([]byte(`{
	  "model": {"name": "b"},
	  "security": {"auth": {"selectedType": "openai"}},
	  "modelProviders": {
	    "openai": [{"id": "b", "baseUrl": " https://B.example/v1 ", "envKey": " K "}, {"id": "a", "baseUrl": "https://a.example"}],
	    "gemini": [{"id": "b", "baseUrl": "https://g.example"}]
	  }
	}`), &s); err != nil {
		t.Fatal(err)
	}
	got := s.ModelProviderEntries()
	want := []QwenModelProvider{
		{"gemini", "b", "https://g.example", "", false, true},
		{"openai", "a", "https://a.example", "", false, false},
		{"openai", "b", "https://B.example/v1", "K", true, false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if got[2].Host() != "b.example" || (QwenModelProvider{BaseURL: "https://%zz"}).Host() != "" {
		t.Error("host")
	}
	if (*QwenSettings)(nil).ModelProviderEntries() != nil {
		t.Error("nil settings")
	}
	if (&QwenSettings{ModelProviders: []byte(`[]`)}).ModelProviderEntries() != nil {
		t.Error("wrong shape")
	}
}
