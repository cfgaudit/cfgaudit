package cfgaudit

import "testing"

func TestRuleDoc(t *testing.T) {
	doc, ok := RuleDoc("CFG001")
	if !ok || doc == "" {
		t.Fatalf("expected CFG001 doc, ok=%v len=%d", ok, len(doc))
	}
	if _, ok := RuleDoc("CFG999"); ok {
		t.Errorf("expected CFG999 to be absent")
	}
}

func TestRuleIDs(t *testing.T) {
	ids := RuleIDs()
	if len(ids) < 20 {
		t.Fatalf("expected many rule docs, got %d", len(ids))
	}
	// sorted and well-formed
	for i, id := range ids {
		if len(id) != 6 || id[:3] != "CFG" {
			t.Errorf("unexpected rule id %q", id)
		}
		if i > 0 && ids[i-1] >= id {
			t.Errorf("rule ids not sorted: %s before %s", ids[i-1], id)
		}
	}
}
