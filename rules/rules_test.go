package rules

import "testing"

func TestEmbeddedRulesCompile(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Version == "" || len(s.Rules) < 25 {
		t.Fatalf("version %q, %d rules", s.Version, len(s.Rules))
	}
	for i := 1; i < len(s.Rules); i++ {
		if s.Rules[i-1].Priority < s.Rules[i].Priority {
			t.Fatal("rules must be sorted by priority, highest first")
		}
	}
	for _, r := range s.Rules {
		if !r.Multiline && len(r.Keywords) == 0 {
			t.Errorf("%s: line rules need keywords (they double as the prefilter)", r.ID)
		}
	}
}

func TestParseRejectsBadRules(t *testing.T) {
	bad := []string{
		`{"rules":[{"id":"x","regex":"(","severity":"high"}]}`,
		`{"rules":[{"id":"x","regex":"a","severity":"urgent"}]}`,
		`{"rules":[{"id":"x","regex":"a","severity":"high","secretGroup":2}]}`,
		`{"rules":[{"id":"x","regex":"a","severity":"high"},{"id":"x","regex":"b","severity":"high"}]}`,
		`{"rules":[{"id":"x","regex":"a","severity":"high","validate":"nope"}]}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("accepted bad rules: %s", b)
		}
	}
}
