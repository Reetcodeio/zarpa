package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Reetcodeio/zarpa/internal/scan"
)

func TestCheckDetailsAreShown(t *testing.T) {
	res := &scan.Result{Findings: []*scan.Finding{
		{Provider: "supabase", Severity: "critical", Display: "eyJ…AAAA", Category: scan.CategoryLeak,
			Liveness: "revoked", LiveDetail: "the project no longer exists",
			Locations: []scan.Location{{Kind: "file", Ref: "file:~/a.env:1"}}},
		{Provider: "openai", Severity: "high", Display: "sk-proj-…BBBB", Category: scan.CategoryLeak,
			Liveness: "revoked", Locations: []scan.Location{{Kind: "file", Ref: "file:~/b.env:1"}}},
	}}
	var out bytes.Buffer
	Text(&out, res, TextOptions{Now: time.Now()})
	s := out.String()
	if !strings.Contains(s, "Check details") || !strings.Contains(s, "the project no longer exists") {
		t.Fatalf("details missing:\n%s", s)
	}
	// A key with no detail gets no line in the details block.
	block := s[strings.Index(s, "Check details"):]
	if strings.Contains(block, "BBBB") {
		t.Errorf("key without detail listed:\n%s", block)
	}
}

func TestNoDetailsBlockWithoutCheck(t *testing.T) {
	res := &scan.Result{Findings: []*scan.Finding{
		{Provider: "openai", Severity: "high", Display: "sk-proj-…BBBB", Category: scan.CategoryLeak,
			Locations: []scan.Location{{Kind: "file", Ref: "file:~/b.env:1"}}},
	}}
	var out bytes.Buffer
	Text(&out, res, TextOptions{Now: time.Now()})
	if strings.Contains(out.String(), "Check details") {
		t.Errorf("details block printed without a check")
	}
}
