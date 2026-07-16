package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/policycandidate"
)

func TestPolicyCandidateSchemaKeepsCurrentStateAndImmutableTransitions(t *testing.T) {
	joined := strings.Join(policyCandidateStatements, "\n")
	for _, required := range []string{"CREATE TABLE IF NOT EXISTS policy_candidates", "CREATE TABLE IF NOT EXISTS policy_candidate_events", "UNIQUE (candidate_id, revision)", "policy_digest", "shadow_receipt_id"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("schema missing %q", required)
		}
	}
}

func TestDecodePolicyCandidateRoundTrip(t *testing.T) {
	want := &policycandidate.Candidate{ID: "pc_test", TenantID: "tenant-a", Status: policycandidate.StatusGrounded, Revision: 1, Hypothesis: "A redacted hypothesis.", Domain: "aws", CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: time.Unix(100, 0).UTC()}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodePolicyCandidate(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.TenantID != want.TenantID || got.Status != want.Status || got.Revision != want.Revision {
		t.Fatalf("decoded candidate = %#v", got)
	}
}
