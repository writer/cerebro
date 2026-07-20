package policyevaluationdatasets

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/policycandidate"
)

func TestPublicViewsOmitTenantActorAndRequestHashes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	result := newResultView(&policycandidate.PolicyEvaluationDatasetResult{
		Dataset: &policycandidate.PolicyEvaluationDataset{
			ID: "dataset-1", TenantID: "tenant-private", CandidateID: "candidate-1", Name: "Synthetic graph cases",
			CurrentRevisionID: "revision-1", AggregateVersion: 1, CreatedAt: now, UpdatedAt: now,
			CreateRequestHash: "create-request-private",
		},
		Revision: &policycandidate.PolicyEvaluationDatasetRevision{
			ID: "revision-1", TenantID: "tenant-private", DatasetID: "dataset-1", Version: 1,
			PolicyDigest: strings.Repeat("a", 64), SourceTestDigest: strings.Repeat("b", 64), ContentDigest: strings.Repeat("c", 64),
			CaseCount: 1, ChangeSummary: "Initial synthetic cases", CreatedBy: "actor-private", CreatedAt: now,
			RequestHash: "revision-request-private",
		},
	})
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result view: %v", err)
	}
	for _, forbidden := range []string{"tenant-private", "actor-private", "create-request-private", "revision-request-private", "tenant_id", "created_by", "request_hash"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("public result contains private field %q: %s", forbidden, payload)
		}
	}
}

func TestCaseViewContainsOnlySyntheticFixturePayload(t *testing.T) {
	t.Parallel()

	view := newCaseView(&policycandidate.PolicyEvaluationDatasetCase{
		ID: "multi-hop", DatasetID: "dataset-1", RevisionID: "revision-1", ContentDigest: strings.Repeat("d", 64),
		Test: findingdsl.PolicyRuleTestCase{
			Name: "synthetic multi-hop path",
			GraphFixture: &findingdsl.PolicyGraphFixture{
				TenantID: "fixture",
				Nodes:    []findingdsl.PolicyGraphFixtureNode{{URN: "urn:test:principal", SourceID: "fixture-source", EntityType: "Principal"}},
			},
		},
	})
	payload, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal case view: %v", err)
	}
	if bytes.Contains(payload, []byte("tenant_id")) || bytes.Contains(payload, []byte("resource")) || bytes.Contains(payload, []byte("queryRows")) {
		t.Fatalf("case view contains forbidden payload fields: %s", payload)
	}
	if !bytes.Contains(payload, []byte("urn:test:principal")) {
		t.Fatalf("case view omits synthetic fixture: %s", payload)
	}
}
