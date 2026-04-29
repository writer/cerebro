package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestPutFindingEvidenceRejectsNilEvidence(t *testing.T) {
	store := &Store{}
	if err := store.PutFindingEvidence(context.Background(), nil); err == nil {
		t.Fatal("PutFindingEvidence() error = nil, want non-nil")
	}
}

func TestPutFindingEvidenceRejectsMissingRunID(t *testing.T) {
	store := &Store{}
	err := store.PutFindingEvidence(context.Background(), &cerebrov1.FindingEvidence{
		Id:        "finding-evidence-1",
		RuntimeId: "writer-okta-audit",
		RuleId:    "identity-okta-policy-rule-lifecycle-tampering",
		FindingId: "finding-1",
		ClaimIds:  []string{"claim-1"},
		EventIds:  []string{"okta-audit-2"},
		CreatedAt: timestamppb.New(time.Date(2026, 4, 24, 13, 0, 0, 0, time.UTC)),
	})
	if err == nil {
		t.Fatal("PutFindingEvidence() error = nil, want non-nil")
	}
}

func TestGetFindingEvidenceRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.GetFindingEvidence(context.Background(), "finding-evidence-1"); err == nil {
		t.Fatal("GetFindingEvidence() error = nil, want non-nil")
	}
}

func TestListFindingEvidenceRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListFindingEvidence(context.Background(), ports.ListFindingEvidenceRequest{RuntimeID: "writer-okta-audit"}); err == nil {
		t.Fatal("ListFindingEvidence() error = nil, want non-nil")
	}
}

func TestFindingEvidenceListQueryIncludesOptionalFilters(t *testing.T) {
	query, args, err := findingEvidenceListQuery(ports.ListFindingEvidenceRequest{
		RuntimeID:    "writer-okta-audit",
		FindingID:    "finding-1",
		RunID:        "finding-evaluation-run-1",
		RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
		ClaimID:      "claim-1",
		EventID:      "okta-audit-2",
		GraphRootURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		Limit:        25,
	})
	if err != nil {
		t.Fatalf("findingEvidenceListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_id = $1",
		"finding_id = $2",
		"run_id = $3",
		"rule_id = $4",
		"claim_ids_json @> $5::jsonb",
		"event_ids_json @> $6::jsonb",
		"graph_root_urns_json @> $7::jsonb",
		"LIMIT $8",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 8 {
		t.Fatalf("len(findingEvidenceListQuery().args) = %d, want 8", got)
	}
	if got := args[0]; got != "writer-okta-audit" {
		t.Fatalf("findingEvidenceListQuery().args[0] = %#v, want writer-okta-audit", got)
	}
	if got := args[7]; got != int64(25) {
		t.Fatalf("findingEvidenceListQuery().args[7] = %#v, want 25", got)
	}
}

func TestFindingEvidenceUpsertPreservesCreatedAtOnConflict(t *testing.T) {
	query := findingEvidenceUpsertSQL()
	if strings.Contains(query, "created_at = EXCLUDED.created_at") {
		t.Fatalf("finding evidence upsert overwrites created_at:\n%s", query)
	}
	if !strings.Contains(query, "jsonb_set(EXCLUDED.finding_evidence_json, '{created_at}'") {
		t.Fatalf("finding evidence upsert does not preserve payload created_at:\n%s", query)
	}
}
