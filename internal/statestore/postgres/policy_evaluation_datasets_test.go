package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/policycandidate"
)

func TestPolicyEvaluationDatasetPersistenceAtomicCASReplayAndTenantIsolation(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run policy evaluation dataset persistence test")
	}
	ctx := context.Background()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	candidateID, datasetID := "pc_dataset_"+suffix, "ped_"+suffix
	defer func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM policy_evaluation_dataset_cases WHERE dataset_id=$1`, datasetID)
		_, _ = store.db.ExecContext(ctx, `DELETE FROM policy_evaluation_dataset_revisions WHERE dataset_id=$1`, datasetID)
		_, _ = store.db.ExecContext(ctx, `DELETE FROM policy_evaluation_datasets WHERE id=$1`, datasetID)
		_, _ = store.db.ExecContext(ctx, `DELETE FROM policy_candidates WHERE id=$1`, candidateID)
	}()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.CreatePolicyCandidate(ctx, &policycandidate.Candidate{ID: candidateID, TenantID: "tenant-a", Status: policycandidate.StatusProved, Revision: 1, Hypothesis: "dataset persistence test", Domain: "aws", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	create := evaluationDatasetCreateRecord(candidateID, datasetID, now)
	created, initial, err := store.CreatePolicyEvaluationDataset(ctx, create)
	if err != nil {
		t.Fatalf("CreatePolicyEvaluationDataset() error = %v", err)
	}
	if created.AggregateVersion != 1 || initial.Version != 1 {
		t.Fatalf("created = %#v, initial = %#v", created, initial)
	}
	replayed, replayedRevision, err := store.CreatePolicyEvaluationDataset(ctx, create)
	if err != nil || replayed.ID != datasetID || replayedRevision.ID != initial.ID {
		t.Fatalf("create replay = %#v, %#v, %v", replayed, replayedRevision, err)
	}
	conflictingCreate := create
	conflictingCreate.Dataset = clonePolicyEvaluationDataset(create.Dataset)
	conflictingCreate.Dataset.CreateRequestHash = "different-create-content"
	if _, _, err := store.CreatePolicyEvaluationDataset(ctx, conflictingCreate); !errors.Is(err, policycandidate.ErrConflict) {
		t.Fatalf("conflicting create error = %v", err)
	}
	if _, err := store.GetPolicyEvaluationDataset(ctx, "tenant-b", datasetID); !errors.Is(err, policycandidate.ErrNotFound) {
		t.Fatalf("cross-tenant get error = %v", err)
	}
	wrongTenantList, err := store.ListPolicyEvaluationDatasets(ctx, policycandidate.ListPolicyEvaluationDatasetsRequest{TenantID: "tenant-b", Limit: 10})
	if err != nil || len(wrongTenantList) != 0 {
		t.Fatalf("cross-tenant list = %#v, %v", wrongTenantList, err)
	}

	appendCommand := evaluationDatasetAppendRecord(create, now.Add(time.Second))
	advanced, second, err := store.AppendPolicyEvaluationDatasetRevision(ctx, appendCommand)
	if err != nil {
		t.Fatalf("AppendPolicyEvaluationDatasetRevision() error = %v", err)
	}
	if advanced.AggregateVersion != 2 || second.PredecessorID != initial.ID {
		t.Fatalf("advanced = %#v, second = %#v", advanced, second)
	}
	initialCases, err := store.ListPolicyEvaluationDatasetCases(ctx, policycandidate.ListPolicyEvaluationDatasetCasesRequest{TenantID: "tenant-a", DatasetID: datasetID, RevisionID: initial.ID})
	if err != nil || len(initialCases) != 1 || initialCases[0].ContentDigest != "case-digest-v1" {
		t.Fatalf("immutable initial cases = %#v, %v", initialCases, err)
	}
	snapshot, err := store.GetPolicyEvaluationDatasetRevisionSnapshot(ctx, policycandidate.GetPolicyEvaluationDatasetRevisionRequest{TenantID: "tenant-a", DatasetID: datasetID, RevisionID: second.ID})
	if err != nil || snapshot.Revision.ID != second.ID || len(snapshot.Cases) != 1 || snapshot.Cases[0].ContentDigest != "case-digest-v2" {
		t.Fatalf("revision snapshot = %#v, %v", snapshot, err)
	}
	if _, err := store.GetPolicyEvaluationDatasetRevisionSnapshot(ctx, policycandidate.GetPolicyEvaluationDatasetRevisionRequest{TenantID: "tenant-b", DatasetID: datasetID, RevisionID: second.ID}); !errors.Is(err, policycandidate.ErrNotFound) {
		t.Fatalf("cross-tenant snapshot error = %v", err)
	}
	appendReplay, replayRevision, err := store.AppendPolicyEvaluationDatasetRevision(ctx, appendCommand)
	if err != nil || appendReplay.AggregateVersion != 2 || replayRevision.ID != second.ID {
		t.Fatalf("append replay = %#v, %#v, %v", appendReplay, replayRevision, err)
	}
	conflictingAppend := appendCommand
	conflictingAppend.Revision = clonePolicyEvaluationDatasetRevision(appendCommand.Revision)
	conflictingAppend.Revision.RequestHash = "different-append-content"
	if _, _, err := store.AppendPolicyEvaluationDatasetRevision(ctx, conflictingAppend); !errors.Is(err, policycandidate.ErrConflict) {
		t.Fatalf("conflicting append error = %v", err)
	}
	stale := appendCommand
	stale.IdempotencyKey = "append-stale"
	stale.Revision = clonePolicyEvaluationDatasetRevision(appendCommand.Revision)
	stale.Revision.ID = "pedr_stale_" + suffix
	stale.Revision.RequestHash = "stale-request"
	stale.Dataset = clonePolicyEvaluationDataset(appendCommand.Dataset)
	stale.Dataset.CurrentRevisionID = stale.Revision.ID
	for index := range stale.Cases {
		cloned := *stale.Cases[index]
		cloned.RevisionID = stale.Revision.ID
		stale.Cases[index] = &cloned
	}
	if _, _, err := store.AppendPolicyEvaluationDatasetRevision(ctx, stale); !errors.Is(err, policycandidate.ErrConflict) {
		t.Fatalf("stale append error = %v", err)
	}

	missingDatasetID := "ped_missing_" + suffix
	atomicFailure := evaluationDatasetCreateRecord("pc_missing_"+suffix, missingDatasetID, now)
	if _, _, err := store.CreatePolicyEvaluationDataset(ctx, atomicFailure); err == nil {
		t.Fatal("missing-candidate create error = nil")
	}
	if _, err := store.GetPolicyEvaluationDataset(ctx, "tenant-a", missingDatasetID); !errors.Is(err, policycandidate.ErrNotFound) {
		t.Fatalf("failed create left dataset row: %v", err)
	}
}

func evaluationDatasetCreateRecord(candidateID, datasetID string, now time.Time) policycandidate.CreatePolicyEvaluationDatasetRecord {
	revisionID := "pedr_initial_" + strings.TrimPrefix(datasetID, "ped_")
	dataset := &policycandidate.PolicyEvaluationDataset{ID: datasetID, TenantID: "tenant-a", CandidateID: candidateID, Name: "Multi-hop suite", CurrentRevisionID: revisionID, AggregateVersion: 1, CreatedAt: now, UpdatedAt: now, CreateRequestHash: "create-content-v1"}
	revision := &policycandidate.PolicyEvaluationDatasetRevision{ID: revisionID, TenantID: "tenant-a", DatasetID: datasetID, Version: 1, PolicyDigest: strings.Repeat("a", 64), SourceTestDigest: strings.Repeat("b", 64), ContentDigest: "dataset-digest-v1", CaseCount: 1, ChangeSummary: "Initial suite", CreatedBy: "test-agent", CreatedAt: now, RequestHash: "create-content-v1"}
	testCase := &policycandidate.PolicyEvaluationDatasetCase{ID: "case_path", DatasetID: datasetID, RevisionID: revisionID, Ordinal: 0, ContentDigest: "case-digest-v1", Test: findingdsl.PolicyRuleTestCase{Name: "multi-hop path", Resource: map[string]any{"state": "risky"}, WantFinding: true}}
	return policycandidate.CreatePolicyEvaluationDatasetRecord{Dataset: dataset, Revision: revision, Cases: []*policycandidate.PolicyEvaluationDatasetCase{testCase}, IdempotencyKey: "create-key"}
}

func evaluationDatasetAppendRecord(create policycandidate.CreatePolicyEvaluationDatasetRecord, now time.Time) policycandidate.AppendPolicyEvaluationDatasetRevisionRecord {
	revisionID := "pedr_second_" + strings.TrimPrefix(create.Dataset.ID, "ped_")
	dataset := clonePolicyEvaluationDataset(create.Dataset)
	dataset.CurrentRevisionID, dataset.AggregateVersion, dataset.UpdatedAt = revisionID, 2, now
	revision := &policycandidate.PolicyEvaluationDatasetRevision{ID: revisionID, TenantID: dataset.TenantID, DatasetID: dataset.ID, Version: 2, PredecessorID: create.Revision.ID, PolicyDigest: create.Revision.PolicyDigest, SourceTestDigest: create.Revision.SourceTestDigest, ContentDigest: "dataset-digest-v2", CaseCount: 1, ChangeSummary: "Tighten fixture", CreatedBy: "test-agent", CreatedAt: now, RequestHash: "append-content-v2"}
	testCase := &policycandidate.PolicyEvaluationDatasetCase{ID: "case_path", DatasetID: dataset.ID, RevisionID: revisionID, Ordinal: 0, ContentDigest: "case-digest-v2", Test: findingdsl.PolicyRuleTestCase{Name: "multi-hop path", Resource: map[string]any{"state": "safer"}, WantFinding: false}}
	return policycandidate.AppendPolicyEvaluationDatasetRevisionRecord{Dataset: dataset, Revision: revision, Cases: []*policycandidate.PolicyEvaluationDatasetCase{testCase}, ExpectedVersion: 1, IdempotencyKey: "append-key"}
}
