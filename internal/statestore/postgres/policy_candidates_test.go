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

func TestPolicyExperimentSchemaKeepsPinnedRunsAndAppendOnlyObservations(t *testing.T) {
	joined := strings.Join(policyExperimentStatements, "\n")
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS policy_experiments",
		"candidate_revision BIGINT NOT NULL",
		"dataset_digest TEXT NOT NULL",
		"CREATE TABLE IF NOT EXISTS policy_experiment_observations",
		"UNIQUE (experiment_id, sequence)",
		"idempotency_key TEXT NOT NULL",
		"policy_experiment_observations_idempotency_idx",
		"receipt_digest TEXT NOT NULL",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("experiment schema missing %q", required)
		}
	}
}

func TestPolicyEvaluationDatasetSchemaKeepsImmutableSnapshotsAndIdempotency(t *testing.T) {
	joined := strings.Join(policyEvaluationDatasetStatements, "\n")
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS policy_evaluation_datasets",
		"aggregate_version BIGINT NOT NULL",
		"UNIQUE (tenant_id, candidate_id, idempotency_key)",
		"CREATE TABLE IF NOT EXISTS policy_evaluation_dataset_revisions",
		"UNIQUE (dataset_id, version)",
		"UNIQUE (dataset_id, idempotency_key)",
		"CREATE TABLE IF NOT EXISTS policy_evaluation_dataset_cases",
		"PRIMARY KEY (revision_id, case_id)",
		"UNIQUE (revision_id, ordinal)",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("evaluation dataset schema missing %q", required)
		}
	}
}
