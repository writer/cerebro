package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
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

func TestListGRCFindingEvidenceRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListGRCFindingEvidence(context.Background(), ports.ListFindingEvidenceRequest{RuntimeID: "runtime-alpha"}); err == nil {
		t.Fatal("ListGRCFindingEvidence() error = nil, want non-nil")
	}
}

func TestCountGRCFindingEvidenceByFindingIDRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.CountGRCFindingEvidenceByFindingID(context.Background(), ports.ListFindingEvidenceRequest{RuntimeID: "runtime-alpha"}); err == nil {
		t.Fatal("CountGRCFindingEvidenceByFindingID() error = nil, want non-nil")
	}
}

func TestFindingEvidenceListQueryIncludesOptionalFilters(t *testing.T) {
	query, args, err := findingEvidenceListQuery(ports.ListFindingEvidenceRequest{
		RuntimeID:    "runtime-alpha",
		FindingID:    "finding-1",
		RunID:        "finding-evaluation-run-1",
		RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
		ClaimID:      "claim-1",
		EventID:      "okta-audit-2",
		GraphRootURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		GraphPathURN: "urn:cerebro:writer:okta_user:00u2",
		Limit:        25,
	})
	if err != nil {
		t.Fatalf("findingEvidenceListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_id = $1",
		"finding_id = $2",
		"(run_id = $3 OR run_ids_json @> jsonb_build_array($3))",
		"rule_id = $4",
		"claim_ids_json @> $5::jsonb",
		"event_ids_json @> $6::jsonb",
		"graph_root_urns_json @> $7::jsonb",
		"graph_path_urns_json @> $8::jsonb",
		"LIMIT $9",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 9 {
		t.Fatalf("len(findingEvidenceListQuery().args) = %d, want 9", got)
	}
	if got := args[0]; got != "runtime-alpha" {
		t.Fatalf("findingEvidenceListQuery().args[0] = %#v, want runtime-alpha", got)
	}
	if got := args[8]; got != int64(25) {
		t.Fatalf("findingEvidenceListQuery().args[8] = %#v, want 25", got)
	}
}

func TestFindingEvidenceHeaderListQueryAvoidsFullPayload(t *testing.T) {
	query, args, err := findingEvidenceHeaderListQuery(ports.ListFindingEvidenceRequest{
		RuntimeIDs:   []string{"runtime-alpha", "runtime-beta"},
		FindingIDs:   []string{"finding-high", "finding-critical"},
		Limit:        25,
		CreatedOrder: true,
	})
	if err != nil {
		t.Fatalf("findingEvidenceHeaderListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"SELECT id, runtime_id, rule_id, finding_id, run_id, claim_ids_json::text, event_ids_json::text, graph_root_urns_json::text, created_at",
		"runtime_id IN ($1, $2)",
		"finding_id IN ($3, $4)",
		"ORDER BY created_at DESC, id",
		"LIMIT $5",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceHeaderListQuery() query missing %q: %s", fragment, query)
		}
	}
	if strings.Contains(query, "finding_evidence_json") {
		t.Fatalf("findingEvidenceHeaderListQuery() selected full payload: %s", query)
	}
	if got := len(args); got != 5 {
		t.Fatalf("len(findingEvidenceHeaderListQuery().args) = %d, want 5", got)
	}
}

func TestFindingEvidenceCountByFindingIDQueryUsesGroupedCounts(t *testing.T) {
	query, args, err := findingEvidenceCountByFindingIDQuery(ports.ListFindingEvidenceRequest{
		RuntimeIDs: []string{"runtime-alpha", "runtime-beta"},
		FindingIDs: []string{"finding-high", "finding-critical"},
		Limit:      25,
	})
	if err != nil {
		t.Fatalf("findingEvidenceCountByFindingIDQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"SELECT finding_id, COUNT(*)",
		"FROM finding_evidence",
		"runtime_id IN ($1, $2)",
		"finding_id IN ($3, $4)",
		"GROUP BY finding_id",
		"ORDER BY finding_id",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceCountByFindingIDQuery() query missing %q: %s", fragment, query)
		}
	}
	for _, forbidden := range []string{"finding_evidence_json", "LIMIT"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("findingEvidenceCountByFindingIDQuery() included %q: %s", forbidden, query)
		}
	}
	if got := len(args); got != 4 {
		t.Fatalf("len(findingEvidenceCountByFindingIDQuery().args) = %d, want 4", got)
	}
}

func TestFindingEvidenceListQuerySupportsRuntimeBatches(t *testing.T) {
	query, args, err := findingEvidenceListQuery(ports.ListFindingEvidenceRequest{
		RuntimeIDs: []string{"runtime-alpha", "runtime-beta", "runtime-alpha"},
		Limit:      25,
	})
	if err != nil {
		t.Fatalf("findingEvidenceListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"FROM (VALUES ($1::text), ($2::text)) AS requested(runtime_id)",
		"CROSS JOIN LATERAL",
		"evidence.runtime_id = requested.runtime_id",
		"ORDER BY evidence.last_observed_at DESC, evidence.created_at DESC, evidence.id",
		"ORDER BY candidate.last_observed_at DESC, candidate.created_at DESC, candidate.id",
		"LIMIT $3",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 3 {
		t.Fatalf("len(findingEvidenceListQuery().args) = %d, want 3", got)
	}
	if got := args[0]; got != "runtime-alpha" {
		t.Fatalf("findingEvidenceListQuery().args[0] = %#v, want first runtime", got)
	}
	if got := args[1]; got != "runtime-beta" {
		t.Fatalf("findingEvidenceListQuery().args[1] = %#v, want second runtime", got)
	}
	if got := args[2]; got != int64(25) {
		t.Fatalf("findingEvidenceListQuery().args[2] = %#v, want 25", got)
	}
}

func TestFindingEvidenceHeaderListQueryBoundsEachRuntimeBeforeGlobalSort(t *testing.T) {
	query, args, err := findingEvidenceHeaderListQuery(ports.ListFindingEvidenceRequest{
		RuntimeIDs:   []string{"runtime-alpha", "runtime-beta"},
		Limit:        25,
		CreatedOrder: true,
	})
	if err != nil {
		t.Fatalf("findingEvidenceHeaderListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"SELECT candidate.id, candidate.runtime_id",
		"FROM (VALUES ($1::text), ($2::text)) AS requested(runtime_id)",
		"CROSS JOIN LATERAL",
		"ORDER BY evidence.created_at DESC, evidence.id",
		"LIMIT $3",
		"ORDER BY candidate.created_at DESC, candidate.id",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceHeaderListQuery() query missing %q: %s", fragment, query)
		}
	}
	if strings.Contains(query, "finding_evidence_json") {
		t.Fatalf("findingEvidenceHeaderListQuery() selected full payload: %s", query)
	}
	if got := len(args); got != 3 {
		t.Fatalf("len(findingEvidenceHeaderListQuery().args) = %d, want 3", got)
	}
}

func TestFindingEvidenceListQueriesPreserveExplicitEmptyFindingBatch(t *testing.T) {
	request := ports.ListFindingEvidenceRequest{
		RuntimeIDs: []string{"runtime-alpha", "runtime-beta"},
		FindingIDs: []string{},
		Limit:      25,
	}
	for name, buildQuery := range map[string]func(ports.ListFindingEvidenceRequest) (string, []any, error){
		"full":   findingEvidenceListQuery,
		"header": findingEvidenceHeaderListQuery,
	} {
		t.Run(name, func(t *testing.T) {
			query, _, err := buildQuery(request)
			if err != nil {
				t.Fatalf("build query: %v", err)
			}
			if strings.Contains(query, "CROSS JOIN LATERAL") {
				t.Fatalf("explicit empty finding batch used runtime top-N query: %s", query)
			}
			if !strings.Contains(query, "FALSE") {
				t.Fatalf("explicit empty finding batch query missing FALSE clause: %s", query)
			}
		})
	}
}

func TestFindingEvidenceListQuerySupportsFindingBatches(t *testing.T) {
	query, args, err := findingEvidenceListQuery(ports.ListFindingEvidenceRequest{
		RuntimeIDs:   []string{"runtime-alpha", "runtime-beta"},
		FindingIDs:   []string{"finding-high", "finding-critical", "finding-high"},
		Limit:        25,
		CreatedOrder: true,
	})
	if err != nil {
		t.Fatalf("findingEvidenceListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"runtime_id IN ($1, $2)",
		"finding_id IN ($3, $4)",
		"ORDER BY created_at DESC, id",
		"LIMIT $5",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceListQuery() query missing %q: %s", fragment, query)
		}
	}
	if got := len(args); got != 5 {
		t.Fatalf("len(findingEvidenceListQuery().args) = %d, want 5", got)
	}
	if got := args[2]; got != "finding-high" {
		t.Fatalf("findingEvidenceListQuery().args[2] = %#v, want first finding", got)
	}
	if got := args[3]; got != "finding-critical" {
		t.Fatalf("findingEvidenceListQuery().args[3] = %#v, want second finding", got)
	}
}

func TestFindingEvidenceListQuerySupportsCreatedOrder(t *testing.T) {
	query, args, err := findingEvidenceListQuery(ports.ListFindingEvidenceRequest{
		RuntimeIDs:   []string{"runtime-alpha", "runtime-beta"},
		Limit:        25,
		CreatedOrder: true,
	})
	if err != nil {
		t.Fatalf("findingEvidenceListQuery() error = %v", err)
	}
	for _, fragment := range []string{
		"FROM (VALUES ($1::text), ($2::text)) AS requested(runtime_id)",
		"ORDER BY evidence.created_at DESC, evidence.id",
		"ORDER BY candidate.created_at DESC, candidate.id",
		"LIMIT $3",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("findingEvidenceListQuery() query missing %q: %s", fragment, query)
		}
	}
	if strings.Contains(query, "ORDER BY last_observed_at") {
		t.Fatalf("findingEvidenceListQuery() used last-observed order for created-order request: %s", query)
	}
	if got := len(args); got != 3 {
		t.Fatalf("len(findingEvidenceListQuery().args) = %d, want 3", got)
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
	if !strings.Contains(query, "last_observed_at = GREATEST") {
		t.Fatalf("finding evidence upsert does not advance last_observed_at:\n%s", query)
	}
	if !strings.Contains(query, "run_ids_json = EXCLUDED.run_ids_json") {
		t.Fatalf("finding evidence upsert does not persist merged run_ids_json:\n%s", query)
	}
	if !strings.Contains(query, "observations_json = EXCLUDED.observations_json") {
		t.Fatalf("finding evidence upsert does not persist merged observations_json:\n%s", query)
	}
	if !strings.Contains(query, "'{last_observed_at}'") {
		t.Fatalf("finding evidence upsert does not persist payload last_observed_at:\n%s", query)
	}
}

func TestFindingEvidenceAdvisoryLockSerializesHistoryMerges(t *testing.T) {
	query := findingEvidenceAdvisoryLockSQL()
	for _, fragment := range []string{
		"pg_advisory_xact_lock",
		"hashtext('finding_evidence')",
		"hashtext($1)",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("finding evidence advisory lock query missing %q:\n%s", fragment, query)
		}
	}
}

func TestFindingEvidenceSchemaPersistsEnrichedEvidence(t *testing.T) {
	joined := strings.Join(ensureFindingEvidenceStatements, "\n")
	for _, fragment := range []string{
		"last_observed_at TIMESTAMPTZ",
		"graph_path_urns_json JSONB",
		"run_ids_json JSONB",
		"observations_json JSONB",
		"attributes_json JSONB",
		"finding_evidence_graph_path_urns_gin_idx",
		"finding_evidence_run_ids_gin_idx",
		"finding_evidence_attributes_gin_idx",
		"finding_evidence_runtime_created_id_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS finding_evidence_runtime_created_id_idx",
		"runtime_id, created_at DESC, id",
		"finding_evidence_runtime_finding_observed_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS finding_evidence_runtime_finding_observed_idx",
		"runtime_id, finding_id, last_observed_at DESC, created_at DESC, id",
		"finding_evidence_runtime_finding_created_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS finding_evidence_runtime_finding_created_idx",
		"runtime_id, finding_id, created_at DESC, id",
		"finding_evidence_runtime_rule_observed_idx",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS finding_evidence_runtime_rule_observed_idx",
		"runtime_id, rule_id, last_observed_at DESC, created_at DESC, id",
		"CREATE TABLE IF NOT EXISTS finding_evidence_counts",
		"PRIMARY KEY (runtime_id, finding_id)",
		"CREATE OR REPLACE FUNCTION sync_finding_evidence_count()",
		"CREATE TRIGGER finding_evidence_count_sync",
		"AFTER INSERT OR UPDATE OF runtime_id, finding_id OR DELETE ON finding_evidence",
		"CREATE TABLE IF NOT EXISTS finding_evidence_count_migrations",
		"pg_advisory_xact_lock",
		"LOCK TABLE finding_evidence IN SHARE ROW EXCLUSIVE MODE",
		"GROUP BY runtime_id, finding_id",
		"INSERT INTO finding_evidence_count_migrations (id) VALUES ('backfill-v1')",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("finding evidence schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestRuntimeTopNQueriesPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run runtime top-N query integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	ctx := context.Background()
	if err := store.ensureFindingEvaluationRunTables(ctx); err != nil {
		t.Fatalf("ensure finding evaluation run tables: %v", err)
	}
	if err := store.ensureFindingEvidenceTables(ctx); err != nil {
		t.Fatalf("ensure finding evidence tables: %v", err)
	}
	prefix := fmt.Sprintf("runtime-top-n-%d", time.Now().UnixNano())
	runtimeIDs := []string{prefix + "-a", prefix + "-b"}
	cleanup := func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM finding_evidence WHERE runtime_id IN ($1, $2)`, runtimeIDs[0], runtimeIDs[1])
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM finding_evaluation_runs WHERE runtime_id IN ($1, $2)`, runtimeIDs[0], runtimeIDs[1])
	}
	cleanup()
	t.Cleanup(func() {
		cleanup()
		_ = store.Close()
	})

	startedAt := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	for _, runtimeID := range runtimeIDs {
		for _, suffix := range []string{"a", "z"} {
			run := &cerebrov1.FindingEvaluationRun{
				Id:        runtimeID + "-" + suffix,
				RuntimeId: runtimeID,
				RuleId:    "rule-a",
				Status:    "completed",
				StartedAt: timestamppb.New(startedAt),
			}
			if err := store.PutFindingEvaluationRun(ctx, run); err != nil {
				t.Fatalf("PutFindingEvaluationRun(%q) error = %v", run.GetId(), err)
			}
		}
	}
	runs, err := store.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{
		RuntimeIDs:      runtimeIDs,
		Limit:           2,
		LatestByRuntime: true,
	})
	if err != nil {
		t.Fatalf("ListFindingEvaluationRuns() error = %v", err)
	}
	if len(runs) != len(runtimeIDs) {
		t.Fatalf("ListFindingEvaluationRuns() returned %d runs, want %d", len(runs), len(runtimeIDs))
	}
	for _, run := range runs {
		if !strings.HasSuffix(run.GetId(), "-z") {
			t.Fatalf("ListFindingEvaluationRuns() returned non-latest run %q", run.GetId())
		}
	}

	evidenceTimes := []time.Time{startedAt.Add(time.Minute), startedAt.Add(3 * time.Minute), startedAt.Add(2 * time.Minute), startedAt.Add(4 * time.Minute)}
	for index, observedAt := range evidenceTimes {
		runtimeID := runtimeIDs[index%len(runtimeIDs)]
		evidence := &cerebrov1.FindingEvidence{
			Id:             fmt.Sprintf("%s-evidence-%d", runtimeID, index),
			RuntimeId:      runtimeID,
			RuleId:         "rule-a",
			FindingId:      "finding-a",
			RunId:          "run-a",
			CreatedAt:      timestamppb.New(observedAt),
			LastObservedAt: timestamppb.New(observedAt),
		}
		if err := store.PutFindingEvidence(ctx, evidence); err != nil {
			t.Fatalf("PutFindingEvidence(%q) error = %v", evidence.GetId(), err)
		}
	}
	for _, runtimeID := range runtimeIDs {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT evidence_count FROM finding_evidence_counts WHERE runtime_id = $1 AND finding_id = 'finding-a'`, runtimeID).Scan(&count); err != nil {
			t.Fatalf("query materialized evidence count for %q: %v", runtimeID, err)
		}
		if count != 2 {
			t.Fatalf("materialized evidence count for %q = %d, want 2", runtimeID, count)
		}
	}
	evidence, err := store.ListGRCFindingEvidence(ctx, ports.ListFindingEvidenceRequest{
		RuntimeIDs:   runtimeIDs,
		Limit:        3,
		CreatedOrder: true,
	})
	if err != nil {
		t.Fatalf("ListGRCFindingEvidence() error = %v", err)
	}
	if len(evidence) != 3 {
		t.Fatalf("ListGRCFindingEvidence() returned %d records, want 3", len(evidence))
	}
	for index := 1; index < len(evidence); index++ {
		if evidence[index-1].GetCreatedAt().AsTime().Before(evidence[index].GetCreatedAt().AsTime()) {
			t.Fatalf("ListGRCFindingEvidence() records are not globally newest-first: %#v", evidence)
		}
	}
}
