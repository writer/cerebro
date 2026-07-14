package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/complianceassessment"
)

func TestComplianceAssessmentSchemaPinsTenantRevisionAndChunkBoundaries(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureComplianceAssessmentStatements, "\n")
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, revision_id)",
		"UNIQUE (tenant_id, plan_id, revision_version)",
		"UNIQUE (tenant_id, idempotency_key)",
		"PRIMARY KEY (tenant_id, run_id, sequence)",
		"FOREIGN KEY (tenant_id, plan_revision_id)",
		"payload_digest TEXT NOT NULL",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("assessment schema missing %q", required)
		}
	}
}

func TestComplianceAssessmentChunkProjectionDoesNotRewriteExistingPayload(t *testing.T) {
	t.Parallel()
	query := strings.ToUpper(insertComplianceAssessmentResultChunk)
	if strings.Contains(query, "DO UPDATE") || !strings.Contains(query, "DO NOTHING") {
		t.Fatalf("chunk insert must preserve the first durable payload: %s", insertComplianceAssessmentResultChunk)
	}
}

func TestComplianceAssessmentChunkReplayRequiresExactPayload(t *testing.T) {
	t.Parallel()
	chunk := complianceassessment.ResultChunk{
		RunID: "run-1", Sequence: 1, FirstResultID: "result-1", LastResultID: "result-1",
		Count: 1, Digest: "sha256:" + strings.Repeat("a", 64),
	}
	stored, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if !assessmentResultChunkPayloadMatches(stored, assessmentJSONDigest(stored)) {
		t.Fatal("identical chunk payload did not match")
	}
	chunk.FirstResultID = "altered-result"
	altered, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if assessmentResultChunkPayloadMatches(stored, assessmentJSONDigest(altered)) {
		t.Fatal("altered chunk payload matched the durable record")
	}
}

func TestComplianceAssessmentReceiptTrimsTenantID(t *testing.T) {
	t.Parallel()
	recorder := &assessmentReceiptRecorder{}
	if err := insertAssessmentReceipt(context.Background(), recorder, "event-1", "  tenant-1  ", "assessment_result_chunk", "run-1", 1, "sha256:digest"); err != nil {
		t.Fatalf("insertAssessmentReceipt() error = %v", err)
	}
	if len(recorder.args) != 6 {
		t.Fatalf("receipt args = %#v, want 6 values", recorder.args)
	}
	if got := recorder.args[1]; got != "tenant-1" {
		t.Fatalf("receipt tenant_id = %q, want %q", got, "tenant-1")
	}
}

type assessmentReceiptRecorder struct {
	args []any
}

func (r *assessmentReceiptRecorder) ExecContext(_ context.Context, _ string, args ...any) (sql.Result, error) {
	r.args = append([]any(nil), args...)
	return nil, nil
}
