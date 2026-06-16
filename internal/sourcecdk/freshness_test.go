package sourcecdk

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestFamilyFreshnessCheckpointStoresCanaryExtra(t *testing.T) {
	observedAt := time.Date(2026, 6, 16, 15, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 6, 16, 14, 59, 0, 0, time.UTC)
	checkpoint := FamilyFreshnessCheckpoint(" github ", " audit ", &cerebrov1.SourceCheckpoint{CursorOpaque: "cursor-2"}, FamilyFreshnessProbe{
		Kind:       " audit_log_latest_event ",
		ResourceID: " github-audit-1 ",
		ObservedAt: observedAt,
		UpdatedAt:  updatedAt,
		Hash:       " canary-hash ",
		Confidence: FamilyFreshnessConfidenceHeuristic,
	})

	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok {
		t.Fatalf("checkpoint cursor %q is not an envelope", checkpoint.GetCursorOpaque())
	}
	if envelope.Source != "github" || envelope.Family != "audit" || envelope.Mode != FamilyFreshnessProbeMode {
		t.Fatalf("envelope source/family/mode = %q/%q/%q", envelope.Source, envelope.Family, envelope.Mode)
	}
	if envelope.Token != "cursor-2" {
		t.Fatalf("envelope token = %q, want cursor-2", envelope.Token)
	}
	if envelope.ResumableCheckpoint {
		t.Fatal("freshness-only checkpoint is resumable, want metadata-only cursor")
	}
	if got := envelope.Extra[FamilyFreshnessExtraKind]; got != "audit_log_latest_event" {
		t.Fatalf("canary kind = %q, want audit_log_latest_event", got)
	}
	if got := envelope.Extra[FamilyFreshnessExtraResourceID]; got != "github-audit-1" {
		t.Fatalf("canary resource = %q, want github-audit-1", got)
	}
	if got := envelope.Extra[FamilyFreshnessExtraObservedAt]; got != observedAt.Format(time.RFC3339Nano) {
		t.Fatalf("canary observed_at = %q, want %s", got, observedAt.Format(time.RFC3339Nano))
	}
	if got := envelope.Extra[FamilyFreshnessExtraUpdatedAt]; got != updatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("canary updated_at = %q, want %s", got, updatedAt.Format(time.RFC3339Nano))
	}

	probe, ok := FamilyFreshnessProbeFromCheckpoint("github", "audit", checkpoint)
	if !ok {
		t.Fatal("FamilyFreshnessProbeFromCheckpoint() ok = false, want true")
	}
	if probe.Kind != "audit_log_latest_event" || probe.ResourceID != "github-audit-1" || probe.Hash != "canary-hash" {
		t.Fatalf("probe = %#v, want normalized canary", probe)
	}
}

func TestFamilyFreshnessChangeProbeIgnoresObservedAtForChangeDetection(t *testing.T) {
	updatedAt := time.Date(2026, 6, 16, 14, 59, 0, 0, time.UTC)
	hash := FamilyFreshnessHash("audit_log_latest_event", "github-audit-1", updatedAt.Format(time.RFC3339Nano))
	checkpoint := FamilyFreshnessCheckpoint("github", "audit", nil, FamilyFreshnessProbe{
		Kind:       "audit_log_latest_event",
		ResourceID: "github-audit-1",
		ObservedAt: updatedAt.Add(time.Minute),
		UpdatedAt:  updatedAt,
		Hash:       hash,
		Confidence: FamilyFreshnessConfidenceHeuristic,
	})

	change := FamilyFreshnessChangeProbe("github", "audit", checkpoint, FamilyFreshnessProbe{
		Kind:       "audit_log_latest_event",
		ResourceID: "github-audit-1",
		ObservedAt: updatedAt.Add(time.Hour),
		UpdatedAt:  updatedAt,
		Hash:       hash,
		Confidence: FamilyFreshnessConfidenceHeuristic,
	})
	if !change.Unchanged {
		t.Fatal("ChangeProbe.Unchanged = false, want true for same canary hash")
	}
	if change.ShortCircuitReason != PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", change.ShortCircuitReason)
	}

	nextProbe, ok := FamilyFreshnessProbeFromCheckpoint("github", "audit", change.Checkpoint)
	if !ok {
		t.Fatal("updated checkpoint missing freshness probe")
	}
	if !nextProbe.ObservedAt.Equal(updatedAt.Add(time.Hour)) {
		t.Fatalf("observed_at = %s, want refreshed observed time", nextProbe.ObservedAt)
	}
}

func TestFamilyFreshnessCheckpointPreservesExistingResumableEnvelope(t *testing.T) {
	opaque, err := EncodeCursorEnvelope(CursorEnvelope{
		Source:              "github",
		Family:              "pull_request",
		Mode:                "incremental_watermark",
		ResumableCheckpoint: true,
		Token:               "2",
		BoundaryIDs:         []string{"pr-1"},
		Extra:               map[string]string{"existing": "kept"},
	})
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}

	checkpoint := FamilyFreshnessCheckpoint("github", "pull_request", &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}, FamilyFreshnessProbe{
		Kind:       "repo_updated_at",
		ResourceID: "writer/cerebro",
		Hash:       "hash",
	})
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok {
		t.Fatal("checkpoint cursor is not an envelope")
	}
	if !envelope.ResumableCheckpoint || envelope.Mode != "incremental_watermark" || envelope.Token != "2" {
		t.Fatalf("envelope resumable/mode/token = %v/%q/%q", envelope.ResumableCheckpoint, envelope.Mode, envelope.Token)
	}
	if got := envelope.BoundaryIDs; len(got) != 1 || got[0] != "pr-1" {
		t.Fatalf("boundary IDs = %#v, want pr-1", got)
	}
	if got := envelope.Extra["existing"]; got != "kept" {
		t.Fatalf("existing extra = %q, want kept", got)
	}
	if got := envelope.Extra[FamilyFreshnessExtraHash]; got != "hash" {
		t.Fatalf("canary hash = %q, want hash", got)
	}
}

func TestBeginFamilyFreshnessReadCarriesProbeFromContinuationCursor(t *testing.T) {
	checkpoint := FamilyFreshnessCheckpoint("github", "audit", nil, FamilyFreshnessProbe{
		Kind:       "audit_log_latest_event",
		ResourceID: "github-audit-1",
		Hash:       "hash",
	})
	cursor := &cerebrov1.SourceCursor{Opaque: FamilyFreshnessCursor("github", "audit", checkpoint, "cursor-2")}

	readCheckpoint, shortCircuit, err := BeginFamilyFreshnessRead("github", "audit", cursor, nil, func(*cerebrov1.SourceCheckpoint) (ChangeProbe, error) {
		t.Fatal("probe should not run while a continuation cursor is active")
		return ChangeProbe{}, nil
	})
	if err != nil {
		t.Fatalf("BeginFamilyFreshnessRead() error = %v", err)
	}
	if shortCircuit != nil {
		t.Fatalf("shortCircuit = %#v, want nil while cursor is active", shortCircuit)
	}
	if got := CursorToken(cursor); got != "cursor-2" {
		t.Fatalf("CursorToken(cursor) = %q, want cursor-2", got)
	}
	if _, ok := FamilyFreshnessProbeFromCheckpoint("github", "audit", readCheckpoint); !ok {
		t.Fatalf("read checkpoint %q missing freshness probe", readCheckpoint.GetCursorOpaque())
	}
}
