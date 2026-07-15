package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestSourceTrustSchemaKeepsTenantRunObjectiveBoundaries(t *testing.T) {
	joined := strings.Join(ensureSourceTrustStatements, "\n")
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, run_id, objective_id, snapshot_id)",
		"UNIQUE (tenant_id, run_id, objective_id, source_id, dimension_id)",
		"PRIMARY KEY (tenant_id, run_id, objective_id)",
		"requirement_revision_json JSONB NOT NULL",
		"expected_source_check_ids_json JSONB NOT NULL",
		"NOT complete OR expected_check_count = observed_check_count",
		"FOREIGN KEY (tenant_id, run_id, objective_id, snapshot_id)",
		"PRIMARY KEY (tenant_id, event_id)",
		"ADD COLUMN IF NOT EXISTS event_digest",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("source trust schema does not contain %q", required)
		}
	}
}

func TestDecodeSourceTrustEventRequiresDedicatedKindAndTenant(t *testing.T) {
	event, _, _ := validSourceTrustEvents(t, "tenant-a")
	decoded, err := decodeSourceTrustEvent(event)
	if err != nil {
		t.Fatalf("decodeSourceTrustEvent() error = %v", err)
	}
	if decoded.aggregateType != complianceassessment.AggregateTypeSourceCheckSnapshot {
		t.Fatalf("aggregate type = %q", decoded.aggregateType)
	}

	wrongKind := proto.Clone(event).(*cerebrov1.EventEnvelope)
	wrongKind.Kind = workflowevents.EventKindComplianceActivityRecorded
	if _, err := decodeSourceTrustEvent(wrongKind); err == nil {
		t.Fatal("decodeSourceTrustEvent(activity kind) error = nil")
	}

	wrongTenant := proto.Clone(event).(*cerebrov1.EventEnvelope)
	wrongTenant.TenantId = "tenant-b"
	if _, err := decodeSourceTrustEvent(wrongTenant); err == nil {
		t.Fatal("decodeSourceTrustEvent(tenant mismatch) error = nil")
	}

	embeddedPayload := payloadFromEvent(t, event)
	encoded, err := json.Marshal(embeddedPayload)
	if err != nil {
		t.Fatalf("encode source-check payload: %v", err)
	}
	wrongOperation, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceSourceCheckRecorded, TenantID: decoded.tenantID,
		AggregateType: decoded.aggregateType, AggregateID: decoded.aggregateID, AggregateVersion: 1,
		Operation: "updated", ContentDigest: decoded.contentDigest, PayloadJSON: string(encoded), RecordedAt: decoded.recordedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewComplianceAggregateEvent(updated) error = %v", err)
	}
	if _, err := decodeSourceTrustEvent(wrongOperation); !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("decodeSourceTrustEvent(updated operation) error = %v, want conflict", err)
	}
}

func TestSourceTrustEventsReplayDeterministically(t *testing.T) {
	firstSource, _, firstObjective := validSourceTrustEvents(t, "tenant-a")
	secondSource, _, secondObjective := validSourceTrustEvents(t, "tenant-a")
	if firstSource.GetId() != secondSource.GetId() || sourceTrustDigest(firstSource.GetPayload()) != sourceTrustDigest(secondSource.GetPayload()) {
		t.Fatal("equivalent source-check events did not produce a stable identity and digest")
	}
	if firstObjective.GetId() != secondObjective.GetId() || sourceTrustDigest(firstObjective.GetPayload()) != sourceTrustDigest(secondObjective.GetPayload()) {
		t.Fatal("equivalent objective-source events did not produce a stable identity and digest")
	}
}

func TestValidateSourceCheckRecordRequiresExactProofAndCertificationRevisions(t *testing.T) {
	eventEnvelope, payload, _ := validSourceTrustEvents(t, "tenant-a")
	event, err := decodeSourceTrustEvent(eventEnvelope)
	if err != nil {
		t.Fatalf("decodeSourceTrustEvent() error = %v", err)
	}
	if err := validateSourceCheckRecord(event, payload); err != nil {
		t.Fatalf("validateSourceCheckRecord(valid) error = %v", err)
	}

	invalidCertification := payload
	invalidCertification.CertificationRevision = revisionRef("another-receipt", sourceTrustDigest([]byte("certification")), payload.Snapshot.CheckedAt)
	invalidCertification.ContentDigest = mustSourceTrustContentDigest(t, invalidCertification)
	event.contentDigest = invalidCertification.ContentDigest
	if err := validateSourceCheckRecord(event, invalidCertification); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateSourceCheckRecord(certification mismatch) error = %v, want invalid", err)
	}

	missingProof := payload
	missingProof.ProofRevisions = nil
	missingProof.ContentDigest = mustSourceTrustContentDigest(t, missingProof)
	event.contentDigest = missingProof.ContentDigest
	if err := validateSourceCheckRecord(event, missingProof); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateSourceCheckRecord(missing proof) error = %v, want invalid", err)
	}

	unrelatedProof := payload
	unrelatedProof.ProofRevisions = append([]compliance.RevisionRef(nil), payload.ProofRevisions...)
	unrelatedProof.ProofRevisions = append(unrelatedProof.ProofRevisions, *revisionRef("unrelated-proof", sourceTrustDigest([]byte("unrelated")), payload.Snapshot.CheckedAt))
	unrelatedProof.ContentDigest = mustSourceTrustContentDigest(t, unrelatedProof)
	event.contentDigest = unrelatedProof.ContentDigest
	if err := validateSourceCheckRecord(event, unrelatedProof); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateSourceCheckRecord(unrelated proof) error = %v, want invalid", err)
	}

	subMillisecondRevision := payload
	subMillisecondRevision.ProofRevisions = append([]compliance.RevisionRef(nil), payload.ProofRevisions...)
	subMillisecondRevision.ProofRevisions[0].LastModified = payload.Snapshot.CheckedAt.Add(-time.Millisecond).Add(time.Nanosecond)
	subMillisecondRevision.ContentDigest = mustSourceTrustContentDigest(t, subMillisecondRevision)
	event.contentDigest = subMillisecondRevision.ContentDigest
	if err := validateSourceCheckRecord(event, subMillisecondRevision); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateSourceCheckRecord(sub-millisecond revision) error = %v, want invalid", err)
	}

	futureProof := payload
	futureProof.ProofRevisions = append([]compliance.RevisionRef(nil), payload.ProofRevisions...)
	futureProof.ProofRevisions[0].LastModified = payload.Snapshot.CheckedAt.Add(time.Second)
	futureProof.ContentDigest = mustSourceTrustContentDigest(t, futureProof)
	event.contentDigest = futureProof.ContentDigest
	if err := validateSourceCheckRecord(event, futureProof); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateSourceCheckRecord(future proof) error = %v, want invalid", err)
	}

	eventBeforeCheck := event
	eventBeforeCheck.recordedAt = payload.Snapshot.CheckedAt.Add(-time.Second)
	if err := validateSourceCheckRecord(eventBeforeCheck, payload); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateSourceCheckRecord(event before check) error = %v, want invalid", err)
	}

	tamperedDigest := payload
	tamperedDigest.ContentDigest = "sha256:" + strings.Repeat("f", 64)
	event.contentDigest = tamperedDigest.ContentDigest
	if err := validateSourceCheckRecord(event, tamperedDigest); !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("validateSourceCheckRecord(tampered digest) error = %v, want conflict", err)
	}
}

func TestValidateObjectiveSourceRecordRequiresCompleteExactManifest(t *testing.T) {
	_, _, objectiveEvent := validSourceTrustEvents(t, "tenant-a")
	event, err := decodeSourceTrustEvent(objectiveEvent)
	if err != nil {
		t.Fatalf("decodeSourceTrustEvent() error = %v", err)
	}
	var record complianceassessment.ObjectiveSourceAssessmentRecord
	if err := json.Unmarshal([]byte(event.payloadJSON), &record); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	if err := validateObjectiveSourceRecord(event, record); err != nil {
		t.Fatalf("validateObjectiveSourceRecord(valid) error = %v", err)
	}

	for name, mutate := range map[string]func(*complianceassessment.ObjectiveSourceAssessmentRecord){
		"incomplete":             func(value *complianceassessment.ObjectiveSourceAssessmentRecord) { value.Complete = false },
		"missing observed check": func(value *complianceassessment.ObjectiveSourceAssessmentRecord) { value.ObservedCheckCount = 0 },
		"expected check missing": func(value *complianceassessment.ObjectiveSourceAssessmentRecord) { value.ExpectedCheckCount = 2 },
		"missing expected manifest": func(value *complianceassessment.ObjectiveSourceAssessmentRecord) {
			value.ExpectedSourceCheckIDs = nil
		},
		"noncanonical requirement": func(value *complianceassessment.ObjectiveSourceAssessmentRecord) {
			value.Requirement.Sources[0].SourceID = " source-a "
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneObjectiveSourceRecord(t, record)
			mutate(&candidate)
			candidate.ContentDigest = mustObjectiveSourceContentDigest(t, candidate)
			event.contentDigest = candidate.ContentDigest
			if err := validateObjectiveSourceRecord(event, candidate); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
				t.Fatalf("validateObjectiveSourceRecord() error = %v, want invalid", err)
			}
		})
	}

	futureRequirement := record
	futureRequirement.RequirementRevision.LastModified = record.AssessedAt.Add(time.Second)
	futureRequirement.ContentDigest = mustObjectiveSourceContentDigest(t, futureRequirement)
	event.contentDigest = futureRequirement.ContentDigest
	if err := validateObjectiveSourceRecord(event, futureRequirement); !errors.Is(err, complianceassessment.ErrInvalidSourceCheck) {
		t.Fatalf("validateObjectiveSourceRecord(future requirement) error = %v, want invalid", err)
	}

	wrongRequirementDigest := record
	wrongRequirementDigest.RequirementRevision.ContentDigest = compliance.ContentDigest(sourceTrustDigest([]byte("different requirement")))
	wrongRequirementDigest.ContentDigest = mustObjectiveSourceContentDigest(t, wrongRequirementDigest)
	event.contentDigest = wrongRequirementDigest.ContentDigest
	if err := validateObjectiveSourceRecord(event, wrongRequirementDigest); !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("validateObjectiveSourceRecord(requirement digest mismatch) error = %v, want conflict", err)
	}
}

func TestSourceTrustReceiptDecisionIsReplaySafe(t *testing.T) {
	digest := sourceTrustDigest([]byte("event"))
	if apply, err := sourceTrustReceiptDecision("", false, digest); err != nil || !apply {
		t.Fatalf("new receipt decision = %v, %v", apply, err)
	}
	if apply, err := sourceTrustReceiptDecision(digest, true, digest); err != nil || apply {
		t.Fatalf("exact replay decision = %v, %v", apply, err)
	}
	if apply, err := sourceTrustReceiptDecision(digest, true, sourceTrustDigest([]byte("different"))); apply || !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("conflicting replay decision = %v, %v", apply, err)
	}
}

func TestDerivedObjectiveSourceAssessmentRejectsFabricatedFacts(t *testing.T) {
	_, payload, objectiveEvent := validSourceTrustEvents(t, "tenant-a")
	record := objectiveRecordFromEvent(t, objectiveEvent)
	if err := validateDerivedObjectiveSourceAssessment(record, []complianceassessment.SourceCheckSnapshot{payload.Snapshot}); err != nil {
		t.Fatalf("validateDerivedObjectiveSourceAssessment(valid) error = %v", err)
	}
	record.Assessment.EvidenceIDs = append(record.Assessment.EvidenceIDs, "fabricated-evidence")
	if err := validateDerivedObjectiveSourceAssessment(record, []complianceassessment.SourceCheckSnapshot{payload.Snapshot}); !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("validateDerivedObjectiveSourceAssessment(fabricated) error = %v, want conflict", err)
	}
}

func TestApplySourceTrustEventIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run source trust persistence integration test")
	}
	ctx := context.Background()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	tenantID := "source-trust-test-" + time.Now().UTC().Format("20060102150405.000000000")
	sourceEvent, payload, objectiveEvent := validSourceTrustEvents(t, tenantID)
	defer cleanupSourceTrustTenant(t, ctx, store, tenantID)

	applied, err := store.ApplySourceTrustEvent(ctx, sourceEvent)
	if err != nil || !applied {
		t.Fatalf("ApplySourceTrustEvent(source) = %v, %v", applied, err)
	}
	if applied, err = store.ApplySourceTrustEvent(ctx, sourceEvent); err != nil || applied {
		t.Fatalf("ApplySourceTrustEvent(source replay) = %v, %v", applied, err)
	}

	conflictingPayload := payload
	conflictingPayload.ProofRevisions = append([]compliance.RevisionRef(nil), payload.ProofRevisions...)
	conflictingPayload.ProofRevisions[0].RevisionID = payload.ProofRevisions[0].RevisionID + "-alternate"
	conflictingPayload.ProofRevisions[0].Version++
	conflictingPayload.ContentDigest = mustSourceTrustContentDigest(t, conflictingPayload)
	conflict := newSourceTrustEvent(t, tenantID, complianceassessment.AggregateTypeSourceCheckSnapshot, payload.Snapshot.ID, conflictingPayload.ContentDigest, conflictingPayload, payload.Snapshot.CheckedAt)
	if conflict.GetId() != sourceEvent.GetId() {
		t.Fatalf("conflicting replay id = %q, want %q", conflict.GetId(), sourceEvent.GetId())
	}
	if applied, err = store.ApplySourceTrustEvent(ctx, conflict); applied || !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("ApplySourceTrustEvent(conflicting receipt) = %v, %v", applied, err)
	}

	fabricatedObjective := objectiveRecordFromEvent(t, objectiveEvent)
	fabricatedObjective.Assessment.EvidenceIDs = append(fabricatedObjective.Assessment.EvidenceIDs, "fabricated-evidence")
	fabricatedObjective.ContentDigest = mustObjectiveSourceContentDigest(t, fabricatedObjective)
	fabricatedEvent := newSourceTrustEvent(t, tenantID, complianceassessment.AggregateTypeObjectiveSourceAssessment, fabricatedObjective.ID, fabricatedObjective.ContentDigest, fabricatedObjective, fabricatedObjective.AssessedAt)
	if applied, err = store.ApplySourceTrustEvent(ctx, fabricatedEvent); applied || !errors.Is(err, complianceassessment.ErrSourceTrustProjectionConflict) {
		t.Fatalf("ApplySourceTrustEvent(fabricated objective) = %v, %v", applied, err)
	}
	if applied, err = store.ApplySourceTrustEvent(ctx, objectiveEvent); err != nil || !applied {
		t.Fatalf("ApplySourceTrustEvent(objective) = %v, %v", applied, err)
	}

	stored, err := store.GetSourceCheckSnapshot(ctx, tenantID, "run-a", "objective-a", payload.Snapshot.ID)
	if err != nil || stored.ContentDigest != payload.ContentDigest || stored.Snapshot.SnapshotHash != payload.Snapshot.SnapshotHash {
		t.Fatalf("GetSourceCheckSnapshot() = %+v, %v", stored, err)
	}
	assessment, err := store.GetObjectiveSourceAssessment(ctx, tenantID, "run-a", "objective-a")
	if err != nil || !assessment.Complete || assessment.ObservedCheckCount != 1 {
		t.Fatalf("GetObjectiveSourceAssessment() = %+v, %v", assessment, err)
	}
	if _, err := store.GetSourceCheckSnapshot(ctx, "another-tenant", "run-a", "objective-a", payload.Snapshot.ID); !errors.Is(err, complianceassessment.ErrSourceCheckNotFound) {
		t.Fatalf("foreign tenant source lookup error = %v", err)
	}
	if _, err := store.GetObjectiveSourceAssessment(ctx, "another-tenant", "run-a", "objective-a"); !errors.Is(err, complianceassessment.ErrObjectiveSourceNotFound) {
		t.Fatalf("foreign tenant objective lookup error = %v", err)
	}

	concurrentTenantID := tenantID + "-concurrent"
	concurrentEvent, _, _ := validSourceTrustEvents(t, concurrentTenantID)
	defer cleanupSourceTrustTenant(t, ctx, store, concurrentTenantID)
	type applyResult struct {
		applied bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan applyResult, 2)
	for range 2 {
		go func() {
			<-start
			wasApplied, applyErr := store.ApplySourceTrustEvent(ctx, concurrentEvent)
			results <- applyResult{applied: wasApplied, err: applyErr}
		}()
	}
	close(start)
	appliedCount := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent ApplySourceTrustEvent() error = %v", result.err)
		}
		if result.applied {
			appliedCount++
		}
	}
	if appliedCount != 1 {
		t.Fatalf("concurrent applied count = %d, want 1", appliedCount)
	}

}

func validSourceTrustEvents(t *testing.T, tenantID string) (*cerebrov1.EventEnvelope, complianceassessment.SourceCheckRecordedPayload, *cerebrov1.EventEnvelope) {
	t.Helper()
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	receiptHash := sourceTrustDigest([]byte("collection receipt"))
	snapshot, err := complianceassessment.BuildSourceCheckSnapshot(complianceassessment.SourceCheckInput{
		TenantID: tenantID, SourceID: "source-a", RuntimeID: "runtime-a", DimensionID: "dimension-a",
		Support: complianceassessment.SourceSupportSupported, Health: complianceassessment.SourceHealthHealthy,
		Certification: sourcecoverage.CertificationFixtureValidated, CertificationReceiptID: "certification-receipt-a",
		Watermark: "watermark-a", CollectionReceiptID: "collection-receipt-a", CollectionReceiptHash: receiptHash,
		LastSuccessfulAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour),
		AffectedObjectiveIDs: []string{"objective-a"}, EvidenceIDs: []string{"evidence-a"}, CheckedAt: now,
	})
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot() error = %v", err)
	}
	payload := complianceassessment.SourceCheckRecordedPayload{
		RunID: "run-a", ObjectiveID: "objective-a", Snapshot: snapshot,
		CertificationRevision: revisionRef(snapshot.CertificationReceiptID, sourceTrustDigest([]byte("certification")), now),
		ProofRevisions:        []compliance.RevisionRef{*revisionRef(snapshot.CollectionReceiptID, snapshot.CollectionReceiptHash, now)},
	}
	payload.ContentDigest = mustSourceTrustContentDigest(t, payload)
	sourceEvent := newSourceTrustEvent(t, tenantID, complianceassessment.AggregateTypeSourceCheckSnapshot, snapshot.ID, payload.ContentDigest, payload, now)

	requirement := complianceassessment.ObjectiveSourceRequirement{
		ObjectiveID: "objective-a", Sources: []complianceassessment.SourceCheckRequirement{{
			SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated,
		}},
	}
	assessment, err := complianceassessment.AssessObjectiveSourceChecks(requirement, []complianceassessment.SourceCheckSnapshot{snapshot})
	if err != nil {
		t.Fatalf("AssessObjectiveSourceChecks() error = %v", err)
	}
	record := complianceassessment.ObjectiveSourceAssessmentRecord{
		ID: "objective-source-assessment-a", TenantID: tenantID, RunID: "run-a", ObjectiveID: "objective-a",
		Requirement: requirement, ExpectedSourceCheckIDs: []string{snapshot.ID},
		ExpectedCheckCount: 1, ObservedCheckCount: 1, Complete: true, Assessment: assessment, AssessedAt: now,
	}
	requirementDigest, err := sourceTrustValueDigest(requirement)
	if err != nil {
		t.Fatalf("sourceTrustValueDigest(requirement) error = %v", err)
	}
	record.RequirementRevision = *revisionRef("objective-source-requirement-a", requirementDigest, now)
	record.ContentDigest = mustObjectiveSourceContentDigest(t, record)
	objectiveEvent := newSourceTrustEvent(t, tenantID, complianceassessment.AggregateTypeObjectiveSourceAssessment, record.ID, record.ContentDigest, record, now)
	return sourceEvent, payload, objectiveEvent
}

func objectiveRecordFromEvent(t *testing.T, event *cerebrov1.EventEnvelope) complianceassessment.ObjectiveSourceAssessmentRecord {
	t.Helper()
	decoded, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		t.Fatalf("DecodeComplianceAggregate() error = %v", err)
	}
	var record complianceassessment.ObjectiveSourceAssessmentRecord
	if err := json.Unmarshal([]byte(decoded.PayloadJSON), &record); err != nil {
		t.Fatalf("decode objective source record: %v", err)
	}
	return record
}

func cloneObjectiveSourceRecord(t *testing.T, record complianceassessment.ObjectiveSourceAssessmentRecord) complianceassessment.ObjectiveSourceAssessmentRecord {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encode objective source record: %v", err)
	}
	var clone complianceassessment.ObjectiveSourceAssessmentRecord
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("decode objective source record: %v", err)
	}
	return clone
}

func newSourceTrustEvent(t *testing.T, tenantID, aggregateType, aggregateID, digest string, payload any, now time.Time) *cerebrov1.EventEnvelope {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal source trust payload: %v", err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceSourceCheckRecorded, TenantID: tenantID,
		AggregateType: aggregateType, AggregateID: aggregateID, AggregateVersion: 1,
		Operation: "recorded", ContentDigest: digest, PayloadJSON: string(encoded), RecordedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewComplianceAggregateEvent() error = %v", err)
	}
	return event
}

func payloadFromEvent(t *testing.T, event *cerebrov1.EventEnvelope) any {
	t.Helper()
	decoded, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		t.Fatalf("DecodeComplianceAggregate() error = %v", err)
	}
	var payload any
	if err := json.Unmarshal([]byte(decoded.PayloadJSON), &payload); err != nil {
		t.Fatalf("decode embedded payload: %v", err)
	}
	return payload
}

func revisionRef(id, digest string, now time.Time) *compliance.RevisionRef {
	return &compliance.RevisionRef{ID: id, RevisionID: id + "-revision-1", Version: 1, ContentDigest: compliance.ContentDigest(digest), LastModified: now}
}

func mustSourceTrustContentDigest(t *testing.T, payload complianceassessment.SourceCheckRecordedPayload) string {
	t.Helper()
	digest, err := sourceTrustContentDigest(payload)
	if err != nil {
		t.Fatalf("sourceTrustContentDigest() error = %v", err)
	}
	return digest
}

func mustObjectiveSourceContentDigest(t *testing.T, record complianceassessment.ObjectiveSourceAssessmentRecord) string {
	t.Helper()
	digest, err := objectiveSourceContentDigest(record)
	if err != nil {
		t.Fatalf("objectiveSourceContentDigest() error = %v", err)
	}
	return digest
}

func cleanupSourceTrustTenant(t *testing.T, ctx context.Context, store *Store, tenantID string) {
	t.Helper()
	for _, query := range []string{
		"DELETE FROM compliance_source_trust_event_receipts WHERE tenant_id = $1",
		"DELETE FROM compliance_objective_source_check_refs WHERE tenant_id = $1",
		"DELETE FROM compliance_objective_source_assessments WHERE tenant_id = $1",
		"DELETE FROM compliance_source_check_snapshots WHERE tenant_id = $1",
	} {
		if _, err := store.db.ExecContext(ctx, query, tenantID); err != nil {
			t.Errorf("cleanup source trust tenant: %v", err)
		}
	}
}
