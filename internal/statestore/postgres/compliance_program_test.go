package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestComplianceProgramSchemaPreservesRevisionAndReceiptBoundaries(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureComplianceProgramStatements, "\n")
	for _, fragment := range []string{
		"PRIMARY KEY (tenant_id, program_id)",
		"grc_program_scope_revisions",
		"UNIQUE (tenant_id, program_id, scope_id, revision_version)",
		"grc_program_scope_selectors",
		"grc_program_scope_subjects",
		"grc_control_implementation_revisions",
		"UNIQUE (tenant_id, program_id, implementation_id, revision_version)",
		"grc_control_mapping_revisions",
		"grc_compliance_event_application_receipts",
		"PRIMARY KEY (tenant_id, event_id)",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("compliance program schema missing %q", fragment)
		}
	}
}

func TestComplianceProgramSchemaIncludesIdempotentUpgrades(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureComplianceProgramStatements, "\n")
	for _, fragment := range []string{
		"ALTER TABLE grc_program_scope_selectors ADD COLUMN IF NOT EXISTS resolution_state",
		"ALTER TABLE grc_program_scope_selectors ADD COLUMN IF NOT EXISTS unresolved_reason",
		"ALTER TABLE grc_compliance_event_application_receipts ADD COLUMN IF NOT EXISTS event_digest",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("compliance program schema upgrade missing %q", fragment)
		}
	}
}

func TestComplianceProgramApplicationAdvisoryLockSerializesReceipts(t *testing.T) {
	t.Parallel()
	query := complianceApplicationAdvisoryLockSQL()
	for _, fragment := range []string{"pg_advisory_xact_lock", "grc_compliance_event_application", "hashtext($1)"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("compliance application advisory lock missing %q", fragment)
		}
	}
}

func TestComplianceProgramApplicationReceiptDecisions(t *testing.T) {
	t.Parallel()
	if apply, err := complianceReceiptDecision("", false, testComplianceDigest("1")); err != nil || !apply {
		t.Fatalf("new receipt decision = (%v, %v), want apply", apply, err)
	}
	if apply, err := complianceReceiptDecision(testComplianceDigest("1"), true, testComplianceDigest("1")); err != nil || apply {
		t.Fatalf("same-digest receipt decision = (%v, %v), want no-op", apply, err)
	}
	if apply, err := complianceReceiptDecision(testComplianceDigest("1"), true, testComplianceDigest("2")); !errors.Is(err, ports.ErrComplianceEventApplicationConflict) || apply {
		t.Fatalf("conflicting receipt decision = (%v, %v), want conflict", apply, err)
	}
}

func TestComplianceProgramConflictingDuplicateHasDifferentEventDigest(t *testing.T) {
	t.Parallel()
	tenantID := "tenant-conflict"
	first := testComplianceEvent(t, workflowevents.EventKindComplianceProgramRecorded, tenantID, 1, "", testComplianceDigest("1"), testComplianceProgramRecord(tenantID))
	changed := testComplianceProgramRecord(tenantID)
	changed.Name = "Changed name"
	second := testComplianceEvent(t, workflowevents.EventKindComplianceProgramRecorded, tenantID, 1, "", testComplianceDigest("2"), changed)
	if first.GetId() != second.GetId() {
		t.Fatal("same aggregate operation did not produce the same deterministic event id")
	}
	firstApplication, err := decodeComplianceProgramApplication(first)
	if err != nil {
		t.Fatalf("decode first application: %v", err)
	}
	secondApplication, err := decodeComplianceProgramApplication(second)
	if err != nil {
		t.Fatalf("decode second application: %v", err)
	}
	if firstApplication.eventDigest == secondApplication.eventDigest {
		t.Fatal("conflicting duplicate payloads produced the same event digest")
	}
	if _, err := complianceReceiptDecision(firstApplication.eventDigest, true, secondApplication.eventDigest); !errors.Is(err, ports.ErrComplianceEventApplicationConflict) {
		t.Fatalf("conflicting duplicate decision error = %v, want application conflict", err)
	}
}

func TestComplianceProgramAggregateAdvanceRejectsGapAndStaleVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		exists   bool
		current  uint64
		incoming uint64
		want     error
	}{
		{name: "initial", incoming: 1},
		{name: "next", exists: true, current: 4, incoming: 5},
		{name: "initial gap", incoming: 2, want: ports.ErrComplianceEventVersionGap},
		{name: "later gap", exists: true, current: 2, incoming: 4, want: ports.ErrComplianceEventVersionGap},
		{name: "duplicate without receipt", exists: true, current: 2, incoming: 2, want: ports.ErrComplianceProgramVersionConflict},
		{name: "stale", exists: true, current: 3, incoming: 2, want: ports.ErrComplianceProgramVersionConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateComplianceAggregateAdvance(test.exists, test.current, test.incoming)
			if !errors.Is(err, test.want) {
				t.Fatalf("validateComplianceAggregateAdvance() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestComplianceProgramEventReplayReconstructsDeterministically(t *testing.T) {
	t.Parallel()
	events := testComplianceProgramEvents(t, "tenant-replay")
	first := newTestComplianceReplay()
	for _, event := range events {
		if err := first.apply(event); err != nil {
			t.Fatalf("first replay apply: %v", err)
		}
	}
	second := newTestComplianceReplay()
	for _, event := range events {
		if err := second.apply(event); err != nil {
			t.Fatalf("second replay apply: %v", err)
		}
		if err := second.apply(event); err != nil {
			t.Fatalf("duplicate replay apply: %v", err)
		}
	}
	if !reflect.DeepEqual(first.snapshot(), second.snapshot()) {
		t.Fatalf("replay snapshots differ:\nfirst = %#v\nsecond = %#v", first.snapshot(), second.snapshot())
	}
}

func TestComplianceProgramJSONIsBounded(t *testing.T) {
	t.Parallel()
	if _, err := marshalBoundedComplianceProgramJSON(strings.Repeat("x", maxComplianceProgramJSONBytes)); err == nil {
		t.Fatal("oversized compliance program JSON unexpectedly accepted")
	}
}

func TestComplianceProgramLookupSQLIsTenantScoped(t *testing.T) {
	t.Parallel()
	for name, query := range map[string]string{
		"program":        complianceProgramSelectSQL,
		"implementation": controlImplementationSelectSQL,
	} {
		if !strings.Contains(query, "tenant_id = $1") {
			t.Fatalf("%s lookup is not tenant-scoped: %s", name, query)
		}
	}
}

func TestComplianceProgramProjectionPostgresReplay(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run compliance program replay integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	ctx := context.Background()
	tenantID := fmt.Sprintf("compliance-program-%d", time.Now().UnixNano())
	events := testComplianceProgramEvents(t, tenantID)
	if err := store.ensureComplianceProgramTables(ctx); err != nil {
		t.Fatalf("ensure compliance program tables: %v", err)
	}
	cleanupComplianceProgramTenant(t, ctx, store, tenantID)
	t.Cleanup(func() {
		cleanupComplianceProgramTenant(t, context.Background(), store, tenantID)
		_ = store.Close()
	})

	for _, event := range events {
		applied, applyErr := store.ApplyComplianceProgramEvent(ctx, event)
		if applyErr != nil || !applied {
			t.Fatalf("ApplyComplianceProgramEvent() = (%v, %v), want applied", applied, applyErr)
		}
	}
	if applied, applyErr := store.ApplyComplianceProgramEvent(ctx, events[0]); applyErr != nil || applied {
		t.Fatalf("duplicate ApplyComplianceProgramEvent() = (%v, %v), want no-op", applied, applyErr)
	}
	programID := testProgramID()
	first := readComplianceProgramSnapshot(t, ctx, store, tenantID, programID)
	if _, getErr := store.GetComplianceProgram(ctx, tenantID+"-foreign", programID); !errors.Is(getErr, ports.ErrComplianceProgramNotFound) {
		t.Fatalf("foreign tenant program lookup error = %v, want opaque not found", getErr)
	}

	conflictPayload := testComplianceProgramRecord(tenantID)
	conflictPayload.Name = "Changed replay payload"
	conflicting := testComplianceEvent(t, workflowevents.EventKindComplianceProgramRecorded, tenantID, 1, "", testComplianceDigest("9"), conflictPayload)
	if conflicting.GetId() != events[0].GetId() {
		t.Fatal("conflicting duplicate fixture did not preserve deterministic event id")
	}
	if _, applyErr := store.ApplyComplianceProgramEvent(ctx, conflicting); !errors.Is(applyErr, ports.ErrComplianceEventApplicationConflict) {
		t.Fatalf("conflicting duplicate error = %v, want application conflict", applyErr)
	}

	cleanupComplianceProgramTenant(t, ctx, store, tenantID)
	for _, event := range events {
		if _, applyErr := store.ApplyComplianceProgramEvent(ctx, event); applyErr != nil {
			t.Fatalf("reconstruction apply: %v", applyErr)
		}
	}
	second := readComplianceProgramSnapshot(t, ctx, store, tenantID, programID)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Postgres reconstruction differs:\nfirst = %#v\nsecond = %#v", first, second)
	}
}

type testComplianceReplay struct {
	receipts       map[string]string
	version        uint64
	program        grcprogram.ComplianceProgramRecord
	scope          grcprogram.ProgramScopeRevisionRecord
	implementation grcprogram.ControlImplementationRecordedPayload
}

type testComplianceSnapshot struct {
	Version        uint64
	Program        grcprogram.ComplianceProgramRecord
	Scope          grcprogram.ProgramScopeRevisionRecord
	Implementation grcprogram.ControlImplementationRecordedPayload
}

func newTestComplianceReplay() *testComplianceReplay {
	return &testComplianceReplay{receipts: map[string]string{}}
}

func (replay *testComplianceReplay) apply(event *cerebrov1.EventEnvelope) error {
	application, err := decodeComplianceProgramApplication(event)
	if err != nil {
		return err
	}
	existing, exists := replay.receipts[application.eventID]
	apply, err := complianceReceiptDecision(existing, exists, application.eventDigest)
	if err != nil || !apply {
		return err
	}
	if err := validateComplianceAggregateAdvance(replay.version != 0, replay.version, application.aggregateVersion); err != nil {
		return err
	}
	switch application.kind {
	case workflowevents.EventKindComplianceProgramRecorded:
		err = json.Unmarshal([]byte(application.payloadJSON), &replay.program)
	case workflowevents.EventKindComplianceProgramScopeRecorded:
		err = json.Unmarshal([]byte(application.payloadJSON), &replay.scope)
	case workflowevents.EventKindComplianceImplementationRecorded:
		err = json.Unmarshal([]byte(application.payloadJSON), &replay.implementation)
	}
	if err != nil {
		return err
	}
	replay.version = application.aggregateVersion
	replay.receipts[application.eventID] = application.eventDigest
	return nil
}

func (replay *testComplianceReplay) snapshot() testComplianceSnapshot {
	return testComplianceSnapshot{Version: replay.version, Program: replay.program, Scope: replay.scope, Implementation: replay.implementation}
}

func testComplianceProgramEvents(t *testing.T, tenantID string) []*cerebrov1.EventEnvelope {
	t.Helper()
	program := testComplianceProgramRecord(tenantID)
	scope := testComplianceScopeRevision(tenantID)
	implementation := testComplianceImplementationPayload(tenantID)
	return []*cerebrov1.EventEnvelope{
		testComplianceEvent(t, workflowevents.EventKindComplianceProgramRecorded, tenantID, 1, "", testComplianceDigest("1"), program),
		testComplianceEvent(t, workflowevents.EventKindComplianceProgramScopeRecorded, tenantID, 2, scope.Version.RevisionID, string(scope.Version.ContentDigest), scope),
		testComplianceEvent(t, workflowevents.EventKindComplianceImplementationRecorded, tenantID, 3, implementation.Revision.Version.RevisionID, string(implementation.Revision.Version.ContentDigest), implementation),
	}
}

func testComplianceEvent(t *testing.T, kind string, tenantID string, version int64, revisionID string, digest string, payload any) *cerebrov1.EventEnvelope {
	t.Helper()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal compliance event payload: %v", err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: kind, TenantID: tenantID, AggregateType: "program", AggregateID: testProgramID(),
		RevisionID: revisionID, AggregateVersion: version, Operation: "recorded",
		ContentDigest: digest, PayloadJSON: string(payloadJSON), ActorID: "actor-one",
		RecordedAt: testComplianceTime().Add(time.Duration(version) * time.Second).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewComplianceAggregateEvent() error = %v", err)
	}
	return event
}

func testComplianceProgramRecord(tenantID string) grcprogram.ComplianceProgramRecord {
	return grcprogram.ComplianceProgramRecord{
		TenantID: tenantID, ID: testProgramID(), Name: "Payment controls", OwnerTeam: "security",
		Status: grcprogram.ComplianceProgramActive, AggregateVersion: 1,
		CreatedAt: testComplianceTime(), UpdatedAt: testComplianceTime(),
	}
}

func testComplianceScopeRevision(tenantID string) grcprogram.ProgramScopeRevisionRecord {
	digest := compliance.ContentDigest(testComplianceDigest("2"))
	return grcprogram.ProgramScopeRevisionRecord{
		TenantID: tenantID, ProgramID: testProgramID(), State: grcprogram.ScopeRevisionActive,
		Version: compliance.VersionMetadata{
			ID: "scope-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RevisionID: "scope-revision-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Version: 1, LastModified: testComplianceTime().Add(2 * time.Second), ContentDigest: digest, CreatedBy: "actor-one",
		},
		ChangeSummary: "Establish scope",
		Specification: grcprogram.ProgramScopeSpecification{
			Selectors: []grcprogram.ProgramScopeSelector{{
				ID: "asset-include", Kind: "asset", Mode: grcprogram.ScopeSelectorInclude,
				Criteria: []grcprogram.ScopeSelectorCriterion{{Field: "id", Operator: "prefix", Value: "prod-"}},
				Source:   "inventory", Reason: "Boundary", ApproverID: "actor-one", EffectiveFrom: testComplianceTime(),
			}},
			SubjectManifest: grcprogram.ProgramSubjectManifest{
				Subjects:            []compliance.SubjectRef{{Type: "asset", ID: "asset-one"}},
				SelectorResolutions: []grcprogram.SelectorResolution{{SelectorID: "asset-include", State: grcprogram.SubjectResolutionResolved, Subjects: []compliance.SubjectRef{{Type: "asset", ID: "asset-one"}}}},
				Watermark:           "inventory:1", Cutoff: testComplianceTime(), ContentDigest: compliance.ContentDigest(testComplianceDigest("3")),
			},
		},
	}
}

func testComplianceImplementationPayload(tenantID string) grcprogram.ControlImplementationRecordedPayload {
	digest := compliance.ContentDigest(testComplianceDigest("4"))
	implementationID := "implementation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revisionID := "implementation-revision-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return grcprogram.ControlImplementationRecordedPayload{
		Implementation: grcprogram.ControlImplementationRecord{
			TenantID: tenantID, ProgramID: testProgramID(), ID: implementationID,
			CurrentRevisionID: revisionID, AggregateVersion: 1,
			CreatedAt: testComplianceTime().Add(3 * time.Second), UpdatedAt: testComplianceTime().Add(3 * time.Second),
		},
		Revision: grcprogram.ControlImplementationRevisionRecord{
			TenantID: tenantID, ProgramID: testProgramID(), ImplementationID: implementationID,
			Version: compliance.VersionMetadata{
				ID: implementationID, RevisionID: revisionID, Version: 1,
				LastModified: testComplianceTime().Add(3 * time.Second), ContentDigest: digest, CreatedBy: "actor-one",
			},
			ChangeSummary: "Record implementation",
			Specification: grcprogram.ControlImplementationSpecification{
				ScopeRevisionID: "scope-revision-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ControlRef:      compliance.ControlRef{FrameworkID: "framework-one", ControlID: "AC-1"},
				Status:          grcprogram.ImplementationImplemented, Narrative: "Identity policy is enforced.", OwnerTeam: "identity",
				ReviewPolicy:     grcprogram.ImplementationReviewPolicy{Cadence: "P30D", EffectiveFrom: testComplianceTime()},
				ResponsibleRoles: []string{"operator"}, AccountableRoles: []string{"owner"}, Responsibility: grcprogram.ResponsibilityDirect,
				MappingRefs: []grcprogram.ControlMappingRef{{
					ID:           "control-mapping-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					RevisionID:   "control-mapping-revision-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Relationship: compliance.MappingOverlap, Granularity: "control", Method: "manual_review",
					Rationale: "The requirements overlap but retain distinct operating tests.", CoverageBasisPoints: 5000,
					Source:        testComplianceRevisionRef("source-one", "source-revision-one"),
					Target:        testComplianceRevisionRef("target-one", "target-revision-one"),
					DecisionState: compliance.MappingApproved, AuthorID: "actor-one", ReviewerID: "reviewer-one",
				}},
			},
		},
	}
}

func readComplianceProgramSnapshot(t *testing.T, ctx context.Context, store *Store, tenantID string, programID string) testComplianceSnapshot {
	t.Helper()
	program, err := store.GetComplianceProgram(ctx, tenantID, programID)
	if err != nil {
		t.Fatalf("GetComplianceProgram() error = %v", err)
	}
	scope, err := store.GetProgramScopeRevision(ctx, tenantID, programID, program.CurrentScopeRevisionID)
	if err != nil {
		t.Fatalf("GetProgramScopeRevision() error = %v", err)
	}
	implementationID := "implementation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	implementation, err := store.GetControlImplementation(ctx, tenantID, programID, implementationID)
	if err != nil {
		t.Fatalf("GetControlImplementation() error = %v", err)
	}
	revision, err := store.GetControlImplementationRevision(ctx, tenantID, programID, implementationID, implementation.CurrentRevisionID)
	if err != nil {
		t.Fatalf("GetControlImplementationRevision() error = %v", err)
	}
	return testComplianceSnapshot{
		Version: program.AggregateVersion, Program: *program, Scope: *scope,
		Implementation: grcprogram.ControlImplementationRecordedPayload{Implementation: *implementation, Revision: *revision},
	}
}

func cleanupComplianceProgramTenant(t *testing.T, ctx context.Context, store *Store, tenantID string) {
	t.Helper()
	for _, statement := range []string{
		`DELETE FROM grc_compliance_event_application_receipts WHERE tenant_id = $1`,
		`DELETE FROM grc_control_mapping_revisions WHERE tenant_id = $1`,
		`DELETE FROM grc_control_implementation_revisions WHERE tenant_id = $1`,
		`DELETE FROM grc_control_implementations WHERE tenant_id = $1`,
		`DELETE FROM grc_program_scope_subjects WHERE tenant_id = $1`,
		`DELETE FROM grc_program_scope_selectors WHERE tenant_id = $1`,
		`DELETE FROM grc_program_scope_revisions WHERE tenant_id = $1`,
		`DELETE FROM grc_programs WHERE tenant_id = $1`,
	} {
		if _, err := store.db.ExecContext(ctx, statement, tenantID); err != nil {
			t.Fatalf("clean compliance program tenant: %v", err)
		}
	}
}

func testProgramID() string {
	return "program-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func testComplianceDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func testComplianceTime() time.Time {
	return time.Date(2026, time.July, 11, 22, 0, 0, 0, time.UTC)
}

func testComplianceRevisionRef(id string, revisionID string) compliance.RevisionRef {
	return compliance.RevisionRef{
		ID: id, RevisionID: revisionID, Version: 1,
		ContentDigest: compliance.ContentDigest(testComplianceDigest("5")), LastModified: testComplianceTime(),
	}
}
