package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/grcaudit"
	"github.com/writer/cerebro/internal/workflowevents"
)

func TestAuditStateSchemaCoversTenantScopedAuditObjects(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureAuditStateStatements, "\n")
	for _, fragment := range []string{
		"grc_audit_engagements", "PRIMARY KEY (tenant_id, engagement_id)",
		"grc_audit_engagement_revisions", "UNIQUE (tenant_id, engagement_id, revision)",
		"grc_audit_participants", "grc_audit_evidence_requests",
		"grc_audit_evidence_request_revisions", "grc_audit_evidence_submissions",
		"grc_audit_sample_revisions", "grc_audit_package_manifests",
		"grc_audit_package_manifest_entries", "grc_audit_capability_state",
		"grc_audit_access_grants", "grc_audit_event_application_receipts",
		"PRIMARY KEY (tenant_id, event_id)",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("audit state schema missing %q", fragment)
		}
	}
}

func TestAuditStateSchemaIncludesReceiptUpgradeAndAccessIndexes(t *testing.T) {
	t.Parallel()
	joined := strings.Join(ensureAuditStateStatements, "\n")
	for _, fragment := range []string{
		"ALTER TABLE grc_audit_event_application_receipts ADD COLUMN IF NOT EXISTS event_digest",
		"grc_audit_participants_principal_idx", "grc_audit_access_grants_principal_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("audit state schema upgrade missing %q", fragment)
		}
	}
}

func TestAuditReceiptDecisionIsIdempotentAndRejectsConflict(t *testing.T) {
	t.Parallel()
	if apply, err := auditReceiptDecision("", false, "digest-a"); err != nil || !apply {
		t.Fatalf("new receipt decision = (%v, %v), want apply", apply, err)
	}
	if apply, err := auditReceiptDecision("digest-a", true, "digest-a"); err != nil || apply {
		t.Fatalf("duplicate receipt decision = (%v, %v), want no-op", apply, err)
	}
	if apply, err := auditReceiptDecision("digest-a", true, "digest-b"); !errors.Is(err, grcaudit.ErrProjectionConflict) || apply {
		t.Fatalf("conflicting receipt decision = (%v, %v), want conflict", apply, err)
	}
}

func TestAuditProjectionVersionOrdering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		exists   bool
		current  uint64
		incoming uint64
		want     error
	}{
		{name: "first", incoming: 1},
		{name: "next", exists: true, current: 1, incoming: 2},
		{name: "initial gap", incoming: 2, want: grcaudit.ErrProjectionGap},
		{name: "later gap", exists: true, current: 2, incoming: 4, want: grcaudit.ErrProjectionGap},
		{name: "duplicate without receipt", exists: true, current: 2, incoming: 2, want: grcaudit.ErrVersionConflict},
		{name: "stale", exists: true, current: 3, incoming: 2, want: grcaudit.ErrVersionConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateAuditAdvance(test.exists, test.current, test.incoming); !errors.Is(err, test.want) {
				t.Fatalf("validateAuditAdvance() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuditSubmissionProjectionRequiresExistingReferencedRequestVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		exists         bool
		current        uint64
		incoming       uint64
		requestVersion uint64
		want           error
	}{
		{name: "next request version", exists: true, current: 3, incoming: 4, requestVersion: 3},
		{name: "missing request", incoming: 1, want: grcaudit.ErrProjectionGap},
		{name: "wrong referenced version", exists: true, current: 3, incoming: 4, requestVersion: 2, want: grcaudit.ErrVersionConflict},
		{name: "aggregate gap", exists: true, current: 3, incoming: 5, requestVersion: 3, want: grcaudit.ErrProjectionGap},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuditSubmissionAdvance(test.exists, test.current, test.incoming, test.requestVersion)
			if !errors.Is(err, test.want) {
				t.Fatalf("validateAuditSubmissionAdvance() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDecodeAuditPackageManifestRejectsDigestMismatch(t *testing.T) {
	t.Parallel()
	manifest := testAuditManifest(t, "tenant-manifest", "engagement-one")
	manifest.Entries[0].RevisionID = "altered-revision"
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal altered manifest: %v", err)
	}
	if _, err := decodeAuditPackageManifest(string(payload)); !errors.Is(err, grcaudit.ErrManifestDigestMismatch) {
		t.Fatalf("decodeAuditPackageManifest() error = %v, want ErrManifestDigestMismatch", err)
	}
}

func TestAuditProjectionReplayReconstructsDeterministically(t *testing.T) {
	t.Parallel()
	events := testAuditEvents(t, "tenant-replay")
	first := newAuditReplayState()
	for _, event := range events {
		if err := first.apply(event); err != nil {
			t.Fatalf("first replay apply: %v", err)
		}
	}
	second := newAuditReplayState()
	for _, event := range events {
		if err := second.apply(event); err != nil {
			t.Fatalf("second replay apply: %v", err)
		}
		if err := second.apply(event); err != nil {
			t.Fatalf("duplicate replay apply: %v", err)
		}
	}
	if !reflect.DeepEqual(first.snapshot(), second.snapshot()) {
		t.Fatalf("audit replay snapshots differ:\nfirst = %#v\nsecond = %#v", first.snapshot(), second.snapshot())
	}
}

func TestAuditProjectionConflictingDuplicateIsRejected(t *testing.T) {
	t.Parallel()
	event := testAuditEvents(t, "tenant-conflict")[0]
	firstApplication, err := decodeAuditProjectionEvent(event)
	if err != nil {
		t.Fatalf("validate first event: %v", err)
	}
	payload := testAuditEngagementPayload(t, "tenant-conflict")
	payload.Engagement.Status = grcaudit.EngagementStatusFieldwork
	conflict := testAuditEvent(t, grcaudit.AuditAggregateEngagement, payload.Engagement.ID, payload.Engagement.Version, payload)
	secondApplication, err := decodeAuditProjectionEvent(conflict)
	if err != nil {
		t.Fatalf("validate conflicting event: %v", err)
	}
	if event.GetId() != conflict.GetId() {
		t.Fatal("conflicting duplicate did not preserve the canonical deterministic event id")
	}
	if firstApplication.eventDigest == secondApplication.eventDigest {
		t.Fatal("conflicting duplicate produced the same event digest")
	}
	if _, err := auditReceiptDecision(firstApplication.eventDigest, true, secondApplication.eventDigest); !errors.Is(err, grcaudit.ErrProjectionConflict) {
		t.Fatalf("conflicting duplicate decision error = %v", err)
	}
}

func TestAuditAccessBoundaryReturnsOpaqueNotFound(t *testing.T) {
	t.Parallel()
	payload := testAuditEngagementPayload(t, "tenant-access")
	engagement := payload.Engagement
	foreignTenant := grcaudit.AuthorizeEngagementAccess(grcaudit.Principal{TenantID: "tenant-other", ID: "owner-one"}, engagement, grcaudit.EngagementPermissionRead)
	foreignPrincipal := grcaudit.AuthorizeEngagementAccess(grcaudit.Principal{TenantID: engagement.TenantID, ID: "principal-other"}, engagement, grcaudit.EngagementPermissionRead)
	if !errors.Is(foreignTenant, grcaudit.ErrEngagementNotFound) || !errors.Is(foreignPrincipal, grcaudit.ErrEngagementNotFound) {
		t.Fatalf("access errors = (%v, %v), want identical opaque not found", foreignTenant, foreignPrincipal)
	}
	manifest := testAuditManifest(t, engagement.TenantID, engagement.ID)
	if err := grcaudit.AuthorizePackageAccess(grcaudit.Principal{TenantID: engagement.TenantID, ID: "principal-other"}, engagement, manifest, grcaudit.EngagementPermissionRead); !errors.Is(err, grcaudit.ErrPackageNotFound) {
		t.Fatalf("foreign package access error = %v, want opaque package not found", err)
	}
}

func TestAuditProjectionAdvisoryLockSerializesReceiptCheck(t *testing.T) {
	t.Parallel()
	query := auditProjectionAdvisoryLockSQL()
	for _, fragment := range []string{"pg_advisory_xact_lock", "grc_audit_projection_event", "hashtext($1)"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("audit projection lock missing %q", fragment)
		}
	}
}

func TestAuditStatePostgresAccessAndReplay(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run audit state integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	ctx := context.Background()
	if err := store.ensureAuditStateTables(ctx); err != nil {
		t.Fatalf("ensure audit state tables: %v", err)
	}
	tenantID := fmt.Sprintf("audit-state-%d", time.Now().UnixNano())
	cleanupAuditTenant(t, ctx, store, tenantID)
	t.Cleanup(func() {
		cleanupAuditTenant(t, context.Background(), store, tenantID)
		_ = store.Close()
	})
	events := testAuditEvents(t, tenantID)
	for _, event := range events {
		applied, applyErr := store.ApplyAuditProjectionEvent(ctx, event)
		if applyErr != nil || !applied {
			t.Fatalf("ApplyAuditProjectionEvent() = (%v, %v), want applied", applied, applyErr)
		}
	}
	if applied, applyErr := store.ApplyAuditProjectionEvent(ctx, events[0]); applyErr != nil || applied {
		t.Fatalf("duplicate ApplyAuditProjectionEvent() = (%v, %v), want no-op", applied, applyErr)
	}
	principal := grcaudit.Principal{TenantID: tenantID, ID: "owner-one"}
	if _, err := store.GetAuditEngagement(ctx, principal, "engagement-one", grcaudit.EngagementPermissionRead); err != nil {
		t.Fatalf("GetAuditEngagement() error = %v", err)
	}
	foreign := grcaudit.Principal{TenantID: tenantID + "-foreign", ID: "owner-one"}
	if _, err := store.GetAuditEngagement(ctx, foreign, "engagement-one", grcaudit.EngagementPermissionRead); !errors.Is(err, grcaudit.ErrEngagementNotFound) {
		t.Fatalf("foreign engagement error = %v, want opaque not found", err)
	}
}

type auditReplayState struct {
	receipts map[string]string
	versions map[string]uint64
	payloads map[string]string
}

func newAuditReplayState() *auditReplayState {
	return &auditReplayState{receipts: map[string]string{}, versions: map[string]uint64{}, payloads: map[string]string{}}
}

func (state *auditReplayState) apply(envelope *cerebrov1.EventEnvelope) error {
	event, err := decodeAuditProjectionEvent(envelope)
	if err != nil {
		return err
	}
	existing, exists := state.receipts[event.eventID]
	apply, err := auditReceiptDecision(existing, exists, event.eventDigest)
	if err != nil || !apply {
		return err
	}
	key := event.aggregateType + "\x00" + event.aggregateID
	if event.aggregateType == grcaudit.AuditAggregateSubmission {
		key = grcaudit.AuditAggregateRequest + "\x00" + event.aggregateID
	}
	current, aggregateExists := state.versions[key]
	if err := validateAuditAdvance(aggregateExists, current, event.aggregateVersion); err != nil {
		return err
	}
	state.receipts[event.eventID] = event.eventDigest
	state.versions[key] = event.aggregateVersion
	state.payloads[key] = event.payloadJSON
	return nil
}

func (state *auditReplayState) snapshot() []string {
	keys := make([]string, 0, len(state.payloads))
	for key := range state.payloads {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, fmt.Sprintf("%s|%d|%s", key, state.versions[key], state.payloads[key]))
	}
	return result
}

func testAuditEvents(t *testing.T, tenantID string) []*cerebrov1.EventEnvelope {
	t.Helper()
	engagement := testAuditEngagementPayload(t, tenantID)
	request, requestRevision, err := grcaudit.NewEvidenceRequest(grcaudit.CreateEvidenceRequestRequest{
		ID: "request-one", TenantID: tenantID, EngagementID: engagement.Engagement.ID,
		Revision: grcaudit.EvidenceRequestRevisionInput{
			ObjectiveID: "objective-one", SubjectIDs: []string{"subject-one"},
			PeriodStart: testAuditTime(), PeriodEnd: testAuditTime().Add(24 * time.Hour),
			RequesterPrincipalID: "auditor-one", OwnerPrincipalID: "owner-one",
			DueAt: testAuditTime().Add(48 * time.Hour), ExpectedFormats: []string{"application/json"},
			Status: grcaudit.EvidenceRequestStatusOpen,
		}, CreatedBy: "auditor-one", CreatedAt: testAuditTime().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("NewEvidenceRequest() error = %v", err)
	}
	updatedRequest, submission, err := grcaudit.RecordEvidenceSubmission(request, 1,
		grcaudit.EvidenceSubmissionInput{ClaimIDs: []string{"claim-one"}}, "owner-one", testAuditTime().Add(2*time.Minute))
	if err != nil {
		t.Fatalf("RecordEvidenceSubmission() error = %v", err)
	}
	sample, err := grcaudit.RefineSample(grcaudit.SampleRefinementRequest{
		TenantID: tenantID, EngagementID: engagement.Engagement.ID, EvidenceRequestID: request.ID,
		Population: grcaudit.PopulationSnapshot{ID: "population-one", SubjectIDs: []string{"subject-one", "subject-two"}},
		Seed:       "seed-one", Size: 1, CreatedBy: "auditor-one", CreatedAt: testAuditTime().Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RefineSample() error = %v", err)
	}
	manifest := testAuditManifest(t, tenantID, engagement.Engagement.ID)
	capability := grcaudit.CapabilityState{ID: "manifest-signing", TenantID: tenantID, Kind: "manifest_signer", Enabled: true, Version: 1, UpdatedBy: "owner-one", UpdatedAt: testAuditTime()}
	grant := grcaudit.AccessGrant{
		ID: "grant-one", TenantID: tenantID, EngagementID: engagement.Engagement.ID,
		PrincipalID: "auditor-one", Permission: grcaudit.EngagementPermissionReview,
		Status: grcaudit.ParticipantStatusActive, Version: 1, GrantedBy: "owner-one",
		EffectiveFrom: testAuditTime(), UpdatedAt: testAuditTime(),
	}
	return []*cerebrov1.EventEnvelope{
		testAuditEvent(t, grcaudit.AuditAggregateEngagement, engagement.Engagement.ID, 1, engagement),
		testAuditEvent(t, grcaudit.AuditAggregateRequest, request.ID, 1, grcaudit.EvidenceRequestRecordedPayload{Request: request, Revision: requestRevision}),
		testAuditEvent(t, grcaudit.AuditAggregateSubmission, request.ID, 2, grcaudit.EvidenceSubmissionRecordedPayload{Request: updatedRequest, Submission: submission}),
		testAuditEvent(t, grcaudit.AuditAggregateSample, sample.ID, 1, sample),
		testAuditEvent(t, grcaudit.AuditAggregatePackage, manifest.PackageID, 1, manifest),
		testAuditEvent(t, grcaudit.AuditAggregateCapability, capability.ID, 1, capability),
		testAuditEvent(t, grcaudit.AuditAggregateGrant, grant.ID, 1, grant),
	}
}

func testAuditEngagementPayload(t *testing.T, tenantID string) grcaudit.EngagementRecordedPayload {
	t.Helper()
	engagement, revision, err := grcaudit.NewEngagement(grcaudit.CreateEngagementRequest{
		ID: "engagement-one", TenantID: tenantID,
		Revision: grcaudit.EngagementRevisionInput{
			ProgramID: "program-one", ProgramScopeRevision: "scope-revision-one",
			PeriodStart: testAuditTime(), PeriodEnd: testAuditTime().Add(24 * time.Hour),
			Deadline: testAuditTime().Add(72 * time.Hour), DisclosurePolicyID: "policy-one",
			Status: grcaudit.EngagementStatusPlanning,
		},
		Participants: []grcaudit.ParticipantInput{{PrincipalID: "owner-one", Role: grcaudit.ParticipantRoleClientOwner}},
		CreatedBy:    "owner-one", CreatedAt: testAuditTime(),
	})
	if err != nil {
		t.Fatalf("NewEngagement() error = %v", err)
	}
	return grcaudit.EngagementRecordedPayload{Engagement: engagement, Revision: revision}
}

func testAuditManifest(t *testing.T, tenantID string, engagementID string) grcaudit.PackageManifest {
	t.Helper()
	manifest, err := grcaudit.BuildPackageManifest(grcaudit.PackageManifestRequest{
		PackageID: "package-one", TenantID: tenantID, EngagementID: engagementID, Revision: 1,
		AssessmentRunID: "run-one", ReviewRevisionID: "review-one", RedactionMode: "auditor",
		Entries: []grcaudit.PackageManifestEntry{{
			Path: "evidence/control.json", LogicalType: "evidence", SchemaVersion: "v1",
			StableID: "evidence-one", RevisionID: "evidence-revision-one", MediaType: "application/json",
			ContentDigest: grcaudit.DigestBytes([]byte("evidence")), SizeBytes: 8,
			Redaction: grcaudit.RedactionDecision{Mode: "auditor", Action: grcaudit.RedactionActionIncluded, PolicyRevisionID: "policy-one"},
		}},
	})
	if err != nil {
		t.Fatalf("BuildPackageManifest() error = %v", err)
	}
	return manifest
}

func testAuditEvent(t *testing.T, aggregateType string, aggregateID string, version uint64, payload any) *cerebrov1.EventEnvelope {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal audit projection payload: %v", err)
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: auditTestEventKind(aggregateType), TenantID: auditPayloadTenant(payload),
		AggregateType: aggregateType, AggregateID: aggregateID,
		AggregateVersion: int64(version), // #nosec G115 -- test fixtures use small positive versions.
		Operation:        "recorded", ContentDigest: auditPayloadDigest(payload, encoded),
		PayloadJSON: string(encoded), ActorID: "actor-one", RecordedAt: testAuditTime().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewComplianceAggregateEvent() error = %v", err)
	}
	return event
}

func auditTestEventKind(aggregateType string) string {
	switch aggregateType {
	case grcaudit.AuditAggregateEngagement, grcaudit.AuditAggregateCapability, grcaudit.AuditAggregateGrant:
		return workflowevents.EventKindComplianceAuditEngagementRecorded
	case grcaudit.AuditAggregateRequest:
		return workflowevents.EventKindComplianceAuditRequestUpdated
	case grcaudit.AuditAggregateSubmission:
		return workflowevents.EventKindComplianceAuditSubmissionRecorded
	case grcaudit.AuditAggregateSample:
		return workflowevents.EventKindComplianceSampleRecorded
	case grcaudit.AuditAggregatePackage:
		return workflowevents.EventKindComplianceAuditPackageRecorded
	default:
		return ""
	}
}

func auditPayloadDigest(payload any, encoded []byte) string {
	switch value := payload.(type) {
	case grcaudit.EngagementRecordedPayload:
		return value.Revision.RevisionHash
	case grcaudit.EvidenceRequestRecordedPayload:
		return value.Revision.RevisionHash
	case grcaudit.EvidenceSubmissionRecordedPayload:
		return value.Submission.SubmissionHash
	case grcaudit.SampleRevision:
		return value.RevisionHash
	case grcaudit.PackageManifest:
		return value.SemanticDigest
	default:
		return grcaudit.DigestBytes(encoded)
	}
}

func auditPayloadTenant(payload any) string {
	switch value := payload.(type) {
	case grcaudit.EngagementRecordedPayload:
		return value.Engagement.TenantID
	case grcaudit.EvidenceRequestRecordedPayload:
		return value.Request.TenantID
	case grcaudit.EvidenceSubmissionRecordedPayload:
		return value.Request.TenantID
	case grcaudit.SampleRevision:
		return value.TenantID
	case grcaudit.PackageManifest:
		return value.TenantID
	case grcaudit.CapabilityState:
		return value.TenantID
	case grcaudit.AccessGrant:
		return value.TenantID
	default:
		return ""
	}
}

func cleanupAuditTenant(t *testing.T, ctx context.Context, store *Store, tenantID string) {
	t.Helper()
	for _, statement := range []string{
		`DELETE FROM grc_audit_event_application_receipts WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_access_grants WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_capability_state WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_package_manifest_entries WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_package_manifests WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_packages WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_sample_revisions WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_evidence_submissions WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_evidence_request_revisions WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_evidence_requests WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_participants WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_engagement_revisions WHERE tenant_id = $1`,
		`DELETE FROM grc_audit_engagements WHERE tenant_id = $1`,
	} {
		if _, err := store.db.ExecContext(ctx, statement, tenantID); err != nil {
			t.Fatalf("clean audit tenant: %v", err)
		}
	}
}

func testAuditTime() time.Time {
	return time.Date(2026, time.July, 12, 1, 0, 0, 0, time.UTC)
}
