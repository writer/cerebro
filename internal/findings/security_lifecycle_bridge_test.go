package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestSecurityLifecycleFindingBridgeRequiresRealRuntimeAndVerifiedClosure(t *testing.T) {
	t.Parallel()

	const (
		tenantID   = "tenant-a"
		runtimeID  = "runtime-lifecycle-source"
		findingURN = "urn:cerebro:tenant-a:finding:lifecycle-expiry-1"
		subjectURN = "urn:cerebro:tenant-a:credential:deploy-signing"
	)
	openedAt := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{},
		evidence: map[string]*cerebrov1.FindingEvidence{},
	}
	appendLog := &recordingAppendLog{}
	service := New(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, TenantId: tenantID, SourceId: "lifecycle-source"},
		}},
		nil,
		store,
		store,
		store,
		store,
	).WithAppendLog(appendLog)

	withoutRuntime := lifecycleOpenObservation(tenantID, "", findingURN, subjectURN, openedAt)
	if _, err := service.RecordSecurityLifecycleFinding(context.Background(), withoutRuntime); err == nil || !strings.Contains(err.Error(), "source runtime id is required") {
		t.Fatalf("RecordSecurityLifecycleFinding() without runtime error = %v, want source runtime requirement", err)
	}

	open := lifecycleOpenObservation(tenantID, runtimeID, findingURN, subjectURN, openedAt)
	stored, err := service.RecordSecurityLifecycleFinding(context.Background(), open)
	if err != nil {
		t.Fatalf("RecordSecurityLifecycleFinding(open) error = %v", err)
	}
	if stored.ID != findingURN {
		t.Fatalf("finding id = %q, want exact resolver urn %q", stored.ID, findingURN)
	}
	if stored.RuntimeID != runtimeID {
		t.Fatalf("runtime id = %q, want resolver provenance %q", stored.RuntimeID, runtimeID)
	}
	openFingerprint := stored.Fingerprint

	// A provider execution receipt is supporting evidence only. The resolver
	// still reports the same policy match, so the durable finding remains open.
	afterProviderSuccess := open
	afterProviderSuccess.MaterialRevision = "material-revision-2"
	afterProviderSuccess.ObservedAt = openedAt.Add(5 * time.Minute)
	afterProviderSuccess.EvidenceClaimRefs = append(afterProviderSuccess.EvidenceClaimRefs, "urn:cerebro:tenant-a:evidence:provider-execution-success")
	stored, err = service.RecordSecurityLifecycleFinding(context.Background(), afterProviderSuccess)
	if err != nil {
		t.Fatalf("RecordSecurityLifecycleFinding(provider success) error = %v", err)
	}
	if stored.Status != findingStatusOpen {
		t.Fatalf("status after provider success = %q, want open", stored.Status)
	}
	if stored.Fingerprint != openFingerprint {
		t.Fatalf("fingerprint after material rotation = %q, want stable %q", stored.Fingerprint, openFingerprint)
	}

	incomplete := SecurityLifecycleClosureObservation{
		FindingURN:                      findingURN,
		SourceRuntimeID:                 runtimeID,
		SourceCollectionID:              "collection-incomplete",
		SubjectURN:                      subjectURN,
		AuthorityID:                     open.AuthorityID,
		StableLocator:                   open.StableLocator,
		PolicyState:                     "compliant",
		ObservedAt:                      openedAt.Add(10 * time.Minute),
		FreshnessAsOf:                   openedAt.Add(11 * time.Minute),
		CoverageComplete:                true,
		CoverageTruncated:               false,
		CollectionReceiptTenantID:       tenantID,
		CollectionReceiptRuntimeID:      runtimeID,
		CollectionReceiptID:             "collection-incomplete",
		CollectionReceiptStatus:         "incomplete",
		CollectionReceiptCompletedAt:    openedAt.Add(11 * time.Minute),
		CollectionIncompletenessReasons: []string{"page_limit_reached"},
	}
	if _, err := service.ResolveSecurityLifecycleFindingAfterObservation(context.Background(), incomplete); err == nil {
		t.Fatal("ResolveSecurityLifecycleFindingAfterObservation(incomplete receipt) succeeded, want refusal")
	}
	if got := store.findings[findingURN].Status; got != findingStatusOpen {
		t.Fatalf("status after incomplete observation = %q, want open", got)
	}

	verifiedAt := openedAt.Add(15 * time.Minute)
	staleFreshness := SecurityLifecycleClosureObservation{
		FindingURN:                   findingURN,
		SourceRuntimeID:              runtimeID,
		SourceCollectionID:           "collection-stale-freshness",
		SubjectURN:                   subjectURN,
		AuthorityID:                  open.AuthorityID,
		StableLocator:                open.StableLocator,
		PolicyState:                  "compliant",
		ObservedAt:                   verifiedAt,
		FreshnessAsOf:                verifiedAt.Add(-time.Second),
		CoverageComplete:             true,
		CollectionReceiptTenantID:    tenantID,
		CollectionReceiptRuntimeID:   runtimeID,
		CollectionReceiptID:          "collection-stale-freshness",
		CollectionReceiptStatus:      "complete",
		CollectionReceiptCompletedAt: verifiedAt.Add(time.Minute),
	}
	if _, err := service.ResolveSecurityLifecycleFindingAfterObservation(context.Background(), staleFreshness); err == nil {
		t.Fatal("ResolveSecurityLifecycleFindingAfterObservation(stale freshness) succeeded, want refusal")
	}

	resolved, err := service.ResolveSecurityLifecycleFindingAfterObservation(context.Background(), SecurityLifecycleClosureObservation{
		FindingURN:                   findingURN,
		SourceRuntimeID:              runtimeID,
		SourceCollectionID:           "collection-verified",
		SubjectURN:                   subjectURN,
		AuthorityID:                  open.AuthorityID,
		StableLocator:                open.StableLocator,
		PolicyState:                  "compliant",
		ObservedAt:                   verifiedAt,
		FreshnessAsOf:                verifiedAt.Add(time.Minute),
		CoverageComplete:             true,
		CollectionReceiptTenantID:    tenantID,
		CollectionReceiptRuntimeID:   runtimeID,
		CollectionReceiptID:          "collection-verified",
		CollectionReceiptStatus:      "complete",
		CollectionReceiptCompletedAt: verifiedAt.Add(time.Minute),
		EvidenceClaimRefs:            []string{"urn:cerebro:tenant-a:evidence:independent-observation"},
	})
	if err != nil {
		t.Fatalf("ResolveSecurityLifecycleFindingAfterObservation(verified) error = %v", err)
	}
	if resolved.Status != findingStatusResolved {
		t.Fatalf("verified status = %q, want resolved", resolved.Status)
	}
	if !resolved.StatusUpdatedAt.Equal(verifiedAt) {
		t.Fatalf("status updated at = %s, want observation time %s", resolved.StatusUpdatedAt, verifiedAt)
	}

	evidence, err := service.ListEvidence(context.Background(), ListEvidenceRequest{
		RuntimeID: runtimeID,
		FindingID: findingURN,
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("ListEvidence(exact finding) error = %v", err)
	}
	if got := len(evidence.Evidence); got != 3 {
		t.Fatalf("exact finding evidence rows = %d, want open, provider, and verification observations", got)
	}
	if got := len(appendLog.events); got != 3 {
		t.Fatalf("workflow events = %d, want two recorded and one verified status event", got)
	}
}

func lifecycleOpenObservation(tenantID, runtimeID, findingURN, subjectURN string, observedAt time.Time) SecurityLifecycleFindingObservation {
	return SecurityLifecycleFindingObservation{
		TenantID:           tenantID,
		FindingURN:         findingURN,
		SourceRuntimeID:    runtimeID,
		SourceCollectionID: "collection-open",
		SubjectURN:         subjectURN,
		SubjectKind:        "credential",
		AuthorityID:        "authority-prod",
		StableLocator:      "deploy/signing",
		MaterialRevision:   "material-revision-1",
		Provider:           "provider-a",
		DisplayName:        "Deploy signing credential",
		ObservedState:      "active",
		PolicyState:        "expiring",
		PolicyID:           "credential-expiry-30d",
		PolicyVersion:      "v1",
		ObservedAt:         observedAt,
		ExpiresAt:          observedAt.Add(7 * 24 * time.Hour),
		GraphRevision:      42,
		EvidenceClaimRefs:  []string{"urn:cerebro:tenant-a:evidence:lifecycle-observation"},
	}
}
