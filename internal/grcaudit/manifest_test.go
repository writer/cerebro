package grcaudit

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestBuildPackageManifestIsDeterministicAcrossEntryOrder(t *testing.T) {
	entries := testManifestEntries()
	first, err := BuildPackageManifest(testManifestRequest(entries))
	if err != nil {
		t.Fatalf("BuildPackageManifest(first) error = %v", err)
	}
	entries[0], entries[1] = entries[1], entries[0]
	second, err := BuildPackageManifest(testManifestRequest(entries))
	if err != nil {
		t.Fatalf("BuildPackageManifest(second) error = %v", err)
	}
	if first.SemanticDigest != second.SemanticDigest || !reflect.DeepEqual(first.Entries, second.Entries) {
		t.Fatalf("deterministic manifests differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	firstBytes, err := CanonicalPackageManifestBytes(first)
	if err != nil {
		t.Fatalf("CanonicalPackageManifestBytes(first) error = %v", err)
	}
	secondBytes, err := CanonicalPackageManifestBytes(second)
	if err != nil {
		t.Fatalf("CanonicalPackageManifestBytes(second) error = %v", err)
	}
	if !reflect.DeepEqual(firstBytes, secondBytes) {
		t.Fatalf("canonical manifest bytes differ:\n%s\n%s", firstBytes, secondBytes)
	}
}

func TestCanonicalPackageManifestBytesNormalizeEquivalentEntryOrder(t *testing.T) {
	manifest, err := BuildPackageManifest(testManifestRequest(testManifestEntries()))
	if err != nil {
		t.Fatalf("BuildPackageManifest() error = %v", err)
	}
	want, err := CanonicalPackageManifestBytes(manifest)
	if err != nil {
		t.Fatalf("CanonicalPackageManifestBytes(canonical) error = %v", err)
	}
	equivalent := manifest
	equivalent.Entries = append([]PackageManifestEntry(nil), manifest.Entries...)
	equivalent.Entries[0], equivalent.Entries[1] = equivalent.Entries[1], equivalent.Entries[0]
	if err := VerifyPackageManifest(equivalent); err != nil {
		t.Fatalf("VerifyPackageManifest(equivalent) error = %v", err)
	}
	got, err := CanonicalPackageManifestBytes(equivalent)
	if err != nil {
		t.Fatalf("CanonicalPackageManifestBytes(equivalent) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical bytes depend on equivalent entry order:\n%s\n%s", got, want)
	}
}

func TestPackageManifestDetectsAlteredEntry(t *testing.T) {
	manifest, err := BuildPackageManifest(testManifestRequest(testManifestEntries()))
	if err != nil {
		t.Fatalf("BuildPackageManifest() error = %v", err)
	}
	altered := manifest
	altered.Entries = append([]PackageManifestEntry(nil), manifest.Entries...)
	altered.Entries[0].ContentDigest = DigestBytes([]byte("altered content"))
	if err := VerifyPackageManifest(altered); !errors.Is(err, ErrManifestDigestMismatch) {
		t.Fatalf("VerifyPackageManifest(altered) error = %v, want ErrManifestDigestMismatch", err)
	}
	rebuilt, err := BuildPackageManifest(PackageManifestRequest{
		PackageID:        altered.PackageID,
		TenantID:         altered.TenantID,
		EngagementID:     altered.EngagementID,
		Revision:         altered.Revision,
		AssessmentRunID:  altered.AssessmentRunID,
		ReviewRevisionID: altered.ReviewRevisionID,
		RedactionMode:    altered.RedactionMode,
		Entries:          altered.Entries,
	})
	if err != nil {
		t.Fatalf("BuildPackageManifest(altered) error = %v", err)
	}
	if rebuilt.SemanticDigest == manifest.SemanticDigest {
		t.Fatal("altered entry did not change semantic digest")
	}
}

func TestPackageFinalizerReturnsTypedCapabilityErrors(t *testing.T) {
	manifest, err := BuildPackageManifest(testManifestRequest(testManifestEntries()))
	if err != nil {
		t.Fatalf("BuildPackageManifest() error = %v", err)
	}
	_, err = (PackageFinalizer{}).Finalize(context.Background(), manifest)
	if !errors.Is(err, ErrArtifactCapabilityUnavailable) || !errors.Is(err, ErrSigningCapabilityUnavailable) {
		t.Fatalf("Finalize() error = %v, want both capability errors", err)
	}
	writer := &recordingArtifactWriter{}
	finalizer := PackageFinalizer{Artifacts: writer, Signer: staticManifestSigner{}}
	receipt, err := finalizer.Finalize(context.Background(), manifest)
	if err != nil {
		t.Fatalf("Finalize(configured) error = %v", err)
	}
	if receipt.ManifestDigest != manifest.SemanticDigest || writer.artifact.ContentDigest != DigestBytes(writer.artifact.Content) {
		t.Fatalf("finalization receipt/artifact = %+v / %+v", receipt, writer.artifact)
	}
}

func TestPackageFinalizerRejectsInvalidArtifactReceipt(t *testing.T) {
	manifest, err := BuildPackageManifest(testManifestRequest(testManifestEntries()))
	if err != nil {
		t.Fatalf("BuildPackageManifest() error = %v", err)
	}
	finalizer := PackageFinalizer{Artifacts: invalidReceiptWriter{}, Signer: staticManifestSigner{}}
	if _, err := finalizer.Finalize(context.Background(), manifest); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Finalize() error = %v, want ErrInvalidRequest", err)
	}
}

func TestPackageManifestRequiresBoundedOmissionMetadata(t *testing.T) {
	entries := testManifestEntries()
	entries[0].Redaction.Action = RedactionActionOmitted
	entries[0].Redaction.ReasonCode = ""
	if _, err := BuildPackageManifest(testManifestRequest(entries)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("BuildPackageManifest(omitted content) error = %v, want ErrInvalidRequest", err)
	}
	entries[0].ContentDigest = ""
	entries[0].SizeBytes = 0
	entries[0].Redaction.ReasonCode = "not_disclosed"
	if _, err := BuildPackageManifest(testManifestRequest(entries)); err != nil {
		t.Fatalf("BuildPackageManifest(valid omission) error = %v", err)
	}
}

func TestAuthorizePackageAccessUsesEngagementScope(t *testing.T) {
	engagement, _, err := NewEngagement(testCreateEngagementRequest())
	if err != nil {
		t.Fatalf("NewEngagement() error = %v", err)
	}
	manifest, err := BuildPackageManifest(testManifestRequest(testManifestEntries()))
	if err != nil {
		t.Fatalf("BuildPackageManifest() error = %v", err)
	}
	if err := AuthorizePackageAccess(Principal{TenantID: "tenant-a", ID: "auditor-a"}, engagement, manifest, EngagementPermissionRead); err != nil {
		t.Fatalf("assigned auditor package read error = %v", err)
	}
	if err := AuthorizePackageAccess(Principal{TenantID: "tenant-a", ID: "auditor-b"}, engagement, manifest, EngagementPermissionRead); !errors.Is(err, ErrPackageNotFound) {
		t.Fatalf("same-tenant foreign package error = %v, want ErrPackageNotFound", err)
	}
}

type staticManifestSigner struct{}

func (staticManifestSigner) SignPackageManifest(_ context.Context, _ []byte) (PackageSignature, error) {
	return PackageSignature{
		Algorithm: "test-signature-v1",
		KeyRef:    "test-key",
		Value:     "signature-value",
		SignedAt:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

type recordingArtifactWriter struct {
	artifact PackageArtifact
}

type invalidReceiptWriter struct{}

func (invalidReceiptWriter) WritePackageManifest(_ context.Context, _ PackageArtifact) (PackageArtifactReceipt, error) {
	return PackageArtifactReceipt{URI: "artifact://package-a/1", Digest: DigestBytes([]byte("wrong")), SizeBytes: 1}, nil
}

func (w *recordingArtifactWriter) WritePackageManifest(_ context.Context, artifact PackageArtifact) (PackageArtifactReceipt, error) {
	w.artifact = artifact
	return PackageArtifactReceipt{URI: "artifact://package-a/1", Digest: artifact.ContentDigest, SizeBytes: uint64(len(artifact.Content))}, nil
}

func testManifestRequest(entries []PackageManifestEntry) PackageManifestRequest {
	return PackageManifestRequest{
		PackageID:        "package-a",
		TenantID:         "tenant-a",
		EngagementID:     "engagement-a",
		Revision:         1,
		AssessmentRunID:  "assessment-run-a",
		ReviewRevisionID: "review-r1",
		RedactionMode:    "share_safe",
		Entries:          entries,
	}
}

func testManifestEntries() []PackageManifestEntry {
	return []PackageManifestEntry{
		{
			Path:          "evidence/evidence-a.json",
			LogicalType:   "evidence_claim",
			SchemaVersion: "evidence-claim/v1",
			StableID:      "evidence-a",
			RevisionID:    "evidence-a-r1",
			MediaType:     "application/json",
			ContentDigest: DigestBytes([]byte("evidence-a")),
			SourceDigest:  DigestBytes([]byte("source-evidence-a")),
			SizeBytes:     10,
			Redaction: RedactionDecision{
				Action:           RedactionActionRedacted,
				ReasonCode:       "sensitive_fields_removed",
				PolicyRevisionID: "disclosure-r1",
			},
			ProvenanceRefs: []string{"event-b", "event-a"},
		},
		{
			Path:          "results/objective-a.json",
			LogicalType:   "assessment_objective_result",
			SchemaVersion: "objective-result/v1",
			StableID:      "objective-a",
			RevisionID:    "result-r1",
			MediaType:     "application/json",
			ContentDigest: DigestBytes([]byte("result-a")),
			SizeBytes:     8,
			Redaction: RedactionDecision{
				Action:           RedactionActionIncluded,
				PolicyRevisionID: "disclosure-r1",
			},
		},
	}
}
