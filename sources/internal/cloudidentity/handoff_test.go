package cloudidentitysource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func handoffTestEvidence(provider ci.Provider, id string) ci.Evidence {
	return ci.Evidence{Schema: ci.SchemaVersion, Principal: ci.Principal{ID: id, Provider: provider}, Scope: "writer"}
}

func handoffTestInput() evidenceHandoffInput {
	collectedAt := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)
	evidence := []ci.Evidence{
		handoffTestEvidence(ci.GCP, "b@writer-prod.iam.gserviceaccount.com"),
		handoffTestEvidence(ci.AWS, "arn:aws:iam::222222222222:role/b"),
		handoffTestEvidence(ci.AWS, "arn:aws:iam::222222222222:role/a"),
	}
	principalEvents := make([]json.RawMessage, len(evidence))
	for i, e := range evidence {
		raw, _ := json.Marshal(e)
		principalEvents[i] = raw
	}
	coverage, _ := json.Marshal(ci.CollectionCoverage{Schema: ci.SchemaVersion, Scope: "writer", CollectedAt: collectedAt, InventoryComplete: true, PrincipalCount: len(evidence)})
	return evidenceHandoffInput{
		Tenant: "writer", Stream: "security", Scope: "writer", CollectedAt: collectedAt,
		PlanDigest: "sha256:plan", RuntimeID: "runtime-1", Build: "1.2.3",
		Evidence: evidence, PrincipalEvents: principalEvents, CoveragePayload: coverage,
	}
}

func decompressBundle(t *testing.T, gzipped []byte) evidenceBundle {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer func() { _ = reader.Close() }()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read decompressed bundle: %v", err)
	}
	var bundle evidenceBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	return bundle
}

// fakeHandoffPublisher is an in-memory HandoffPublisher: it records every
// publish call and can be configured to fail deterministically.
type fakeHandoffPublisher struct {
	calls    []fakeHandoffCall
	failWith error
}

type fakeHandoffCall struct {
	Bucket, Region, Key string
	Body                []byte
}

func (f *fakeHandoffPublisher) Publish(_ context.Context, bucket, region, key string, body []byte) error {
	f.calls = append(f.calls, fakeHandoffCall{Bucket: bucket, Region: region, Key: key, Body: append([]byte(nil), body...)})
	return f.failWith
}

func TestBuildEvidenceBundleDeterministic(t *testing.T) {
	in := handoffTestInput()
	gzip1, sha1, err := buildEvidenceBundle(in)
	if err != nil {
		t.Fatalf("buildEvidenceBundle() error = %v", err)
	}
	gzip2, sha2, err := buildEvidenceBundle(in)
	if err != nil {
		t.Fatalf("buildEvidenceBundle() error = %v", err)
	}
	if sha1 != sha2 {
		t.Fatalf("sha256 not deterministic: %q != %q", sha1, sha2)
	}
	if !bytes.Equal(gzip1, gzip2) {
		t.Fatal("gzip bytes not deterministic for identical input")
	}
}

func TestBuildEvidenceBundleSortsPrincipalsByProviderThenID(t *testing.T) {
	in := handoffTestInput()
	gzipped, _, err := buildEvidenceBundle(in)
	if err != nil {
		t.Fatalf("buildEvidenceBundle() error = %v", err)
	}
	bundle := decompressBundle(t, gzipped)
	if bundle.PrincipalCount != 3 || len(bundle.Principals) != 3 {
		t.Fatalf("principal_count/principals = %d/%d, want 3/3", bundle.PrincipalCount, len(bundle.Principals))
	}
	var order []string
	for _, raw := range bundle.Principals {
		var evidence ci.Evidence
		if err := json.Unmarshal(raw, &evidence); err != nil {
			t.Fatalf("unmarshal sorted principal: %v", err)
		}
		order = append(order, string(evidence.Principal.Provider)+":"+evidence.Principal.ID)
	}
	want := []string{
		"aws:arn:aws:iam::222222222222:role/a",
		"aws:arn:aws:iam::222222222222:role/b",
		"gcp:b@writer-prod.iam.gserviceaccount.com",
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("principal order = %v, want %v", order, want)
		}
	}
}

func TestBuildEvidenceBundleSchemaAndFields(t *testing.T) {
	in := handoffTestInput()
	gzipped, sha256Hex, err := buildEvidenceBundle(in)
	if err != nil {
		t.Fatalf("buildEvidenceBundle() error = %v", err)
	}
	bundle := decompressBundle(t, gzipped)
	if bundle.Schema != evidenceBundleSchema {
		t.Fatalf("schema = %q, want %q", bundle.Schema, evidenceBundleSchema)
	}
	if bundle.Stream != "security" || bundle.CohortScope != "writer" {
		t.Fatalf("stream/cohort_scope = %q/%q, want security/writer", bundle.Stream, bundle.CohortScope)
	}
	if bundle.Producer.SourceID != ci.SourceID || bundle.Producer.RuntimeID != "runtime-1" || bundle.Producer.Build != "1.2.3" {
		t.Fatalf("producer = %+v", bundle.Producer)
	}
	if bundle.PlanDigest != "sha256:plan" {
		t.Fatalf("plan_digest = %q, want sha256:plan", bundle.PlanDigest)
	}
	if bundle.CollectionID == "" {
		t.Fatal("collection_id must be non-empty")
	}
	if len(sha256Hex) != 64 {
		t.Fatalf("sha256 hex length = %d, want 64", len(sha256Hex))
	}
}

func TestBuildEvidenceBundleKeyFormat(t *testing.T) {
	collectedAt := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)
	key := buildEvidenceBundleKey("security", "writer", collectedAt, "abc123")
	want := "cloud-identity/security/writer/20260401T090000Z-abc123.json.gz"
	if key != want {
		t.Fatalf("buildEvidenceBundleKey() = %q, want %q", key, want)
	}
	if !regexp.MustCompile(`^cloud-identity/[a-z0-9-]+/[^/]+/\d{8}T\d{6}Z-[0-9a-f]+\.json\.gz$`).MatchString(key) {
		t.Fatalf("key %q does not match the documented key pattern", key)
	}
}

func TestPublishEvidenceHandoffDisabledWhenNoBucket(t *testing.T) {
	publisher := &fakeHandoffPublisher{}
	outcome := publishEvidenceHandoff(context.Background(), publisher, Settings{TenantID: "writer"}, ci.Collection{Scope: "writer", CollectedAt: time.Now()}, nil, []byte(`{}`), "runtime-1")
	if outcome.Status != "disabled" {
		t.Fatalf("Status = %q, want disabled", outcome.Status)
	}
	if len(publisher.calls) != 0 {
		t.Fatal("publisher must never be called when evidence_handoff_bucket is unset")
	}
}

func TestPublishEvidenceHandoffPublishedOnSuccess(t *testing.T) {
	publisher := &fakeHandoffPublisher{}
	settings := Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: "intake-bucket", Stream: "security", Region: "us-east-1"}}
	collection := ci.Collection{Scope: "writer", CollectedAt: time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)}
	coverage, _ := json.Marshal(ci.CollectionCoverage{Schema: ci.SchemaVersion, Scope: "writer", CollectedAt: collection.CollectedAt})
	outcome := publishEvidenceHandoff(context.Background(), publisher, settings, collection, nil, coverage, "runtime-1")
	if outcome.Status != "published" {
		t.Fatalf("Status = %q, want published, outcome=%+v", outcome.Status, outcome)
	}
	if outcome.Bucket != "intake-bucket" || outcome.Stream != "security" || outcome.SHA256 == "" || outcome.SizeBytes == 0 {
		t.Fatalf("incomplete outcome: %+v", outcome)
	}
	if len(publisher.calls) != 1 {
		t.Fatalf("publisher calls = %d, want 1", len(publisher.calls))
	}
	call := publisher.calls[0]
	if call.Bucket != "intake-bucket" || call.Region != "us-east-1" || call.Key != outcome.Key {
		t.Fatalf("publisher call = %+v, outcome = %+v", call, outcome)
	}
}

// TestPublishEvidenceHandoffFailureClassifiedWithoutSecretText pins the
// "failure classification without secret-bearing text" contract
// requirement: the underlying publish error's own text (which could carry
// request IDs, presigned fragments, or credential material) must never
// reach the recorded ErrorCode.
func TestPublishEvidenceHandoffFailureClassifiedWithoutSecretText(t *testing.T) {
	sensitive := "AccessDenied: role arn:aws:iam::222222222222:role/secret, token AKIAABCDEFGHEXAMPLE leaked in request"
	publisher := &fakeHandoffPublisher{failWith: errors.New(sensitive)}
	settings := Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: "intake-bucket", Stream: "security"}}
	collection := ci.Collection{Scope: "writer", CollectedAt: time.Now()}
	outcome := publishEvidenceHandoff(context.Background(), publisher, settings, collection, nil, []byte(`{}`), "runtime-1")
	if outcome.Status != "failed" {
		t.Fatalf("Status = %q, want failed", outcome.Status)
	}
	if outcome.ErrorCode == "" {
		t.Fatal("expected a non-empty ErrorCode")
	}
	if strings.Contains(outcome.ErrorCode, "AKIA") || strings.Contains(outcome.ErrorCode, "arn:aws:iam") || strings.Contains(outcome.ErrorCode, sensitive) {
		t.Fatalf("ErrorCode leaked secret-bearing text: %q", outcome.ErrorCode)
	}
}

// TestPublishEvidenceHandoffEnforcesDecompressedLimitBeforeGzip pins
// finding #9: the contracted 1 GiB decompressed limit must be checked on
// the marshaled JSON body BEFORE gzip, not only on the compressed stored
// object. A highly compressible bundle (one repeated-character coverage
// payload here) stays far under the 256 MiB stored limit yet must still
// be rejected once its pre-gzip size exceeds the decompressed bound.
func TestPublishEvidenceHandoffEnforcesDecompressedLimitBeforeGzip(t *testing.T) {
	originalLimit := maxBundleDecompressedBytes
	maxBundleDecompressedBytes = 1 << 10 // 1 KiB, so the test fixture need not allocate a real 1 GiB body
	defer func() { maxBundleDecompressedBytes = originalLimit }()

	publisher := &fakeHandoffPublisher{}
	settings := Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: "intake-bucket", Stream: "security"}}
	collection := ci.Collection{Scope: "writer", CollectedAt: time.Now()}
	// A single JSON string field of repeated "a"s: gzip would compress this
	// to a handful of bytes (well under the 256 MiB stored limit), so only
	// a pre-gzip decompressed check can catch it.
	oversizedCoverage, err := json.Marshal(map[string]string{"padding": strings.Repeat("a", 1<<12)})
	if err != nil {
		t.Fatalf("marshal oversized coverage: %v", err)
	}
	outcome := publishEvidenceHandoff(context.Background(), publisher, settings, collection, nil, oversizedCoverage, "runtime-1")
	if outcome.Status != "failed" || outcome.ErrorCode != "bundle_too_large" {
		t.Fatalf("outcome = %+v, want failed/bundle_too_large", outcome)
	}
	if outcome.SizeBytes <= int64(maxBundleDecompressedBytes) {
		t.Fatalf("outcome.SizeBytes = %d, want > %d (the decompressed size that triggered rejection)", outcome.SizeBytes, maxBundleDecompressedBytes)
	}
	if len(publisher.calls) != 0 {
		t.Fatalf("publisher.calls = %+v, an oversized bundle must never reach Publish", publisher.calls)
	}
}

// TestPublishEvidenceHandoffStoredLimitStillEnforced pins the existing
// 256 MiB compressed/stored-object guard: it must keep working once the
// decompressed check is added, not be subsumed or bypassed by it.
func TestPublishEvidenceHandoffStoredLimitStillEnforced(t *testing.T) {
	originalStoredLimit, originalDecompressedLimit := maxBundleStoredBytes, maxBundleDecompressedBytes
	maxBundleStoredBytes = 1 << 10       // 1 KiB
	maxBundleDecompressedBytes = 1 << 20 // large enough that only the stored check can trigger
	defer func() {
		maxBundleStoredBytes, maxBundleDecompressedBytes = originalStoredLimit, originalDecompressedLimit
	}()

	publisher := &fakeHandoffPublisher{}
	settings := Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: "intake-bucket", Stream: "security"}}
	collection := ci.Collection{Scope: "writer", CollectedAt: time.Now()}
	// Deterministic incompressible padding (SHA-256 counter stream) so gzip
	// cannot shrink it under the stored limit, forcing the check to run on
	// compressed bytes, not decompressed.
	padding := make([]byte, 1<<12)
	for offset := 0; offset < len(padding); offset += sha256.Size {
		block := sha256.Sum256([]byte(strconv.Itoa(offset)))
		copy(padding[offset:], block[:])
	}
	oversizedCoverage, err := json.Marshal(map[string]string{"padding": base64.StdEncoding.EncodeToString(padding)})
	if err != nil {
		t.Fatalf("marshal oversized coverage: %v", err)
	}
	outcome := publishEvidenceHandoff(context.Background(), publisher, settings, collection, nil, oversizedCoverage, "runtime-1")
	if outcome.Status != "failed" || outcome.ErrorCode != "bundle_too_large" {
		t.Fatalf("outcome = %+v, want failed/bundle_too_large", outcome)
	}
	if len(publisher.calls) != 0 {
		t.Fatalf("publisher.calls = %+v, an oversized stored object must never reach Publish", publisher.calls)
	}
}

func TestPublishEvidenceHandoffNoPublisherConfiguredIsFailure(t *testing.T) {
	settings := Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: "intake-bucket", Stream: "security"}}
	collection := ci.Collection{Scope: "writer", CollectedAt: time.Now()}
	outcome := publishEvidenceHandoff(context.Background(), nil, settings, collection, nil, []byte(`{}`), "runtime-1")
	if outcome.Status != "failed" || outcome.ErrorCode != "publisher_unavailable" {
		t.Fatalf("outcome = %+v, want failed/publisher_unavailable", outcome)
	}
}

// TestPublishEvidenceHandoffBodyCollectedAtMatchesKeyTimestamp pins the
// cross-repo contract VulnView verifies before assessing: the bundle body's
// collected_at must equal the instant the key encodes, even when the
// collection clock carries sub-second precision.
func TestPublishEvidenceHandoffBodyCollectedAtMatchesKeyTimestamp(t *testing.T) {
	publisher := &fakeHandoffPublisher{}
	settings := Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: "intake-bucket", Stream: "security"}}
	collectedAt := time.Date(2026, time.April, 1, 9, 0, 7, 987654321, time.UTC)
	collection := ci.Collection{Scope: "writer", CollectedAt: collectedAt}
	outcome := publishEvidenceHandoff(context.Background(), publisher, settings, collection, nil, []byte(`{}`), "runtime-1")
	if outcome.Status != "published" || len(publisher.calls) != 1 {
		t.Fatalf("outcome = %+v, calls = %d, want one published bundle", outcome, len(publisher.calls))
	}
	match := regexp.MustCompile(`/(\d{8}T\d{6}Z)-[0-9a-f]{64}\.json\.gz$`).FindStringSubmatch(outcome.Key)
	if match == nil {
		t.Fatalf("key %q does not carry a collected_at timestamp", outcome.Key)
	}
	keyTime, err := time.Parse("20060102T150405Z", match[1])
	if err != nil {
		t.Fatalf("parse key timestamp: %v", err)
	}
	bundle := decompressBundle(t, publisher.calls[0].Body)
	if !bundle.CollectedAt.Equal(keyTime) {
		t.Fatalf("bundle collected_at %s != key timestamp %s", bundle.CollectedAt.Format(time.RFC3339Nano), keyTime.Format(time.RFC3339Nano))
	}
}

func TestBuildEvidenceBundleRejectsMisalignedPrincipalEvents(t *testing.T) {
	in := handoffTestInput()
	in.PrincipalEvents = in.PrincipalEvents[:len(in.PrincipalEvents)-1]
	if _, _, err := buildEvidenceBundle(in); err == nil {
		t.Fatal("buildEvidenceBundle() accepted fewer principal events than evidence cohorts")
	}
}

func TestClassifyHandoffErrorRecognizesWrappedDeadline(t *testing.T) {
	wrapped := fmt.Errorf("put object: %w", context.DeadlineExceeded)
	if got := classifyHandoffError(wrapped); got != "timeout" {
		t.Fatalf("classifyHandoffError(wrapped deadline) = %q, want timeout", got)
	}
}
