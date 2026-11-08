package cloudidentitysource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

const (
	// evidenceBundleSchema is the wire schema of the object this source
	// writes to the VulnView-owned S3 intake bucket.
	evidenceBundleSchema = "cloud-identity-evidence-bundle/v1"
)

// maxBundleStoredBytes bounds the gzip-compressed object this source will
// attempt to publish; VulnView independently enforces the same bound on
// read. A var, not a const, so tests can shrink it instead of
// constructing a multi-gigabyte fixture.
var maxBundleStoredBytes = 256 << 20

// maxBundleDecompressedBytes bounds the marshaled JSON body before gzip,
// matching the contract's 1 GiB decompressed limit (a highly compressible
// bundle can stay under the 256 MiB stored bound while still exceeding
// this). VulnView independently enforces the same bound on read. A var,
// not a const, so tests can shrink it instead of constructing a
// multi-gigabyte fixture.
var maxBundleDecompressedBytes = 1 << 30

// bundleTooLargeError reports that the marshaled (pre-gzip) evidence
// bundle exceeded maxBundleDecompressedBytes, carrying the exact
// decompressed size for the handoff outcome's non-secret-bearing
// diagnostics.
type bundleTooLargeError struct {
	decompressedBytes int
}

func (e *bundleTooLargeError) Error() string {
	return fmt.Sprintf("evidence bundle exceeds max decompressed size: %d bytes", e.decompressedBytes)
}

// HandoffPublisher publishes one evidence bundle's gzip-compressed bytes to
// the VulnView-owned S3 intake bucket under key, in region. Implementations
// MUST perform a conditional create (If-None-Match: "*") and must treat a
// precondition-failed response (this exact content-addressed key already
// exists) as success, never as an error.
type HandoffPublisher interface {
	Publish(ctx context.Context, bucket, region, key string, body []byte) error
}

// HandoffOutcome is the non-secret-bearing summary of one publish attempt,
// carried on the cloud_identity.coverage event's handoff field.
type HandoffOutcome struct {
	Status    string // "published", "failed", or "disabled"
	Bucket    string
	Key       string
	SHA256    string
	SizeBytes int64
	Stream    string
	ErrorCode string
}

func (o HandoffOutcome) toCollectionHandoff() ci.CollectionHandoff {
	return ci.CollectionHandoff{
		Status: o.Status, Bucket: o.Bucket, Key: o.Key,
		SHA256: o.SHA256, SizeBytes: o.SizeBytes, Stream: o.Stream, ErrorCode: o.ErrorCode,
	}
}

// evidenceBundle is the exact wire shape published to the intake bucket,
// schema cloud-identity-evidence-bundle/v1.
type evidenceBundle struct {
	Schema         string            `json:"schema"`
	Stream         string            `json:"stream"`
	CohortScope    string            `json:"cohort_scope"`
	CollectedAt    time.Time         `json:"collected_at"`
	CollectionID   string            `json:"collection_id"`
	Producer       bundleProducer    `json:"producer"`
	PlanDigest     string            `json:"plan_digest"`
	Coverage       json.RawMessage   `json:"coverage"`
	PrincipalCount int               `json:"principal_count"`
	Principals     []json.RawMessage `json:"principals"`
}

type bundleProducer struct {
	SourceID  string `json:"source_id"`
	RuntimeID string `json:"runtime_id,omitempty"`
	Build     string `json:"build,omitempty"`
}

// evidenceHandoffInput is every fact buildEvidenceBundle needs. Principals
// and CoveragePayload are the EXACT already-built event payloads
// (cloud_identity.principal_evidence / cloud_identity.coverage), so the
// bundle can never drift from what Cerebro's own append log records for
// this collection pass.
type evidenceHandoffInput struct {
	Tenant          string
	Stream          string
	Scope           string
	CollectedAt     time.Time
	PlanDigest      string
	RuntimeID       string
	Build           string
	Evidence        []ci.Evidence
	PrincipalEvents []json.RawMessage
	CoveragePayload json.RawMessage
}

// buildEvidenceBundle assembles and gzip-compresses the deterministic
// handoff object: principals sorted by (provider, principal.id), a
// canonical digest of the scan plan, and a deterministic collection_id.
// Gzip uses a fixed header (ModTime zero, no name/comment) so identical
// evidence always compresses to identical bytes, making the content-
// addressed object key reproducible across retries of the same
// collection pass. The bundle's collected_at is the collection time at
// whole-second precision, the same instant the object key encodes;
// VulnView rejects a bundle whose body and key disagree.
func buildEvidenceBundle(in evidenceHandoffInput) (gzipped []byte, sha256Hex string, err error) {
	if len(in.Evidence) != len(in.PrincipalEvents) {
		return nil, "", fmt.Errorf("evidence bundle needs one principal event per cohort: %d cohorts, %d events", len(in.Evidence), len(in.PrincipalEvents))
	}
	order := make([]int, len(in.Evidence))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := in.Evidence[order[i]].Principal, in.Evidence[order[j]].Principal
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return a.ID < b.ID
	})
	principals := make([]json.RawMessage, 0, len(order))
	for _, index := range order {
		principals = append(principals, in.PrincipalEvents[index])
	}

	collectedAt := bundleCollectedAt(in.CollectedAt)
	identity, err := json.Marshal(struct {
		Tenant      string    `json:"tenant"`
		Stream      string    `json:"stream"`
		Scope       string    `json:"scope"`
		CollectedAt time.Time `json:"collected_at"`
	}{in.Tenant, in.Stream, in.Scope, collectedAt})
	if err != nil {
		return nil, "", fmt.Errorf("marshal collection id: %w", err)
	}
	collectionIDDigest, err := ci.DigestJSON(identity)
	if err != nil {
		return nil, "", fmt.Errorf("digest collection id: %w", err)
	}

	bundle := evidenceBundle{
		Schema:       evidenceBundleSchema,
		Stream:       in.Stream,
		CohortScope:  in.Scope,
		CollectedAt:  collectedAt,
		CollectionID: collectionIDDigest,
		Producer: bundleProducer{
			SourceID:  ci.SourceID,
			RuntimeID: in.RuntimeID,
			Build:     in.Build,
		},
		PlanDigest:     in.PlanDigest,
		Coverage:       in.CoveragePayload,
		PrincipalCount: len(principals),
		Principals:     principals,
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		return nil, "", fmt.Errorf("marshal evidence bundle: %w", err)
	}
	if len(body) > maxBundleDecompressedBytes {
		return nil, "", &bundleTooLargeError{decompressedBytes: len(body)}
	}

	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, "", fmt.Errorf("construct gzip writer: %w", err)
	}
	writer.ModTime = time.Unix(0, 0)
	writer.OS = 255 // unknown, per RFC 1952 -- never leak the build host's OS byte.
	if _, err := writer.Write(body); err != nil {
		return nil, "", fmt.Errorf("gzip evidence bundle: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("close gzip evidence bundle: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// bundleCollectedAt is the collection instant at the whole-second
// precision of the intake key, so the bundle body and key always agree.
func bundleCollectedAt(collectedAt time.Time) time.Time {
	return collectedAt.UTC().Truncate(time.Second)
}

// buildEvidenceBundleKey formats the content-addressed intake key:
// cloud-identity/<stream>/<cohort_scope>/<collected_at as YYYYMMDDTHHMMSSZ>-<sha256 hex of the stored object bytes>.json.gz
func buildEvidenceBundleKey(stream, cohortScope string, collectedAt time.Time, storedSHA256Hex string) string {
	return fmt.Sprintf("cloud-identity/%s/%s/%sZ-%s.json.gz", stream, cohortScope, bundleCollectedAt(collectedAt).Format("20060102T150405"), storedSHA256Hex)
}

// publishEvidenceHandoff builds and, if a publisher and bucket are
// configured, publishes the evidence bundle for this collection pass.
// Publish failures are classified into a non-secret-bearing error code and
// never surfaced as a Read() error: collection events are never dropped on
// publish failure.
func publishEvidenceHandoff(ctx context.Context, publisher HandoffPublisher, settings Settings, collection ci.Collection, principalEvents []json.RawMessage, coveragePayload json.RawMessage, runtimeID string) HandoffOutcome {
	bucket := settings.EvidenceHandoff.Bucket
	stream := settings.EvidenceHandoff.Stream
	if bucket == "" {
		return HandoffOutcome{Status: "disabled"}
	}

	planJSON, err := json.Marshal(settings.Plan)
	if err != nil {
		return HandoffOutcome{Status: "failed", Stream: stream, ErrorCode: "plan_digest_unavailable"}
	}
	planDigest, err := ci.DigestJSON(planJSON)
	if err != nil {
		return HandoffOutcome{Status: "failed", Stream: stream, ErrorCode: "plan_digest_unavailable"}
	}
	body, sha256Hex, err := buildEvidenceBundle(evidenceHandoffInput{
		Tenant: settings.TenantID, Stream: stream, Scope: collection.Scope,
		CollectedAt: collection.CollectedAt, PlanDigest: planDigest,
		RuntimeID: runtimeID, Build: cerebroBuildVersion(),
		Evidence: collection.Evidence, PrincipalEvents: principalEvents, CoveragePayload: coveragePayload,
	})
	if err != nil {
		var tooLarge *bundleTooLargeError
		if errors.As(err, &tooLarge) {
			return HandoffOutcome{Status: "failed", Stream: stream, ErrorCode: "bundle_too_large", SizeBytes: int64(tooLarge.decompressedBytes)}
		}
		return HandoffOutcome{Status: "failed", Stream: stream, ErrorCode: "bundle_build_failed"}
	}
	if len(body) > maxBundleStoredBytes {
		return HandoffOutcome{Status: "failed", Stream: stream, ErrorCode: "bundle_too_large", SizeBytes: int64(len(body))}
	}
	key := buildEvidenceBundleKey(stream, collection.Scope, collection.CollectedAt, sha256Hex)
	outcome := HandoffOutcome{Bucket: bucket, Key: key, SHA256: sha256Hex, SizeBytes: int64(len(body)), Stream: stream}
	if publisher == nil {
		outcome.Status = "failed"
		outcome.ErrorCode = "publisher_unavailable"
		return outcome
	}
	if err := publisher.Publish(ctx, bucket, settings.EvidenceHandoff.Region, key, body); err != nil {
		outcome.Status = "failed"
		outcome.ErrorCode = classifyHandoffError(err)
		return outcome
	}
	outcome.Status = "published"
	return outcome
}

// classifyHandoffError reduces a publish failure to a short, stable,
// non-secret-bearing code. It never includes the underlying error's own
// text, which could carry request IDs, presigned URL fragments, or other
// operationally sensitive detail.
func classifyHandoffError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "publish_error"
	}
}
