package grcaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const packageManifestSchemaVersion = "grc-audit-package/v1"

var (
	// ErrManifestDigestMismatch indicates that a manifest's semantic content was altered.
	ErrManifestDigestMismatch = errors.New("audit package manifest digest mismatch")
	// ErrArtifactCapabilityUnavailable indicates that no approved artifact writer is configured.
	ErrArtifactCapabilityUnavailable = errors.New("audit package artifact capability unavailable")
	// ErrSigningCapabilityUnavailable indicates that no approved manifest signer is configured.
	ErrSigningCapabilityUnavailable = errors.New("audit package signing capability unavailable")
)

// RedactionAction records how one logical package entry was disclosed.
type RedactionAction string

const (
	RedactionActionIncluded RedactionAction = "included"
	RedactionActionRedacted RedactionAction = "redacted"
	RedactionActionOmitted  RedactionAction = "omitted"
)

// RedactionDecision is the bounded disclosure decision for one package entry.
type RedactionDecision struct {
	Mode             string          `json:"mode"`
	Action           RedactionAction `json:"action"`
	ReasonCode       string          `json:"reason_code,omitempty"`
	PolicyRevisionID string          `json:"policy_revision_id"`
}

// PackageManifestEntry is one logical artifact covered by the package digest.
type PackageManifestEntry struct {
	Path           string            `json:"path"`
	LogicalType    string            `json:"logical_type"`
	SchemaVersion  string            `json:"schema_version"`
	StableID       string            `json:"stable_id"`
	RevisionID     string            `json:"revision_id"`
	MediaType      string            `json:"media_type"`
	ContentDigest  string            `json:"content_digest,omitempty"`
	SourceDigest   string            `json:"source_digest,omitempty"`
	SizeBytes      uint64            `json:"size_bytes,omitempty"`
	Redaction      RedactionDecision `json:"redaction"`
	ProvenanceRefs []string          `json:"provenance_refs,omitempty"`
}

// PackageManifest is the deterministic semantic envelope for one immutable package revision.
type PackageManifest struct {
	SchemaVersion     string                 `json:"schema_version"`
	PackageID         string                 `json:"package_id"`
	TenantID          string                 `json:"tenant_id"`
	EngagementID      string                 `json:"engagement_id"`
	Revision          uint64                 `json:"revision"`
	AssessmentRunID   string                 `json:"assessment_run_id"`
	ReviewRevisionID  string                 `json:"review_revision_id"`
	RedactionMode     string                 `json:"redaction_mode"`
	PredecessorDigest string                 `json:"predecessor_digest,omitempty"`
	Entries           []PackageManifestEntry `json:"entries"`
	SemanticDigest    string                 `json:"semantic_digest"`
}

// PackageManifestRequest contains exact immutable inputs for a package revision.
type PackageManifestRequest struct {
	PackageID         string
	TenantID          string
	EngagementID      string
	Revision          uint64
	AssessmentRunID   string
	ReviewRevisionID  string
	RedactionMode     string
	PredecessorDigest string
	Entries           []PackageManifestEntry
}

// BuildPackageManifest validates, sorts, and hashes one immutable package manifest.
func BuildPackageManifest(request PackageManifestRequest) (PackageManifest, error) {
	packageID, err := required(request.PackageID, "package id")
	if err != nil {
		return PackageManifest{}, err
	}
	tenantID, err := required(request.TenantID, "tenant id")
	if err != nil {
		return PackageManifest{}, err
	}
	engagementID, err := required(request.EngagementID, "engagement id")
	if err != nil {
		return PackageManifest{}, err
	}
	assessmentRunID, err := required(request.AssessmentRunID, "assessment run id")
	if err != nil {
		return PackageManifest{}, err
	}
	reviewRevisionID, err := required(request.ReviewRevisionID, "review revision id")
	if err != nil {
		return PackageManifest{}, err
	}
	redactionMode, err := required(request.RedactionMode, "redaction mode")
	if err != nil {
		return PackageManifest{}, err
	}
	if request.Revision == 0 {
		return PackageManifest{}, fmt.Errorf("%w: package revision must be positive", ErrInvalidRequest)
	}
	predecessorDigest := strings.TrimSpace(request.PredecessorDigest)
	if request.Revision > 1 && !validDigest(predecessorDigest) {
		return PackageManifest{}, fmt.Errorf("%w: predecessor digest is required after revision one", ErrInvalidRequest)
	}
	if request.Revision == 1 && predecessorDigest != "" {
		return PackageManifest{}, fmt.Errorf("%w: revision one cannot have a predecessor digest", ErrInvalidRequest)
	}
	entries, err := normalizeManifestEntries(request.Entries, redactionMode)
	if err != nil {
		return PackageManifest{}, err
	}
	manifest := PackageManifest{
		SchemaVersion:     packageManifestSchemaVersion,
		PackageID:         packageID,
		TenantID:          tenantID,
		EngagementID:      engagementID,
		Revision:          request.Revision,
		AssessmentRunID:   assessmentRunID,
		ReviewRevisionID:  reviewRevisionID,
		RedactionMode:     redactionMode,
		PredecessorDigest: predecessorDigest,
		Entries:           entries,
	}
	digest, err := manifestDigest(manifest)
	if err != nil {
		return PackageManifest{}, err
	}
	manifest.SemanticDigest = digest
	return manifest, nil
}

// VerifyPackageManifest validates canonical fields and detects altered semantic content.
func VerifyPackageManifest(manifest PackageManifest) error {
	rebuilt, err := BuildPackageManifest(PackageManifestRequest{
		PackageID:         manifest.PackageID,
		TenantID:          manifest.TenantID,
		EngagementID:      manifest.EngagementID,
		Revision:          manifest.Revision,
		AssessmentRunID:   manifest.AssessmentRunID,
		ReviewRevisionID:  manifest.ReviewRevisionID,
		RedactionMode:     manifest.RedactionMode,
		PredecessorDigest: manifest.PredecessorDigest,
		Entries:           manifest.Entries,
	})
	if err != nil {
		return err
	}
	if manifest.SchemaVersion != rebuilt.SchemaVersion || manifest.SemanticDigest != rebuilt.SemanticDigest {
		return ErrManifestDigestMismatch
	}
	return nil
}

// CanonicalPackageManifestBytes returns the stable bytes covered by a signature.
func CanonicalPackageManifestBytes(manifest PackageManifest) ([]byte, error) {
	if err := VerifyPackageManifest(manifest); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode package manifest: %w", err)
	}
	return payload, nil
}

// PackageManifestSigner signs canonical manifest bytes using an approved capability.
type PackageManifestSigner interface {
	SignPackageManifest(context.Context, []byte) (PackageSignature, error)
}

// PackageArtifactWriter writes the signed manifest to an approved artifact system.
type PackageArtifactWriter interface {
	WritePackageManifest(context.Context, PackageArtifact) (PackageArtifactReceipt, error)
}

// PackageSignature describes the signer and detached signature returned by a signer.
type PackageSignature struct {
	Algorithm string    `json:"algorithm"`
	KeyRef    string    `json:"key_ref"`
	Value     string    `json:"value"`
	SignedAt  time.Time `json:"signed_at"`
}

// PackageArtifact is the signed manifest passed to an artifact writer.
type PackageArtifact struct {
	PackageID     string
	Revision      uint64
	Content       []byte
	ContentDigest string
	Signature     PackageSignature
}

// PackageArtifactReceipt is the non-content receipt returned by an artifact writer.
type PackageArtifactReceipt struct {
	URI       string `json:"uri"`
	Digest    string `json:"digest"`
	SizeBytes uint64 `json:"size_bytes"`
}

// PackageFinalizationReceipt records the manifest, signature, and artifact receipt.
type PackageFinalizationReceipt struct {
	PackageID      string                 `json:"package_id"`
	Revision       uint64                 `json:"revision"`
	ManifestDigest string                 `json:"manifest_digest"`
	Signature      PackageSignature       `json:"signature"`
	Artifact       PackageArtifactReceipt `json:"artifact"`
}

// PackageFinalizer requires explicit artifact and signing capabilities. It never
// substitutes one capability when another is absent.
type PackageFinalizer struct {
	Artifacts PackageArtifactWriter
	Signer    PackageManifestSigner
}

// Finalize signs and writes an already-built immutable manifest.
func (f PackageFinalizer) Finalize(ctx context.Context, manifest PackageManifest) (PackageFinalizationReceipt, error) {
	if err := f.requireCapabilities(); err != nil {
		return PackageFinalizationReceipt{}, err
	}
	payload, err := CanonicalPackageManifestBytes(manifest)
	if err != nil {
		return PackageFinalizationReceipt{}, err
	}
	signature, err := f.Signer.SignPackageManifest(ctx, payload)
	if err != nil {
		return PackageFinalizationReceipt{}, fmt.Errorf("sign package manifest: %w", err)
	}
	if strings.TrimSpace(signature.Algorithm) == "" || strings.TrimSpace(signature.KeyRef) == "" || strings.TrimSpace(signature.Value) == "" || signature.SignedAt.IsZero() {
		return PackageFinalizationReceipt{}, fmt.Errorf("%w: signer returned an incomplete signature", ErrInvalidRequest)
	}
	contentDigest := DigestBytes(payload)
	receipt, err := f.Artifacts.WritePackageManifest(ctx, PackageArtifact{
		PackageID:     manifest.PackageID,
		Revision:      manifest.Revision,
		Content:       cloneBytes(payload),
		ContentDigest: contentDigest,
		Signature:     signature,
	})
	if err != nil {
		return PackageFinalizationReceipt{}, fmt.Errorf("write package manifest: %w", err)
	}
	if strings.TrimSpace(receipt.URI) == "" || receipt.Digest != contentDigest || receipt.SizeBytes != uint64(len(payload)) {
		return PackageFinalizationReceipt{}, fmt.Errorf("%w: artifact writer returned an invalid receipt", ErrInvalidRequest)
	}
	return PackageFinalizationReceipt{
		PackageID:      manifest.PackageID,
		Revision:       manifest.Revision,
		ManifestDigest: manifest.SemanticDigest,
		Signature:      signature,
		Artifact:       receipt,
	}, nil
}

func (f PackageFinalizer) requireCapabilities() error {
	var missing []error
	if f.Artifacts == nil {
		missing = append(missing, ErrArtifactCapabilityUnavailable)
	}
	if f.Signer == nil {
		missing = append(missing, ErrSigningCapabilityUnavailable)
	}
	return errors.Join(missing...)
}

func normalizeManifestEntries(entries []PackageManifestEntry, redactionMode string) ([]PackageManifestEntry, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: package entries are required", ErrInvalidRequest)
	}
	result := make([]PackageManifestEntry, 0, len(entries))
	seenPaths := map[string]struct{}{}
	for index, entry := range entries {
		normalized, err := normalizeManifestEntry(entry, redactionMode)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index, err)
		}
		if _, ok := seenPaths[normalized.Path]; ok {
			return nil, fmt.Errorf("%w: package entry path %q is duplicated", ErrInvalidRequest, normalized.Path)
		}
		seenPaths[normalized.Path] = struct{}{}
		result = append(result, normalized)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func normalizeManifestEntry(entry PackageManifestEntry, redactionMode string) (PackageManifestEntry, error) {
	rawPath, err := required(entry.Path, "path")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	cleanPath := path.Clean(strings.ReplaceAll(rawPath, "\\", "/"))
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, "../") || strings.HasPrefix(cleanPath, "/") || cleanPath != rawPath {
		return PackageManifestEntry{}, fmt.Errorf("%w: package entry path %q is not canonical and relative", ErrInvalidRequest, rawPath)
	}
	logicalType, err := required(entry.LogicalType, "logical type")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	schemaVersion, err := required(entry.SchemaVersion, "schema version")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	stableID, err := required(entry.StableID, "stable id")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	revisionID, err := required(entry.RevisionID, "revision id")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	mediaType, err := required(entry.MediaType, "media type")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	policyRevisionID, err := required(entry.Redaction.PolicyRevisionID, "redaction policy revision id")
	if err != nil {
		return PackageManifestEntry{}, err
	}
	mode := strings.TrimSpace(entry.Redaction.Mode)
	if mode == "" {
		mode = redactionMode
	}
	if mode != redactionMode {
		return PackageManifestEntry{}, fmt.Errorf("%w: entry redaction mode %q does not match manifest mode %q", ErrInvalidRequest, mode, redactionMode)
	}
	if !validRedactionAction(entry.Redaction.Action) {
		return PackageManifestEntry{}, fmt.Errorf("%w: redaction action %q is invalid", ErrInvalidRequest, entry.Redaction.Action)
	}
	contentDigest := strings.TrimSpace(entry.ContentDigest)
	if entry.Redaction.Action != RedactionActionOmitted && !validDigest(contentDigest) {
		return PackageManifestEntry{}, fmt.Errorf("%w: included or redacted entries require a SHA-256 content digest", ErrInvalidRequest)
	}
	if entry.Redaction.Action == RedactionActionOmitted && (contentDigest != "" || entry.SizeBytes != 0) {
		return PackageManifestEntry{}, fmt.Errorf("%w: omitted entries cannot include disclosed content metadata", ErrInvalidRequest)
	}
	reasonCode := strings.TrimSpace(entry.Redaction.ReasonCode)
	if entry.Redaction.Action != RedactionActionIncluded && reasonCode == "" {
		return PackageManifestEntry{}, fmt.Errorf("%w: redacted or omitted entries require a reason code", ErrInvalidRequest)
	}
	sourceDigest := strings.TrimSpace(entry.SourceDigest)
	if sourceDigest != "" && !validDigest(sourceDigest) {
		return PackageManifestEntry{}, fmt.Errorf("%w: source digest is invalid", ErrInvalidRequest)
	}
	return PackageManifestEntry{
		Path:          cleanPath,
		LogicalType:   logicalType,
		SchemaVersion: schemaVersion,
		StableID:      stableID,
		RevisionID:    revisionID,
		MediaType:     mediaType,
		ContentDigest: contentDigest,
		SourceDigest:  sourceDigest,
		SizeBytes:     entry.SizeBytes,
		Redaction: RedactionDecision{
			Mode:             mode,
			Action:           entry.Redaction.Action,
			ReasonCode:       reasonCode,
			PolicyRevisionID: policyRevisionID,
		},
		ProvenanceRefs: normalizedStrings(entry.ProvenanceRefs),
	}, nil
}

func manifestDigest(manifest PackageManifest) (string, error) {
	manifest.SemanticDigest = ""
	digest, err := canonicalDigest(manifest)
	if err != nil {
		return "", fmt.Errorf("hash package manifest: %w", err)
	}
	return digest, nil
}

func validRedactionAction(action RedactionAction) bool {
	switch action {
	case RedactionActionIncluded, RedactionActionRedacted, RedactionActionOmitted:
		return true
	default:
		return false
	}
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func cloneBytes(values []byte) []byte {
	if values == nil {
		return nil
	}
	return append([]byte(nil), values...)
}

// AuthorizePackageAccess verifies package and engagement object scope.
func AuthorizePackageAccess(principal Principal, engagement Engagement, manifest PackageManifest, permission EngagementPermission) error {
	if strings.TrimSpace(manifest.PackageID) == "" || manifest.TenantID != engagement.TenantID || manifest.EngagementID != engagement.ID {
		return ErrPackageNotFound
	}
	if err := AuthorizeEngagementAccess(principal, engagement, permission); err != nil {
		return ErrPackageNotFound
	}
	return nil
}

// PackageRevisionRef returns a stable human-readable package revision reference.
func PackageRevisionRef(manifest PackageManifest) string {
	return strings.TrimSpace(manifest.PackageID) + "@" + strconv.FormatUint(manifest.Revision, 10)
}
