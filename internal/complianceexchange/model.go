// Package complianceexchange builds and validates portable compliance package
// manifests. It is deliberately storage- and transport-agnostic: callers
// provide already-bounded file bytes, signing capability, and trusted public
// keys, while this package proves path safety, complete file coverage,
// integrity, and signature validity before any persistence is attempted.
package complianceexchange

import (
	"context"
	"crypto"
	"errors"
	"time"
)

const (
	ManifestSchemaVersion = "compliance-exchange-manifest/v1"
	SignatureType         = "compliance-manifest+jws"

	AlgorithmEdDSA = "EdDSA"
	AlgorithmES256 = "ES256"

	SeverityError   = "error"
	SeverityWarning = "warning"

	ValidationValid   = "valid"
	ValidationInvalid = "invalid"
)

var (
	ErrInvalidPackage   = errors.New("invalid compliance exchange package")
	ErrUnsupportedAlg   = errors.New("unsupported compliance package signature algorithm")
	ErrSignatureInvalid = errors.New("compliance package signature is invalid")
)

// Limits bounds the uncompressed files presented to the exchange core. The
// transport layer must independently bound compressed request bytes and archive
// expansion before constructing Files.
type Limits struct {
	MaxFiles          int
	MaxFileBytes      int64
	MaxTotalBytes     int64
	MaxPathBytes      int
	MaxManifestBytes  int
	MaxSignatureBytes int
}

// DefaultLimits returns conservative in-memory validation bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:          10_000,
		MaxFileBytes:      64 << 20,
		MaxTotalBytes:     512 << 20,
		MaxPathBytes:      512,
		MaxManifestBytes:  8 << 20,
		MaxSignatureBytes: 16 << 10,
	}
}

// File is one uncompressed package payload file. Data is copied by Build so a
// caller cannot mutate a built package after its digest has been recorded.
type File struct {
	Path        string
	MediaType   string
	LogicalType string
	Data        []byte
}

// ManifestFile is the immutable, signed description of one payload file.
type ManifestFile struct {
	Path        string `json:"path"`
	MediaType   string `json:"media_type"`
	LogicalType string `json:"logical_type"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}

// Manifest covers every payload file and the package-level provenance needed
// to stage it. ManifestDigest is intentionally not embedded because a manifest
// cannot contain its own digest.
type Manifest struct {
	SchemaVersion     string         `json:"schema_version"`
	PackageID         string         `json:"package_id"`
	TenantID          string         `json:"tenant_id"`
	CreatedAt         time.Time      `json:"created_at"`
	PredecessorDigest string         `json:"predecessor_digest,omitempty"`
	DisclosurePolicy  string         `json:"disclosure_policy,omitempty"`
	RedactionMode     string         `json:"redaction_mode,omitempty"`
	FileCount         int            `json:"file_count"`
	TotalBytes        int64          `json:"total_bytes"`
	Files             []ManifestFile `json:"files"`
}

// BuildRequest contains the exact revision-level inputs for one package.
type BuildRequest struct {
	PackageID         string
	TenantID          string
	CreatedAt         time.Time
	PredecessorDigest string
	DisclosurePolicy  string
	RedactionMode     string
	Files             []File
	Limits            Limits
}

// Package is an in-memory portable package core. Archive and object-storage
// adapters can serialize it without changing the signed manifest bytes.
type Package struct {
	Manifest       Manifest
	ManifestBytes  []byte
	ManifestDigest string
	Signature      string
	Files          []File
}

// Signer provides signing without exposing private key material. Implementors
// may wrap a local crypto.Signer or a remote signer outside this package.
type Signer interface {
	Algorithm() string
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// TrustResolver resolves only locally configured trusted keys. A resolver must
// not treat key IDs as URLs or fetch key material from the package.
type TrustResolver interface {
	ResolveTrustedKey(context.Context, string, string) (crypto.PublicKey, error)
}

// TrustResolverFunc adapts a function into a TrustResolver.
type TrustResolverFunc func(context.Context, string, string) (crypto.PublicKey, error)

func (f TrustResolverFunc) ResolveTrustedKey(ctx context.Context, keyID string, algorithm string) (crypto.PublicKey, error) {
	return f(ctx, keyID, algorithm)
}

// ValidationRequest is a pure staging request. ExpectedTenantID is required so
// a valid package for another tenant cannot be accepted by mistake.
type ValidationRequest struct {
	ExpectedTenantID string
	ManifestBytes    []byte
	Signature        string
	Files            []File
	Limits           Limits
	Trust            TrustResolver
}

// ValidationIssue is stable, machine-readable, and safe to show to the tenant
// that supplied the package. It intentionally excludes raw content and crypto
// implementation errors.
type ValidationIssue struct {
	Layer       string `json:"layer"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Path        string `json:"path,omitempty"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// ChangeOperation describes what a later persistence adapter would stage. The
// core cannot classify creates versus updates without canonical state, so its
// only action is stage.
type ChangeOperation struct {
	Action      string `json:"action"`
	Path        string `json:"path"`
	LogicalType string `json:"logical_type"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
}

// ChangePlan is emitted only after all validation layers pass.
type ChangePlan struct {
	PackageID      string            `json:"package_id"`
	TenantID       string            `json:"tenant_id"`
	ManifestDigest string            `json:"manifest_digest"`
	FileCount      int               `json:"file_count"`
	TotalBytes     int64             `json:"total_bytes"`
	Operations     []ChangeOperation `json:"operations"`
}

// ValidationResult is the complete output of staged validation.
type ValidationResult struct {
	Status         string            `json:"status"`
	Manifest       *Manifest         `json:"manifest,omitempty"`
	ManifestDigest string            `json:"manifest_digest,omitempty"`
	SignerKeyID    string            `json:"signer_key_id,omitempty"`
	Algorithm      string            `json:"algorithm,omitempty"`
	Issues         []ValidationIssue `json:"issues"`
	ChangePlan     *ChangePlan       `json:"change_plan,omitempty"`
}
