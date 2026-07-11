package complianceexchange

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Build creates a deterministic manifest, covers every supplied file, and
// signs the exact manifest bytes. The same request produces the same manifest
// bytes regardless of input file order.
func Build(ctx context.Context, request BuildRequest, signer Signer) (Package, error) {
	limits, err := normalizeLimits(request.Limits)
	if err != nil {
		return Package{}, err
	}
	if strings.TrimSpace(request.PackageID) == "" {
		return Package{}, fmt.Errorf("%w: package_id is required", ErrInvalidPackage)
	}
	if strings.TrimSpace(request.TenantID) == "" {
		return Package{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidPackage)
	}
	if request.CreatedAt.IsZero() {
		return Package{}, fmt.Errorf("%w: created_at is required", ErrInvalidPackage)
	}
	if predecessor := strings.TrimSpace(request.PredecessorDigest); predecessor != "" && !validDigest(predecessor) {
		return Package{}, fmt.Errorf("%w: predecessor_digest must be a lowercase SHA-256 value", ErrInvalidPackage)
	}
	if signer == nil {
		return Package{}, fmt.Errorf("%w: signer is required", ErrInvalidPackage)
	}

	files, manifestFiles, total, err := prepareFiles(request.Files, limits)
	if err != nil {
		return Package{}, err
	}
	manifest := Manifest{
		SchemaVersion:     ManifestSchemaVersion,
		PackageID:         strings.TrimSpace(request.PackageID),
		TenantID:          strings.TrimSpace(request.TenantID),
		CreatedAt:         request.CreatedAt.UTC(),
		PredecessorDigest: strings.TrimSpace(request.PredecessorDigest),
		DisclosurePolicy:  strings.TrimSpace(request.DisclosurePolicy),
		RedactionMode:     strings.TrimSpace(request.RedactionMode),
		FileCount:         len(manifestFiles),
		TotalBytes:        total,
		Files:             manifestFiles,
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return Package{}, err
	}
	if len(manifestBytes) > limits.MaxManifestBytes {
		return Package{}, fmt.Errorf("%w: manifest exceeds size limit", ErrInvalidPackage)
	}
	signature, err := SignDetached(ctx, manifestBytes, signer)
	if err != nil {
		return Package{}, err
	}
	if len(signature) > limits.MaxSignatureBytes {
		return Package{}, fmt.Errorf("%w: detached signature exceeds size limit", ErrInvalidPackage)
	}
	return Package{
		Manifest:       manifest,
		ManifestBytes:  manifestBytes,
		ManifestDigest: sha256Hex(manifestBytes),
		Signature:      signature,
		Files:          files,
	}, nil
}

func prepareFiles(input []File, limits Limits) ([]File, []ManifestFile, int64, error) {
	if len(input) == 0 {
		return nil, nil, 0, fmt.Errorf("%w: at least one payload file is required", ErrInvalidPackage)
	}
	if len(input) > limits.MaxFiles {
		return nil, nil, 0, fmt.Errorf("%w: file count exceeds limit", ErrInvalidPackage)
	}
	files := make([]File, 0, len(input))
	manifestFiles := make([]ManifestFile, 0, len(input))
	seen := make(map[string]string, len(input))
	var total int64
	for _, source := range input {
		if err := validatePackagePath(source.Path, limits.MaxPathBytes); err != nil {
			return nil, nil, 0, fmt.Errorf("%w: %q: %w", ErrInvalidPackage, source.Path, err)
		}
		key := collisionKey(source.Path)
		if prior, ok := seen[key]; ok {
			return nil, nil, 0, fmt.Errorf("%w: duplicate or case-colliding paths %q and %q", ErrInvalidPackage, prior, source.Path)
		}
		seen[key] = source.Path
		if strings.TrimSpace(source.MediaType) == "" {
			return nil, nil, 0, fmt.Errorf("%w: media_type is required for %q", ErrInvalidPackage, source.Path)
		}
		if strings.TrimSpace(source.LogicalType) == "" {
			return nil, nil, 0, fmt.Errorf("%w: logical_type is required for %q", ErrInvalidPackage, source.Path)
		}
		size := int64(len(source.Data))
		if size > limits.MaxFileBytes {
			return nil, nil, 0, fmt.Errorf("%w: file %q exceeds size limit", ErrInvalidPackage, source.Path)
		}
		if total > limits.MaxTotalBytes-size {
			return nil, nil, 0, fmt.Errorf("%w: total payload exceeds size limit", ErrInvalidPackage)
		}
		total += size
		copied := File{
			Path:        source.Path,
			MediaType:   strings.TrimSpace(source.MediaType),
			LogicalType: strings.TrimSpace(source.LogicalType),
			Data:        bytes.Clone(source.Data),
		}
		files = append(files, copied)
		manifestFiles = append(manifestFiles, ManifestFile{
			Path:        copied.Path,
			MediaType:   copied.MediaType,
			LogicalType: copied.LogicalType,
			SizeBytes:   size,
			SHA256:      sha256Hex(copied.Data),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(manifestFiles, func(i, j int) bool { return manifestFiles[i].Path < manifestFiles[j].Path })
	return files, manifestFiles, total, nil
}

func marshalManifest(manifest Manifest) ([]byte, error) {
	content, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal compliance package manifest: %w", err)
	}
	return content, nil
}

func decodeManifest(content []byte) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errorsTrailingJSON()
	}
	return manifest, nil
}

func errorsTrailingJSON() error {
	return fmt.Errorf("manifest contains trailing JSON values")
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits.MaxFiles < 0 || limits.MaxFileBytes < 0 || limits.MaxTotalBytes < 0 || limits.MaxPathBytes < 0 || limits.MaxManifestBytes < 0 || limits.MaxSignatureBytes < 0 {
		return Limits{}, fmt.Errorf("%w: limits cannot be negative", ErrInvalidPackage)
	}
	defaults := DefaultLimits()
	if limits.MaxFiles == 0 {
		limits.MaxFiles = defaults.MaxFiles
	}
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxTotalBytes == 0 {
		limits.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if limits.MaxPathBytes == 0 {
		limits.MaxPathBytes = defaults.MaxPathBytes
	}
	if limits.MaxManifestBytes == 0 {
		limits.MaxManifestBytes = defaults.MaxManifestBytes
	}
	if limits.MaxSignatureBytes == 0 {
		limits.MaxSignatureBytes = defaults.MaxSignatureBytes
	}
	if limits.MaxFileBytes > limits.MaxTotalBytes {
		return Limits{}, fmt.Errorf("%w: max file bytes cannot exceed max total bytes", ErrInvalidPackage)
	}
	return limits, nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func validCreatedAt(value time.Time) bool {
	return !value.IsZero() && value.Location() != nil
}
