package contentpacks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	ManifestSchemaV1  = "cerebro.content-pack/v1"
	AllowlistSchemaV1 = "cerebro.content-pack-allowlist/v1"

	maxContentFiles = 128
	maxFileBytes    = int64(1 << 20)
	maxPackBytes    = int64(8 << 20)
)

var allowedMediaTypes = map[string]struct{}{
	"application/json": {},
	"application/yaml": {},
}

// Manifest is the immutable, data-only contract for one content pack.
type Manifest struct {
	SchemaVersion  string        `json:"schema_version"`
	PackID         string        `json:"pack_id"`
	Version        string        `json:"version"`
	ManifestDigest string        `json:"manifest_digest"`
	SigningKeyID   string        `json:"signing_key_id"`
	Kind           string        `json:"kind"`
	LoadOrder      uint32        `json:"load_order"`
	Kernel         Compatibility `json:"kernel"`
	Contents       []Content     `json:"contents"`
	Metadata       Metadata      `json:"metadata"`
}

type Compatibility struct {
	MinInclusive string `json:"min_inclusive"`
	MaxExclusive string `json:"max_exclusive"`
}

type Content struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}

type Metadata struct {
	Owner            string `json:"owner"`
	Certification    string `json:"certification"`
	GeneratedFrom    string `json:"generated_from"`
	RollbackBoundary string `json:"rollback_boundary"`
}

// Allowlist is an operator-controlled set of tenant, pack, digest, and signer grants.
type Allowlist struct {
	SchemaVersion string        `json:"schema_version"`
	TenantID      string        `json:"tenant_id"`
	Keys          []TrustedKey  `json:"keys"`
	Packs         []AllowedPack `json:"packs"`
}

type TrustedKey struct {
	ID              string `json:"id"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

type AllowedPack struct {
	PackID   string   `json:"pack_id"`
	Versions []string `json:"versions"`
	Digests  []string `json:"digests"`
	KeyIDs   []string `json:"key_ids"`
}

func (manifest Manifest) Validate(kernelVersion string) error {
	if manifest.SchemaVersion != ManifestSchemaV1 {
		return fmt.Errorf("unsupported manifest schema %q", manifest.SchemaVersion)
	}
	if !validIdentifier(manifest.PackID) {
		return fmt.Errorf("invalid pack_id %q", manifest.PackID)
	}
	if _, err := parseVersion(manifest.Version); err != nil {
		return fmt.Errorf("invalid pack version: %w", err)
	}
	if manifest.Kind != "connector" && manifest.Kind != "policy-control" {
		return fmt.Errorf("unsupported pack kind %q", manifest.Kind)
	}
	if !validIdentifier(manifest.SigningKeyID) {
		return fmt.Errorf("invalid signing_key_id %q", manifest.SigningKeyID)
	}
	if err := manifest.Kernel.validate(kernelVersion); err != nil {
		return err
	}
	if len(manifest.Contents) == 0 || len(manifest.Contents) > maxContentFiles {
		return fmt.Errorf("contents count must be between 1 and %d", maxContentFiles)
	}
	seenIDs := map[string]struct{}{}
	seenPaths := map[string]struct{}{}
	var totalBytes int64
	for index, content := range manifest.Contents {
		if !validIdentifier(content.ID) {
			return fmt.Errorf("contents[%d].id %q is invalid", index, content.ID)
		}
		if _, exists := seenIDs[content.ID]; exists {
			return fmt.Errorf("contents[%d].id %q is duplicated", index, content.ID)
		}
		seenIDs[content.ID] = struct{}{}
		cleanPath := path.Clean(content.Path)
		if cleanPath != content.Path || !strings.HasPrefix(cleanPath, "content/") || strings.Contains(cleanPath, "\\") {
			return fmt.Errorf("contents[%d].path %q must be a clean relative content path", index, content.Path)
		}
		if _, exists := seenPaths[content.Path]; exists {
			return fmt.Errorf("contents[%d].path %q is duplicated", index, content.Path)
		}
		seenPaths[content.Path] = struct{}{}
		if _, ok := allowedMediaTypes[content.MediaType]; !ok {
			return fmt.Errorf("contents[%d].media_type %q is not allowed", index, content.MediaType)
		}
		if !validDigest(content.SHA256) {
			return fmt.Errorf("contents[%d].sha256 is invalid", index)
		}
		if content.Bytes <= 0 || content.Bytes > maxFileBytes {
			return fmt.Errorf("contents[%d].bytes must be between 1 and %d", index, maxFileBytes)
		}
		totalBytes += content.Bytes
		if totalBytes > maxPackBytes {
			return fmt.Errorf("pack content exceeds %d bytes", maxPackBytes)
		}
	}
	if !sort.SliceIsSorted(manifest.Contents, func(i, j int) bool {
		return manifest.Contents[i].ID < manifest.Contents[j].ID
	}) {
		return errors.New("contents must be sorted by id")
	}
	wantDigest, err := manifest.digest()
	if err != nil {
		return err
	}
	if manifest.ManifestDigest != wantDigest {
		return fmt.Errorf("manifest_digest mismatch: got %q, want %q", manifest.ManifestDigest, wantDigest)
	}
	if strings.TrimSpace(manifest.Metadata.Owner) == "" || strings.TrimSpace(manifest.Metadata.Certification) == "" {
		return errors.New("metadata owner and certification are required")
	}
	return nil
}

func (compatibility Compatibility) validate(kernelVersion string) error {
	minimum, err := parseVersion(compatibility.MinInclusive)
	if err != nil {
		return fmt.Errorf("invalid kernel min_inclusive: %w", err)
	}
	maximum, err := parseVersion(compatibility.MaxExclusive)
	if err != nil {
		return fmt.Errorf("invalid kernel max_exclusive: %w", err)
	}
	kernel, err := parseVersion(kernelVersion)
	if err != nil {
		return fmt.Errorf("invalid kernel version: %w", err)
	}
	if compareVersions(minimum, maximum) >= 0 {
		return errors.New("kernel compatibility range is empty")
	}
	if compareVersions(kernel, minimum) < 0 || compareVersions(kernel, maximum) >= 0 {
		return fmt.Errorf("kernel version %s is outside [%s, %s)", kernelVersion, compatibility.MinInclusive, compatibility.MaxExclusive)
	}
	return nil
}

func (manifest Manifest) digest() (string, error) {
	manifest.ManifestDigest = ""
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshal manifest digest input: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func signingInput(manifest Manifest) ([]byte, error) {
	return json.Marshal(manifest)
}

type version [3]uint64

func parseVersion(input string) (version, error) {
	parts := strings.Split(strings.TrimSpace(input), ".")
	if len(parts) != 3 {
		return version{}, fmt.Errorf("%q must have major.minor.patch", input)
	}
	var parsed version
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return version{}, fmt.Errorf("%q is not canonical", input)
		}
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return version{}, fmt.Errorf("%q is not numeric", input)
		}
		parsed[index] = value
	}
	return parsed, nil
}

func compareVersions(left, right version) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func validIdentifier(input string) bool {
	if input == "" || len(input) > 128 {
		return false
	}
	for _, char := range input {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-' || char == '_' || char == ':' {
			continue
		}
		return false
	}
	return true
}

func validDigest(input string) bool {
	if !strings.HasPrefix(input, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(input, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}
