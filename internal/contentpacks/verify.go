package contentpacks

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxManifestBytes = int64(256 << 10)

// VerifiedPack contains only declarative bytes that passed compatibility,
// allowlist, signature, path, size, and digest checks.
type VerifiedPack struct {
	Manifest Manifest
	Files    map[string][]byte
	Digest   string
}

func ReadAllowlist(path string) (Allowlist, error) {
	payload, err := readRegularFile(path, maxManifestBytes)
	if err != nil {
		return Allowlist{}, err
	}
	var allowlist Allowlist
	if err := decodeStrict(payload, &allowlist); err != nil {
		return Allowlist{}, fmt.Errorf("decode allowlist: %w", err)
	}
	if err := allowlist.validate(); err != nil {
		return Allowlist{}, err
	}
	return allowlist, nil
}

func VerifyDirectory(directory, kernelVersion, tenantID string, allowlist Allowlist) (VerifiedPack, error) {
	if err := allowlist.validate(); err != nil {
		return VerifiedPack{}, fmt.Errorf("validate allowlist: %w", err)
	}
	manifestPayload, err := readRegularFile(filepath.Join(directory, "manifest.json"), maxManifestBytes)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := decodeStrict(manifestPayload, &manifest); err != nil {
		return VerifiedPack{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := manifest.Validate(kernelVersion); err != nil {
		return VerifiedPack{}, fmt.Errorf("validate manifest: %w", err)
	}
	if err := allowlist.authorize(tenantID, manifest); err != nil {
		return VerifiedPack{}, err
	}
	publicKey, err := allowlist.publicKey(manifest.SigningKeyID)
	if err != nil {
		return VerifiedPack{}, err
	}
	signaturePayload, err := readRegularFile(filepath.Join(directory, "manifest.sig"), 4<<10)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("read manifest signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signaturePayload)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedPack{}, errors.New("manifest signature is not valid base64 Ed25519 data")
	}
	input, err := signingInput(manifest)
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("prepare signature input: %w", err)
	}
	if !ed25519.Verify(publicKey, input, signature) {
		return VerifiedPack{}, errors.New("manifest signature verification failed")
	}

	files := make(map[string][]byte, len(manifest.Contents))
	for _, content := range manifest.Contents {
		payload, err := readRegularFile(filepath.Join(directory, filepath.FromSlash(content.Path)), content.Bytes)
		if err != nil {
			return VerifiedPack{}, fmt.Errorf("read %s: %w", content.Path, err)
		}
		if int64(len(payload)) != content.Bytes {
			return VerifiedPack{}, fmt.Errorf("%s size mismatch: got %d, want %d", content.Path, len(payload), content.Bytes)
		}
		sum := sha256.Sum256(payload)
		gotDigest := "sha256:" + hex.EncodeToString(sum[:])
		if gotDigest != content.SHA256 {
			return VerifiedPack{}, fmt.Errorf("%s digest mismatch", content.Path)
		}
		files[content.ID] = payload
	}
	return VerifiedPack{Manifest: manifest, Files: files, Digest: manifest.ManifestDigest}, nil
}

func (allowlist Allowlist) validate() error {
	if allowlist.SchemaVersion != AllowlistSchemaV1 {
		return fmt.Errorf("unsupported allowlist schema %q", allowlist.SchemaVersion)
	}
	if strings.TrimSpace(allowlist.TenantID) == "" {
		return errors.New("allowlist tenant_id is required")
	}
	seenKeys := map[string]struct{}{}
	for index, key := range allowlist.Keys {
		if !validIdentifier(key.ID) {
			return fmt.Errorf("keys[%d].id is invalid", index)
		}
		if _, exists := seenKeys[key.ID]; exists {
			return fmt.Errorf("keys[%d].id %q is duplicated", index, key.ID)
		}
		seenKeys[key.ID] = struct{}{}
		decoded, err := base64.StdEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return fmt.Errorf("keys[%d].public_key_base64 is not an Ed25519 public key", index)
		}
	}
	seenPacks := map[string]struct{}{}
	for index, pack := range allowlist.Packs {
		if !validIdentifier(pack.PackID) {
			return fmt.Errorf("packs[%d].pack_id is invalid", index)
		}
		if _, exists := seenPacks[pack.PackID]; exists {
			return fmt.Errorf("packs[%d].pack_id %q is duplicated", index, pack.PackID)
		}
		seenPacks[pack.PackID] = struct{}{}
		if len(pack.Versions) == 0 || len(pack.Digests) == 0 || len(pack.KeyIDs) == 0 {
			return fmt.Errorf("packs[%d] must grant versions, digests, and key_ids", index)
		}
		for _, packVersion := range pack.Versions {
			if _, err := parseVersion(packVersion); err != nil {
				return fmt.Errorf("packs[%d] contains an invalid version: %w", index, err)
			}
		}
		for _, digest := range pack.Digests {
			if !validDigest(digest) {
				return fmt.Errorf("packs[%d] contains an invalid digest", index)
			}
		}
		for _, keyID := range pack.KeyIDs {
			if _, exists := seenKeys[keyID]; !exists {
				return fmt.Errorf("packs[%d] references unknown key_id %q", index, keyID)
			}
		}
	}
	return nil
}

func (allowlist Allowlist) authorize(tenantID string, manifest Manifest) error {
	if tenantID == "" || tenantID != allowlist.TenantID {
		return fmt.Errorf("tenant %q is not authorized by this allowlist", tenantID)
	}
	for _, allowed := range allowlist.Packs {
		if allowed.PackID != manifest.PackID {
			continue
		}
		if !contains(allowed.Versions, manifest.Version) {
			return fmt.Errorf("pack %s version %s is not allowlisted", manifest.PackID, manifest.Version)
		}
		if !contains(allowed.Digests, manifest.ManifestDigest) {
			return fmt.Errorf("pack %s digest is not allowlisted", manifest.PackID)
		}
		if !contains(allowed.KeyIDs, manifest.SigningKeyID) {
			return fmt.Errorf("pack %s signing key is not allowlisted", manifest.PackID)
		}
		return nil
	}
	return fmt.Errorf("pack %s is not allowlisted", manifest.PackID)
}

func (allowlist Allowlist) publicKey(keyID string) (ed25519.PublicKey, error) {
	for _, key := range allowlist.Keys {
		if key.ID != keyID {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(key.PublicKeyBase64)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signing key %s is invalid", keyID)
		}
		return ed25519.PublicKey(decoded), nil
	}
	return nil, fmt.Errorf("signing key %s is not trusted", keyID)
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("path must be a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	// #nosec G304 -- callers validate manifest paths and this helper rejects symlinks and non-regular files before opening.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return payload, nil
}

func decodeStrict(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("document must contain one JSON value")
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
