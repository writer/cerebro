package cloudidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// digestJSON hashes encoding/json's representation of a value. Map keys are
// sorted; struct field order and raw JSON member order are preserved.
// Encoding failures are errors, never fabricated content digests.
func digestJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("cloudidentity: digest non-JSON value: %w", err)
	}
	return digestPayload(payload), nil
}

// DigestJSON hashes already-serialized JSON without copying or re-encoding it.
// Callers use json.Marshal on typed values before crossing this boundary to
// preserve the historical JSON encoding used for content identities.
func DigestJSON(payload json.RawMessage) (string, error) {
	if !json.Valid(payload) {
		return "", errors.New("cloudidentity: digest invalid JSON payload")
	}
	return digestPayload(payload), nil
}

func digestPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestBytes preserves the historical base64-JSON encoding of byte content.
// Encoding a byte slice cannot fail.
func DigestBytes(content []byte) string {
	digest, _ := digestJSON(content)
	return digest
}

// DigestString preserves the historical quoted-JSON encoding of strings.
// Encoding a string cannot fail.
func DigestString(s string) string {
	digest, _ := digestJSON(s)
	return digest
}

// repositoryFileDigest is the canonical per-file entry RepositoryDigest
// hashes: Path paired with a digest always derived from the file's actual
// content bytes, never a possibly-wrong caller-supplied string.
type repositoryFileDigest struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// RepositoryDigest hashes sorted (path, content digest) pairs. Each digest is
// computed from actual bytes, never from the caller-supplied SourceFile.Digest.
func RepositoryDigest(files []SourceFile) (string, error) {
	canonical := make([]repositoryFileDigest, len(files))
	for i, file := range files {
		canonical[i] = repositoryFileDigest{Path: file.Path, Digest: DigestBytes(file.Content)}
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Path < canonical[j].Path })
	return digestJSON(canonical)
}
