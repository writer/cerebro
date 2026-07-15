package contentpacks

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
)

// FinalizeManifest computes immutable content sizes and digests. Release tooling
// signs the returned manifest; runtime code never calls this function.
func FinalizeManifest(directory string, manifest Manifest) (Manifest, error) {
	sort.Slice(manifest.Contents, func(i, j int) bool { return manifest.Contents[i].ID < manifest.Contents[j].ID })
	for index := range manifest.Contents {
		content := &manifest.Contents[index]
		payload, err := readRegularFile(filepath.Join(directory, filepath.FromSlash(content.Path)), maxFileBytes)
		if err != nil {
			return Manifest{}, fmt.Errorf("read %s: %w", content.Path, err)
		}
		sum := sha256.Sum256(payload)
		content.Bytes = int64(len(payload))
		content.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	}
	digest, err := manifest.digest()
	if err != nil {
		return Manifest{}, err
	}
	manifest.ManifestDigest = digest
	if err := manifest.Validate(manifest.Kernel.MinInclusive); err != nil {
		return Manifest{}, fmt.Errorf("validate finalized manifest: %w", err)
	}
	return manifest, nil
}

func MarshalManifest(manifest Manifest) ([]byte, error) {
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return append(payload, '\n'), nil
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key must be %d bytes", ed25519.PrivateKeySize)
	}
	input, err := signingInput(manifest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, input)) + "\n", nil
}
