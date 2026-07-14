package grcauditverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func DigestRequest(manifest RequestManifest) (string, error) {
	manifest.Digest, manifest.Signature = "", nil
	return digestJSON(manifest)
}

func DigestDisclosure(manifest DisclosureManifest) (string, error) {
	manifest.Digest, manifest.Signature = "", nil
	return digestJSON(manifest)
}

func DigestPopulation(manifest PopulationManifest) (string, error) {
	manifest.Digest, manifest.Signature = "", nil
	return digestJSON(manifest)
}

func DigestSample(manifest SampleManifest) (string, error) {
	manifest.Digest, manifest.Signature = "", nil
	return digestJSON(manifest)
}

func DigestCitation(citation Citation) string {
	citation.Digest = ""
	payload, err := json.Marshal(citation)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func DigestExternalField(value json.RawMessage) string {
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return ""
	}
	payload, err := json.Marshal(decoded)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal manifest digest payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func verifySignature(signature *ManifestSignature, digest string, trustedKeys map[string]string) error {
	if signature == nil {
		return nil
	}
	if signature.Algorithm != SignatureAlgorithmEd25519 || signature.KeyID == "" || signature.SignedDigest != digest {
		return fmt.Errorf("signature metadata does not bind the manifest digest")
	}
	encodedPublicKey := trustedKeys[signature.KeyID]
	if encodedPublicKey == "" {
		return fmt.Errorf("signature key is not trusted")
	}
	publicKey, err := base64.StdEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("decode ed25519 public key")
	}
	signed, err := base64.StdEncoding.DecodeString(signature.SignatureBase64)
	if err != nil || len(signed) != ed25519.SignatureSize {
		return fmt.Errorf("decode ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(digest), signed) {
		return fmt.Errorf("ed25519 signature verification failed")
	}
	return nil
}
