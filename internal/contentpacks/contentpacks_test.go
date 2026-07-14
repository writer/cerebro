package contentpacks

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyDirectoryAcceptsSignedAllowlistedData(t *testing.T) {
	directory, allowlist := signedPack(t, "pack.connector", "asset.family", 20)
	pack, err := VerifyDirectory(directory, "1.4.0", "tenant-a", allowlist)
	if err != nil {
		t.Fatalf("VerifyDirectory() error = %v", err)
	}
	if pack.Manifest.PackID != "pack.connector" || string(pack.Files["asset.family"]) != "id: family\n" {
		t.Fatalf("VerifyDirectory() pack = %#v", pack)
	}
}

func TestVerifyDirectoryFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		edit func(t *testing.T, directory string, allowlist *Allowlist)
	}{
		{
			name: "payload tampered",
			edit: func(t *testing.T, directory string, _ *Allowlist) {
				t.Helper()
				writeTestFile(t, filepath.Join(directory, "content", "family.yaml"), []byte("id: changed\n"))
			},
		},
		{
			name: "signature tampered",
			edit: func(t *testing.T, directory string, _ *Allowlist) {
				t.Helper()
				writeTestFile(t, filepath.Join(directory, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))))
			},
		},
		{
			name: "digest not allowlisted",
			edit: func(_ *testing.T, _ string, allowlist *Allowlist) {
				allowlist.Packs[0].Digests = []string{"sha256:" + strings.Repeat("0", 64)}
			},
		},
		{
			name: "tenant not allowlisted",
			edit: func(_ *testing.T, _ string, allowlist *Allowlist) {
				allowlist.TenantID = "tenant-b"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory, allowlist := signedPack(t, "pack.connector", "asset.family", 20)
			test.edit(t, directory, &allowlist)
			_, err := VerifyDirectory(directory, "1.4.0", "tenant-a", allowlist)
			if err == nil {
				t.Fatal("VerifyDirectory() error = nil, want rejection")
			}
		})
	}
}

func TestVerifyDirectoryRejectsIncompatibleKernel(t *testing.T) {
	directory, allowlist := signedPack(t, "pack.connector", "asset.family", 20)
	_, err := VerifyDirectory(directory, "2.0.0", "tenant-a", allowlist)
	if err == nil {
		t.Fatal("VerifyDirectory() error = nil, want incompatible kernel rejection")
	}
}

func TestResolveKeepsEmbeddedPackWhenExternalPackIsInvalid(t *testing.T) {
	directory, allowlist := signedPack(t, "pack.external", "asset.external", 20)
	writeTestFile(t, filepath.Join(directory, "manifest.sig"), []byte("invalid"))
	defaultPack := VerifiedPack{Manifest: Manifest{PackID: "pack.embedded", Kind: "connector", Contents: []Content{{ID: "asset.default"}}}}

	result, err := Resolve([]VerifiedPack{defaultPack}, []string{directory}, "1.4.0", "tenant-a", allowlist)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(result.Packs) != 1 || result.Packs[0].Manifest.PackID != "pack.embedded" {
		t.Fatalf("Resolve() packs = %#v", result.Packs)
	}
	if !result.UsingEmbeddedFallback || result.ExternalRejected != 1 || result.ExternalAccepted != 0 {
		t.Fatalf("Resolve() result = %#v", result)
	}
}

func TestResolveUsesDeterministicOrderAndRejectsContentConflict(t *testing.T) {
	directoryA, allowlistA := signedPack(t, "pack.a", "asset.same", 20)
	directoryB, allowlistB := signedPack(t, "pack.b", "asset.same", 10)
	allowlist := mergeAllowlists(t, allowlistA, allowlistB)

	result, err := Resolve(nil, []string{directoryA, directoryB}, "1.4.0", "tenant-a", allowlist)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(result.Packs) != 1 || result.Packs[0].Manifest.PackID != "pack.b" {
		t.Fatalf("Resolve() packs = %#v", result.Packs)
	}
	if result.ExternalAccepted != 1 || result.ExternalRejected != 1 || !strings.Contains(result.Rejected[0].Reason, "conflicts with pack pack.b") {
		t.Fatalf("Resolve() result = %#v", result)
	}
}

func signedPack(t *testing.T, packID, contentID string, order uint32) (string, Allowlist) {
	t.Helper()
	directory := t.TempDir()
	payload := []byte("id: family\n")
	sum := sha256.Sum256(payload)
	manifest := Manifest{
		SchemaVersion: ManifestSchemaV1,
		PackID:        packID,
		Version:       "1.0.0",
		SigningKeyID:  packID + ".key",
		Kind:          "connector",
		LoadOrder:     order,
		Kernel:        Compatibility{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"},
		Contents: []Content{{
			ID:        contentID,
			Path:      "content/family.yaml",
			MediaType: "application/yaml",
			SHA256:    "sha256:" + hex.EncodeToString(sum[:]),
			Bytes:     int64(len(payload)),
		}},
		Metadata: Metadata{Owner: "test", Certification: "test-only", GeneratedFrom: "fixture", RollbackBoundary: "allowlist"},
	}
	digest, err := manifest.digest()
	if err != nil {
		t.Fatalf("digest() error = %v", err)
	}
	manifest.ManifestDigest = digest
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	input, err := signingInput(manifest)
	if err != nil {
		t.Fatalf("signingInput() error = %v", err)
	}
	manifestPayload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	writeTestFile(t, filepath.Join(directory, "manifest.json"), manifestPayload)
	writeTestFile(t, filepath.Join(directory, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, input))))
	writeTestFile(t, filepath.Join(directory, "content", "family.yaml"), payload)
	return directory, Allowlist{
		SchemaVersion: AllowlistSchemaV1,
		TenantID:      "tenant-a",
		Keys:          []TrustedKey{{ID: manifest.SigningKeyID, PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey)}},
		Packs: []AllowedPack{{
			PackID:   packID,
			Versions: []string{manifest.Version},
			Digests:  []string{manifest.ManifestDigest},
			KeyIDs:   []string{manifest.SigningKeyID},
		}},
	}
}

func mergeAllowlists(t *testing.T, allowlists ...Allowlist) Allowlist {
	t.Helper()
	merged := Allowlist{SchemaVersion: AllowlistSchemaV1, TenantID: "tenant-a"}
	for _, allowlist := range allowlists {
		merged.Keys = append(merged.Keys, allowlist.Keys...)
		merged.Packs = append(merged.Packs, allowlist.Packs...)
	}
	if err := merged.validate(); err != nil {
		t.Fatalf("merged allowlist invalid: %v", err)
	}
	return merged
}

func writeTestFile(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", path, err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
