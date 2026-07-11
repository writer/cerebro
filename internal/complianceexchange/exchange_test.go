package complianceexchange

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var exchangeTestTime = time.Date(2026, time.July, 11, 12, 30, 0, 123456000, time.UTC)

func TestBuildDeterministicManifestAndCompleteCoverage(t *testing.T) {
	signer, trust := newEd25519Fixture(t, "package-key-1")
	request := BuildRequest{
		PackageID: "package-1", TenantID: "tenant-1", CreatedAt: exchangeTestTime,
		DisclosurePolicy: "auditor", RedactionMode: "external",
		Files: []File{
			{Path: "data/evidence/access.json", MediaType: "application/json", LogicalType: "evidence", Data: []byte(`{"state":"current"}`)},
			{Path: "data/oscal/results.json", MediaType: "application/oscal+json", LogicalType: "assessment-results", Data: []byte(`{"assessment-results":{}}`)},
		},
	}
	first, err := Build(context.Background(), request, signer)
	if err != nil {
		t.Fatalf("Build(first): %v", err)
	}
	request.Files[0], request.Files[1] = request.Files[1], request.Files[0]
	second, err := Build(context.Background(), request, signer)
	if err != nil {
		t.Fatalf("Build(second): %v", err)
	}
	if !bytes.Equal(first.ManifestBytes, second.ManifestBytes) {
		t.Fatalf("manifest bytes differ by input order:\n%s\n%s", first.ManifestBytes, second.ManifestBytes)
	}
	if first.ManifestDigest != second.ManifestDigest || first.Signature != second.Signature {
		t.Fatalf("deterministic digest/signature mismatch: %q/%q vs %q/%q", first.ManifestDigest, first.Signature, second.ManifestDigest, second.Signature)
	}
	if got := []string{first.Manifest.Files[0].Path, first.Manifest.Files[1].Path}; got[0] != "data/evidence/access.json" || got[1] != "data/oscal/results.json" {
		t.Fatalf("manifest paths = %v, want canonical order", got)
	}
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: first.ManifestBytes,
		Signature: first.Signature, Files: first.Files, Trust: trust,
	})
	if result.Status != ValidationValid || len(result.Issues) != 0 || result.ChangePlan == nil {
		t.Fatalf("validation = %+v, want valid change plan", result)
	}
	if result.ChangePlan.ManifestDigest != first.ManifestDigest || len(result.ChangePlan.Operations) != 2 {
		t.Fatalf("change plan = %+v", result.ChangePlan)
	}
}

func TestBuildCopiesFileBytesBeforeDigesting(t *testing.T) {
	signer, _ := newEd25519Fixture(t, "package-key-1")
	data := []byte("original")
	built, err := Build(context.Background(), BuildRequest{
		PackageID: "package-1", TenantID: "tenant-1", CreatedAt: exchangeTestTime,
		Files: []File{{Path: "data/item.txt", MediaType: "text/plain", LogicalType: "evidence", Data: data}},
	}, signer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	data[0] = 'X'
	if string(built.Files[0].Data) != "original" {
		t.Fatalf("built file = %q, want immutable copy", built.Files[0].Data)
	}
}

func TestValidateRejectsAlteredAttachment(t *testing.T) {
	fixture := buildFixture(t)
	files := cloneFiles(fixture.built.Files)
	files[0].Data = []byte("altered")
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: fixture.built.ManifestBytes,
		Signature: fixture.built.Signature, Files: files, Trust: fixture.trust,
	})
	assertIssue(t, result, "file_digest_mismatch")
	if result.ChangePlan != nil {
		t.Fatal("invalid package received a change plan")
	}
}

func TestValidateRejectsTraversalAndUnexpectedPayload(t *testing.T) {
	fixture := buildFixture(t)
	files := append(cloneFiles(fixture.built.Files), File{
		Path: "../private.txt", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("secret"),
	})
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: fixture.built.ManifestBytes,
		Signature: fixture.built.Signature, Files: files, Trust: fixture.trust,
	})
	assertIssue(t, result, "unsafe_path")
}

func TestValidateRejectsDuplicateAndCaseCollidingPayloadPaths(t *testing.T) {
	fixture := buildFixture(t)
	duplicate := fixture.built.Files[0]
	duplicate.Path = strings.ToUpper(duplicate.Path)
	files := append(cloneFiles(fixture.built.Files), duplicate)
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: fixture.built.ManifestBytes,
		Signature: fixture.built.Signature, Files: files, Trust: fixture.trust,
	})
	assertIssue(t, result, "duplicate_path")
}

func TestValidateRejectsDuplicateManifestPath(t *testing.T) {
	fixture := buildFixture(t)
	manifest := fixture.built.Manifest
	duplicate := manifest.Files[0]
	duplicate.Path = strings.ToUpper(duplicate.Path)
	manifest.Files = append(manifest.Files, duplicate)
	manifest.FileCount++
	manifest.TotalBytes += duplicate.SizeBytes
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignDetached(context.Background(), manifestBytes, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: manifestBytes,
		Signature: signature, Files: fixture.built.Files, Trust: fixture.trust,
	})
	assertIssue(t, result, "duplicate_manifest_path")
}

func TestValidateRejectsMissingAndUnexpectedFile(t *testing.T) {
	fixture := buildFixture(t)
	files := []File{{Path: "data/other.json", MediaType: "application/json", LogicalType: "evidence", Data: []byte(`{}`)}}
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: fixture.built.ManifestBytes,
		Signature: fixture.built.Signature, Files: files, Trust: fixture.trust,
	})
	assertIssue(t, result, "payload_file_missing")
	assertIssue(t, result, "unexpected_payload_file")
}

func TestValidateRejectsTenantMismatchBeforeChangePlan(t *testing.T) {
	fixture := buildFixture(t)
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-2", ManifestBytes: fixture.built.ManifestBytes,
		Signature: fixture.built.Signature, Files: fixture.built.Files, Trust: fixture.trust,
	})
	assertIssue(t, result, "tenant_mismatch")
}

func TestValidateRejectsAlteredManifestSignature(t *testing.T) {
	fixture := buildFixture(t)
	manifest := fixture.built.Manifest
	manifest.RedactionMode = "changed-after-signing"
	altered, err := marshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: altered,
		Signature: fixture.built.Signature, Files: fixture.built.Files, Trust: fixture.trust,
	})
	assertIssue(t, result, "signature_invalid")
}

func TestValidateDoesNotResolveRemoteKeysFromSignature(t *testing.T) {
	fixture := buildFixture(t)
	called := 0
	trust := TrustResolverFunc(func(_ context.Context, keyID string, algorithm string) (crypto.PublicKey, error) {
		called++
		if keyID != "package-key-1" || algorithm != AlgorithmEdDSA {
			t.Fatalf("resolver args = %q/%q", keyID, algorithm)
		}
		return nil, errors.New("not configured")
	})
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: fixture.built.ManifestBytes,
		Signature: fixture.built.Signature, Files: fixture.built.Files, Trust: trust,
	})
	assertIssue(t, result, "signature_invalid")
	if called != 1 {
		t.Fatalf("resolver calls = %d, want 1", called)
	}
}

func TestValidateRejectsRemoteKeyHeaderWithoutCallingResolver(t *testing.T) {
	fixture := buildFixture(t)
	parts := strings.Split(fixture.built.Signature, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"package-key-1","typ":"compliance-manifest+jws","jku":"https://keys.invalid"}`))
	called := false
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: fixture.built.ManifestBytes,
		Signature: strings.Join(parts, "."), Files: fixture.built.Files,
		Trust: TrustResolverFunc(func(context.Context, string, string) (crypto.PublicKey, error) {
			called = true
			return nil, errors.New("must not be called")
		}),
	})
	assertIssue(t, result, "signature_invalid")
	if called {
		t.Fatal("trust resolver called for a signature header containing an unsupported remote-key field")
	}
}

func TestValidateES256RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := CryptoSigner{AlgorithmName: AlgorithmES256, KeyIDValue: "p256-key-1", PrivateKey: key}
	built, err := Build(context.Background(), fixtureBuildRequest(), signer)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: built.ManifestBytes,
		Signature: built.Signature, Files: built.Files,
		Trust: TrustResolverFunc(func(_ context.Context, keyID string, algorithm string) (crypto.PublicKey, error) {
			if keyID != "p256-key-1" || algorithm != AlgorithmES256 {
				return nil, errors.New("unexpected key")
			}
			return &key.PublicKey, nil
		}),
	})
	if result.Status != ValidationValid {
		t.Fatalf("validation = %+v", result)
	}
}

func TestBuildRejectsUnsafePathsDuplicatesAndLimits(t *testing.T) {
	signer, _ := newEd25519Fixture(t, "package-key-1")
	tests := []struct {
		name   string
		files  []File
		limits Limits
	}{
		{name: "traversal", files: []File{{Path: "data/../secret", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("x")}}},
		{name: "backslash", files: []File{{Path: `data\secret`, MediaType: "text/plain", LogicalType: "evidence", Data: []byte("x")}}},
		{name: "volume", files: []File{{Path: "C:/secret", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("x")}}},
		{name: "control character", files: []File{{Path: "data/a\tb", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("x")}}},
		{name: "reserved", files: []File{{Path: "manifest.json", MediaType: "application/json", LogicalType: "manifest", Data: []byte("x")}}},
		{name: "duplicates", files: []File{
			{Path: "data/A", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("x")},
			{Path: "data/a", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("x")},
		}},
		{name: "file limit", files: []File{{Path: "data/a", MediaType: "text/plain", LogicalType: "evidence", Data: []byte("xx")}}, limits: Limits{MaxFiles: 1, MaxFileBytes: 1, MaxTotalBytes: 1, MaxPathBytes: 20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Build(context.Background(), BuildRequest{
				PackageID: "package-1", TenantID: "tenant-1", CreatedAt: exchangeTestTime,
				Files: tt.files, Limits: tt.limits,
			}, signer)
			if !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("Build error = %v, want ErrInvalidPackage", err)
			}
		})
	}
}

func TestValidateBoundsManifestAndSignatureBeforeParsing(t *testing.T) {
	limits := Limits{
		MaxFiles: 1, MaxFileBytes: 16, MaxTotalBytes: 16, MaxPathBytes: 32,
		MaxManifestBytes: 2, MaxSignatureBytes: 2,
	}
	manifestResult := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: []byte(`{}` + " "), Limits: limits,
	})
	assertIssue(t, manifestResult, "manifest_size_limit")

	limits.MaxManifestBytes = 4
	signatureResult := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-1", ManifestBytes: []byte(`{}`), Signature: "abc", Limits: limits,
	})
	assertIssue(t, signatureResult, "signature_size_limit")
}

func TestSignDetachedRejectsUnapprovedAlgorithm(t *testing.T) {
	signer := staticSigner{algorithm: "none", keyID: "key-1", signature: []byte("invalid")}
	if _, err := SignDetached(context.Background(), []byte(`{}`), signer); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("SignDetached error = %v, want unsupported algorithm", err)
	}
}

func TestBuildRejectsInvalidPredecessorAndSignatureShape(t *testing.T) {
	signer, _ := newEd25519Fixture(t, "package-key-1")
	request := fixtureBuildRequest()
	request.PredecessorDigest = "sha256:not-a-digest"
	if _, err := Build(context.Background(), request, signer); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("Build predecessor error = %v, want ErrInvalidPackage", err)
	}

	request.PredecessorDigest = ""
	badSigner := staticSigner{algorithm: AlgorithmEdDSA, keyID: "key-1", signature: []byte("short")}
	if _, err := Build(context.Background(), request, badSigner); err == nil {
		t.Fatal("Build accepted a malformed signature")
	}
}

func TestDecodeManifestRejectsUnknownAndTrailingFields(t *testing.T) {
	for _, content := range []string{
		`{"schema_version":"compliance-exchange-manifest/v1","unknown":true}`,
		`{} {}`,
	} {
		if _, err := decodeManifest([]byte(content)); err == nil {
			t.Fatalf("decodeManifest(%q) error = nil", content)
		}
	}
}

func TestValidationIssuesHaveDeterministicOrder(t *testing.T) {
	fixture := buildFixture(t)
	result := Validate(context.Background(), ValidationRequest{
		ExpectedTenantID: "tenant-2", ManifestBytes: fixture.built.ManifestBytes,
		Files: []File{{Path: "../x", Data: []byte("x")}},
	})
	for index := 1; index < len(result.Issues); index++ {
		left := validationLayerOrder[result.Issues[index-1].Layer]
		right := validationLayerOrder[result.Issues[index].Layer]
		if left > right {
			t.Fatalf("issues out of order: %+v", result.Issues)
		}
	}
}

type staticSigner struct {
	algorithm string
	keyID     string
	signature []byte
}

func (s staticSigner) Algorithm() string { return s.algorithm }
func (s staticSigner) KeyID() string     { return s.keyID }
func (s staticSigner) Sign(context.Context, []byte) ([]byte, error) {
	return s.signature, nil
}

type packageFixture struct {
	built  Package
	signer CryptoSigner
	trust  TrustResolver
}

func buildFixture(t *testing.T) packageFixture {
	t.Helper()
	signer, trust := newEd25519Fixture(t, "package-key-1")
	built, err := Build(context.Background(), fixtureBuildRequest(), signer)
	if err != nil {
		t.Fatalf("Build fixture: %v", err)
	}
	return packageFixture{built: built, signer: signer, trust: trust}
}

func fixtureBuildRequest() BuildRequest {
	return BuildRequest{
		PackageID: "package-1", TenantID: "tenant-1", CreatedAt: exchangeTestTime,
		PredecessorDigest: strings.Repeat("a", 64),
		Files: []File{{
			Path: "data/evidence.json", MediaType: "application/json",
			LogicalType: "evidence", Data: []byte(`{"state":"current"}`),
		}},
	}
}

func newEd25519Fixture(t *testing.T, keyID string) (CryptoSigner, TrustResolver) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := CryptoSigner{AlgorithmName: AlgorithmEdDSA, KeyIDValue: keyID, PrivateKey: private}
	trust := TrustResolverFunc(func(_ context.Context, requestedKeyID string, algorithm string) (crypto.PublicKey, error) {
		if requestedKeyID != keyID || algorithm != AlgorithmEdDSA {
			return nil, errors.New("key not trusted")
		}
		return public, nil
	})
	return signer, trust
}

func cloneFiles(files []File) []File {
	cloned := make([]File, len(files))
	for index, file := range files {
		file.Data = bytes.Clone(file.Data)
		cloned[index] = file
	}
	return cloned
}

func assertIssue(t *testing.T, result ValidationResult, code string) {
	t.Helper()
	for _, issue := range result.Issues {
		if issue.Code == code {
			return
		}
	}
	content, _ := json.Marshal(result.Issues)
	t.Fatalf("issues = %s, want code %q", content, code)
}
