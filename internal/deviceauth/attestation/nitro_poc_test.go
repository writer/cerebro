package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestNitroPOCVerifierBindsMeasurementNonceAndKey(t *testing.T) {
	measurement := strings.Repeat("a", 96)
	verifier, err := NewNitroPOCVerifier(NitroPOCConfig{Measurements: []string{measurement}})
	if err != nil {
		t.Fatalf("NewNitroPOCVerifier() error = %v", err)
	}
	clientHash := sha256.Sum256([]byte("collector-enroll"))
	pubDER := testPublicKeyDER(t)
	statement := testNitroPOCStatement(t, nitroPOCStatement{
		ModuleID:    "collector",
		ImageSHA384: measurement,
		PublicKey:   base64.StdEncoding.EncodeToString(pubDER),
		Nonce:       base64.StdEncoding.EncodeToString(clientHash[:]),
	})
	result, err := verifier.Verify(context.Background(), Input{
		ClientDataHash: clientHash,
		Format:         FormatAWSNitroEnclavePOC,
		Statement:      statement,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.AssuranceLevel != "software" || result.Vendor != FormatAWSNitroEnclavePOC {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.PublicKey) == 0 || result.KeyID == "" {
		t.Fatalf("attested key was not bound: %+v", result)
	}
	if result.Diagnostics["image_sha384"] != measurement {
		t.Fatalf("image_sha384 diagnostic = %q", result.Diagnostics["image_sha384"])
	}
}

func TestNitroPOCVerifierRejectsUnexpectedMeasurement(t *testing.T) {
	verifier, err := NewNitroPOCVerifier(NitroPOCConfig{Measurements: []string{strings.Repeat("a", 96)}})
	if err != nil {
		t.Fatalf("NewNitroPOCVerifier() error = %v", err)
	}
	clientHash := sha256.Sum256([]byte("collector-enroll"))
	pubDER := testPublicKeyDER(t)
	statement := testNitroPOCStatement(t, nitroPOCStatement{
		ImageSHA384: strings.Repeat("b", 96),
		PublicKey:   base64.StdEncoding.EncodeToString(pubDER),
		Nonce:       base64.StdEncoding.EncodeToString(clientHash[:]),
	})
	if _, err := verifier.Verify(context.Background(), Input{ClientDataHash: clientHash, Format: FormatAWSNitroEnclavePOC, Statement: statement}); err == nil {
		t.Fatalf("Verify() error = nil, want measurement rejection")
	}
}

func TestNitroPOCVerifierRejectsNonceMismatch(t *testing.T) {
	measurement := strings.Repeat("a", 96)
	verifier, err := NewNitroPOCVerifier(NitroPOCConfig{Measurements: []string{measurement}})
	if err != nil {
		t.Fatalf("NewNitroPOCVerifier() error = %v", err)
	}
	clientHash := sha256.Sum256([]byte("collector-enroll"))
	wrongHash := sha256.Sum256([]byte("wrong"))
	pubDER := testPublicKeyDER(t)
	statement := testNitroPOCStatement(t, nitroPOCStatement{
		ImageSHA384: measurement,
		PublicKey:   base64.StdEncoding.EncodeToString(pubDER),
		Nonce:       base64.StdEncoding.EncodeToString(wrongHash[:]),
	})
	if _, err := verifier.Verify(context.Background(), Input{ClientDataHash: clientHash, Format: FormatAWSNitroEnclavePOC, Statement: statement}); err == nil {
		t.Fatalf("Verify() error = nil, want nonce rejection")
	}
}

func testPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return der
}

func testNitroPOCStatement(t *testing.T, statement nitroPOCStatement) string {
	t.Helper()
	body, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	return base64.StdEncoding.EncodeToString(body)
}
