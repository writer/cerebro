package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

type tpmRoot struct {
	pool     *x509.CertPool
	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey
	rootDER  []byte
	leafCert *x509.Certificate
	leafDER  []byte
}

func mintTPMRoot(t *testing.T) tpmRoot {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TPM Vendor Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test EK Cert"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return tpmRoot{pool: pool, rootCert: rootCert, rootKey: rootKey, rootDER: rootDER, leafCert: leafCert, leafDER: leafDER}
}

func TestTPMVerifyRSA(t *testing.T) {
	root := mintTPMRoot(t)
	akKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPubDER, _ := x509.MarshalPKIXPublicKey(&akKey.PublicKey)

	clientHash := sha256.Sum256([]byte("client-data"))
	quote := append([]byte("TPMS_ATTEST"), clientHash[:]...)
	digest := sha256.Sum256(quote)
	sig, err := rsa.SignPKCS1v15(rand.Reader, akKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	stmt, _ := json.Marshal(map[string]string{
		"ek_chain":   base64.StdEncoding.EncodeToString(root.leafDER),
		"ak_pub_der": base64.StdEncoding.EncodeToString(akPubDER),
		"quote":      base64.StdEncoding.EncodeToString(quote),
		"signature":  base64.StdEncoding.EncodeToString(sig),
		"alg":        "RSA-SHA256",
	})
	// Re-encode with full ek_chain array shape:
	bundle, _ := json.Marshal(map[string]any{
		"ek_chain":   []string{base64.StdEncoding.EncodeToString(root.leafDER), base64.StdEncoding.EncodeToString(root.rootDER)},
		"ak_pub_der": base64.StdEncoding.EncodeToString(akPubDER),
		"quote":      base64.StdEncoding.EncodeToString(quote),
		"signature":  base64.StdEncoding.EncodeToString(sig),
		"alg":        "RSA-SHA256",
	})
	_ = stmt

	v, err := NewTPMVerifier(TPMConfig{Roots: root.pool, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Verify(context.Background(), Input{
		Format:         "windows",
		Statement:      base64.StdEncoding.EncodeToString(bundle),
		ClientDataHash: clientHash,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.AssuranceLevel != "hardware" {
		t.Errorf("assurance=%q", res.AssuranceLevel)
	}
	if res.Vendor != FormatTPM2 {
		t.Errorf("vendor=%q", res.Vendor)
	}
}

func TestTPMVerifyECDSA(t *testing.T) {
	root := mintTPMRoot(t)
	akKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	akPubDER, _ := x509.MarshalPKIXPublicKey(&akKey.PublicKey)
	clientHash := sha256.Sum256([]byte("client-data-2"))
	quote := append([]byte("TPMS_ATTEST"), clientHash[:]...)
	digest := sha256.Sum256(quote)
	sig, err := ecdsa.SignASN1(rand.Reader, akKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(map[string]any{
		"ek_chain":   []string{base64.StdEncoding.EncodeToString(root.leafDER), base64.StdEncoding.EncodeToString(root.rootDER)},
		"ak_pub_der": base64.StdEncoding.EncodeToString(akPubDER),
		"quote":      base64.StdEncoding.EncodeToString(quote),
		"signature":  base64.StdEncoding.EncodeToString(sig),
		"alg":        "ECDSA-SHA256",
	})
	v, _ := NewTPMVerifier(TPMConfig{Roots: root.pool, Clock: time.Now})
	res, err := v.Verify(context.Background(), Input{
		Format: "windows", Statement: base64.StdEncoding.EncodeToString(bundle), ClientDataHash: clientHash,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.PublicKey == nil {
		t.Errorf("public key nil")
	}
}

func TestTPMRejectsBadSignature(t *testing.T) {
	root := mintTPMRoot(t)
	akKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPubDER, _ := x509.MarshalPKIXPublicKey(&akKey.PublicKey)
	clientHash := sha256.Sum256([]byte("x"))
	quote := append([]byte("TPMS_ATTEST"), clientHash[:]...)
	bundle, _ := json.Marshal(map[string]any{
		"ek_chain":   []string{base64.StdEncoding.EncodeToString(root.leafDER), base64.StdEncoding.EncodeToString(root.rootDER)},
		"ak_pub_der": base64.StdEncoding.EncodeToString(akPubDER),
		"quote":      base64.StdEncoding.EncodeToString(quote),
		"signature":  base64.StdEncoding.EncodeToString([]byte("garbage")),
		"alg":        "RSA-SHA256",
	})
	v, _ := NewTPMVerifier(TPMConfig{Roots: root.pool, Clock: time.Now})
	_, err := v.Verify(context.Background(), Input{
		Format: "windows", Statement: base64.StdEncoding.EncodeToString(bundle), ClientDataHash: clientHash,
	})
	if err == nil {
		t.Fatal("expected sig failure")
	}
}

func TestTPMRejectsMissingClientHash(t *testing.T) {
	root := mintTPMRoot(t)
	akKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPubDER, _ := x509.MarshalPKIXPublicKey(&akKey.PublicKey)
	wrongHash := sha256.Sum256([]byte("wrong"))
	rightHash := sha256.Sum256([]byte("right"))
	quote := append([]byte("TPMS_ATTEST"), wrongHash[:]...)
	digest := sha256.Sum256(quote)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, akKey, crypto.SHA256, digest[:])
	bundle, _ := json.Marshal(map[string]any{
		"ek_chain":   []string{base64.StdEncoding.EncodeToString(root.leafDER), base64.StdEncoding.EncodeToString(root.rootDER)},
		"ak_pub_der": base64.StdEncoding.EncodeToString(akPubDER),
		"quote":      base64.StdEncoding.EncodeToString(quote),
		"signature":  base64.StdEncoding.EncodeToString(sig),
		"alg":        "RSA-SHA256",
	})
	v, _ := NewTPMVerifier(TPMConfig{Roots: root.pool, Clock: time.Now})
	_, err := v.Verify(context.Background(), Input{
		Format: "windows", Statement: base64.StdEncoding.EncodeToString(bundle), ClientDataHash: rightHash,
	})
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("err=%v want ErrNonceMismatch", err)
	}
}
