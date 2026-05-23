package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"
)

type appleRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
	pool *x509.CertPool
}

func mintAppleRoot(t *testing.T) appleRoot {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Apple Root"},
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
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return appleRoot{cert: rootCert, key: rootKey, der: rootDER, pool: pool}
}

// mintAppleLeaf builds a leaf credCert signed by root, with the supplied
// nonce embedded in the 1.2.840.113635.100.8.2 extension.
func mintAppleLeaf(t *testing.T, root appleRoot, leafKey *ecdsa.PrivateKey, nonce []byte) []byte {
	t.Helper()
	extVal, err := asn1.Marshal(nonce)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Apple AppAttest CredCert"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2},
			Value: extVal,
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root.cert, &leafKey.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER
}

func buildAuthData(t *testing.T, teamID, bundleID string, credID []byte) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(teamID + "." + bundleID))
	out := make([]byte, 0, 32+1+4+16+2+len(credID))
	out = append(out, rpHash[:]...)
	out = append(out, 0x40)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0)
	out = append(out, counter...)
	aaguid := make([]byte, 16)
	out = append(out, aaguid...)
	credIDLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLenBytes, uint16(len(credID)))
	out = append(out, credIDLenBytes...)
	out = append(out, credID...)
	return out
}

func TestAppleAppAttestRoundTrip(t *testing.T) {
	teamID := "TEAM1"
	bundleID := "com.writer.secheck"
	clientHash := sha256.Sum256([]byte("bootstrap-token-1"))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xy := mustP256XY(t, &leafKey.PublicKey)
	credID := sha256.Sum256(xy)
	authData := buildAuthData(t, teamID, bundleID, credID[:])
	nonceHasher := sha256.New()
	nonceHasher.Write(authData)
	nonceHasher.Write(clientHash[:])
	nonce := nonceHasher.Sum(nil)

	root := mintAppleRoot(t)
	leafDER := mintAppleLeaf(t, root, leafKey, nonce)

	att, err := encodeCBORMap([][2]any{
		{"fmt", FormatAppleAppAttest},
		{"attStmt", [][2]any{
			{"x5c", [][]byte{leafDER, root.der}},
			{"receipt", []byte{}},
		}},
		{"authData", authData},
	})
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewAppleAppAttestVerifier(AppleConfig{
		Roots:     root.pool,
		BundleIDs: []string{bundleID},
		TeamID:    teamID,
		Clock:     time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := v.Verify(context.Background(), Input{
		Format:         "darwin",
		Statement:      base64.StdEncoding.EncodeToString(att),
		ClientDataHash: clientHash,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.AssuranceLevel != "hardware" {
		t.Errorf("assurance=%q want hardware", res.AssuranceLevel)
	}
	if res.PublicKey == nil {
		t.Errorf("public key nil")
	}
	if res.Vendor != FormatAppleAppAttest {
		t.Errorf("vendor=%q", res.Vendor)
	}
}

func TestAppleAppAttestRejectsTamperedClientDataHash(t *testing.T) {
	teamID, bundleID := "TEAM1", "com.writer.secheck"
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := sha256.Sum256(mustP256XY(t, &leafKey.PublicKey))
	authData := buildAuthData(t, teamID, bundleID, credID[:])
	originalHash := sha256.Sum256([]byte("real"))
	nh := sha256.New()
	nh.Write(authData)
	nh.Write(originalHash[:])
	root := mintAppleRoot(t)
	leafDER := mintAppleLeaf(t, root, leafKey, nh.Sum(nil))
	att, _ := encodeCBORMap([][2]any{
		{"fmt", FormatAppleAppAttest},
		{"attStmt", [][2]any{{"x5c", [][]byte{leafDER, root.der}}, {"receipt", []byte{}}}},
		{"authData", authData},
	})
	v, _ := NewAppleAppAttestVerifier(AppleConfig{
		Roots: root.pool, BundleIDs: []string{bundleID}, TeamID: teamID, Clock: time.Now,
	})
	tamperedHash := sha256.Sum256([]byte("DIFFERENT"))
	_, err := v.Verify(context.Background(), Input{
		Format: "darwin", Statement: base64.StdEncoding.EncodeToString(att), ClientDataHash: tamperedHash,
	})
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("err=%v want ErrNonceMismatch", err)
	}
}

func TestAppleAppAttestRejectsBadChain(t *testing.T) {
	v, _ := NewAppleAppAttestVerifier(AppleConfig{
		Roots: x509.NewCertPool(), BundleIDs: []string{"x"}, TeamID: "T", Clock: time.Now,
	})
	_, err := v.Verify(context.Background(), Input{Format: "darwin", Statement: "bm9wZQ=="})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRegistryFallbackWhenNotRequired(t *testing.T) {
	r := NewRegistry(false)
	res, err := r.Verify(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if res.AssuranceLevel != "software" {
		t.Errorf("assurance=%q", res.AssuranceLevel)
	}
}

func TestRegistryRequiredRejectsEmpty(t *testing.T) {
	r := NewRegistry(true)
	if _, err := r.Verify(context.Background(), Input{}); !errors.Is(err, ErrAttestationRequired) {
		t.Fatalf("err=%v", err)
	}
}

func TestRegistryDispatch(t *testing.T) {
	teamID, bundleID := "TEAM1", "com.writer.secheck"
	clientHash := sha256.Sum256([]byte("hello"))
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := sha256.Sum256(mustP256XY(t, &leafKey.PublicKey))
	authData := buildAuthData(t, teamID, bundleID, credID[:])
	nh := sha256.New()
	nh.Write(authData)
	nh.Write(clientHash[:])
	root := mintAppleRoot(t)
	leafDER := mintAppleLeaf(t, root, leafKey, nh.Sum(nil))
	att, _ := encodeCBORMap([][2]any{
		{"fmt", FormatAppleAppAttest},
		{"attStmt", [][2]any{{"x5c", [][]byte{leafDER, root.der}}, {"receipt", []byte{}}}},
		{"authData", authData},
	})
	apple, _ := NewAppleAppAttestVerifier(AppleConfig{
		Roots: root.pool, BundleIDs: []string{bundleID}, TeamID: teamID, Clock: time.Now,
	})
	r := NewRegistry(true, apple)
	res, err := r.Verify(context.Background(), Input{
		Format: "darwin", Statement: base64.StdEncoding.EncodeToString(att), ClientDataHash: clientHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AssuranceLevel != "hardware" {
		t.Fatalf("assurance=%q", res.AssuranceLevel)
	}
}

func mustP256XY(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	xy, err := p256UncompressedXY(pub)
	if err != nil {
		t.Fatalf("p256UncompressedXY: %v", err)
	}
	return xy
}
