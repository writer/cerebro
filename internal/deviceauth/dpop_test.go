package deviceauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

type dpopSigner struct {
	es256 *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
	edPub ed25519.PublicKey
}

func newDPoPSignerES256(t *testing.T) *dpopSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	return &dpopSigner{es256: k}
}

func newDPoPSignerEd25519(t *testing.T) *dpopSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	return &dpopSigner{ed: priv, edPub: pub}
}

func (s *dpopSigner) jwk() map[string]string {
	if s.es256 != nil {
		ecdhPub, err := s.es256.PublicKey.ECDH()
		if err != nil {
			panic(err)
		}
		raw := ecdhPub.Bytes()
		return map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
			"y":   base64.RawURLEncoding.EncodeToString(raw[33:]),
		}
	}
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(s.edPub),
	}
}

func (s *dpopSigner) alg() string {
	if s.es256 != nil {
		return "ES256"
	}
	return "EdDSA"
}

func (s *dpopSigner) sign(input []byte) []byte {
	if s.es256 != nil {
		sum := sha256.Sum256(input)
		r, sgn, err := ecdsa.Sign(rand.Reader, s.es256, sum[:])
		if err != nil {
			panic(err)
		}
		out := make([]byte, 64)
		copy(out[32-len(r.Bytes()):32], r.Bytes())
		copy(out[64-len(sgn.Bytes()):64], sgn.Bytes())
		return out
	}
	return ed25519.Sign(s.ed, input)
}

func makeDPoPProof(t *testing.T, s *dpopSigner, htm, htu string, iat time.Time, jti string) string {
	return makeDPoPProofWithATH(t, s, htm, htu, iat, jti, "")
}

func makeDPoPProofWithATH(t *testing.T, s *dpopSigner, htm, htu string, iat time.Time, jti string, ath string) string {
	t.Helper()
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": s.alg(),
		"jwk": s.jwk(),
	}
	hb, _ := json.Marshal(header)
	payload := map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": iat.Unix(),
		"jti": jti,
	}
	if ath != "" {
		payload["ath"] = ath
	}
	pb, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig := s.sign([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestDPoPVerifyES256RoundTrip(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	v := NewDPoPVerifier(time.Minute, time.Minute)
	v.SetClock(func() time.Time { return now })
	signer := newDPoPSignerES256(t)
	proof := makeDPoPProof(t, signer, "POST", "https://cerebro.example.com/platform/devices/token", now, "abc-1")
	res, err := v.Verify(proof, "POST", "https://cerebro.example.com/platform/devices/token")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.JKT == "" {
		t.Fatal("jkt empty")
	}
}

func TestDPoPVerifyEdDSARoundTrip(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	v := NewDPoPVerifier(time.Minute, time.Minute)
	v.SetClock(func() time.Time { return now })
	signer := newDPoPSignerEd25519(t)
	proof := makeDPoPProof(t, signer, "POST", "https://cerebro.example.com/x", now, "abc-2")
	if _, err := v.Verify(proof, "POST", "https://cerebro.example.com/x"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDPoPRejectsReplay(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	v := NewDPoPVerifier(time.Minute, time.Minute)
	v.SetClock(func() time.Time { return now })
	s := newDPoPSignerES256(t)
	proof := makeDPoPProof(t, s, "POST", "https://h/p", now, "jti-1")
	if _, err := v.Verify(proof, "POST", "https://h/p"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := v.Verify(proof, "POST", "https://h/p"); !errors.Is(err, ErrDPoPReplay) {
		t.Fatalf("second verify err = %v, want ErrDPoPReplay", err)
	}
}

func TestDPoPRejectsExpired(t *testing.T) {
	t0 := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	v := NewDPoPVerifier(5*time.Second, 30*time.Second)
	now := t0
	v.SetClock(func() time.Time { return now })
	s := newDPoPSignerES256(t)
	proof := makeDPoPProof(t, s, "POST", "https://h/p", t0, "jti-x")
	now = t0.Add(2 * time.Minute)
	if _, err := v.Verify(proof, "POST", "https://h/p"); !errors.Is(err, ErrDPoPExpired) {
		t.Fatalf("expired err = %v, want ErrDPoPExpired", err)
	}
}

func TestDPoPRejectsHTMHTUMismatch(t *testing.T) {
	now := time.Now()
	v := NewDPoPVerifier(time.Minute, time.Minute)
	v.SetClock(func() time.Time { return now })
	s := newDPoPSignerES256(t)
	proof := makeDPoPProof(t, s, "GET", "https://h/p", now, "jti-q")
	if _, err := v.Verify(proof, "POST", "https://h/p"); !errors.Is(err, ErrDPoPMismatch) {
		t.Fatalf("htm mismatch err = %v, want ErrDPoPMismatch", err)
	}
	proof = makeDPoPProof(t, s, "POST", "https://h/p", now, "jti-r")
	if _, err := v.Verify(proof, "POST", "https://h/q"); !errors.Is(err, ErrDPoPMismatch) {
		t.Fatalf("htu mismatch err = %v, want ErrDPoPMismatch", err)
	}
}

func TestDPoPRejectsTamperedSignature(t *testing.T) {
	now := time.Now()
	v := NewDPoPVerifier(time.Minute, time.Minute)
	v.SetClock(func() time.Time { return now })
	s := newDPoPSignerES256(t)
	proof := makeDPoPProof(t, s, "POST", "https://h/p", now, "jti-t")
	// flip first character of the signature
	idx := lastDot(proof) + 1
	first := proof[idx]
	flipped := byte('A')
	if first == 'A' {
		flipped = 'B'
	}
	tampered := proof[:idx] + string(flipped) + proof[idx+1:]
	if _, err := v.Verify(tampered, "POST", "https://h/p"); !errors.Is(err, ErrDPoPInvalidSignature) {
		t.Fatalf("tampered err = %v, want ErrDPoPInvalidSignature", err)
	}
}

func TestDPoPVerifyBindsAccessTokenHash(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	v := NewDPoPVerifier(time.Minute, time.Minute)
	v.SetClock(func() time.Time { return now })
	s := newDPoPSignerES256(t)
	accessToken := "header.payload.signature"
	proof := makeDPoPProofWithATH(t, s, "GET", "https://h/p", now, "jti-ath-1", dpopAccessTokenHash(accessToken))
	if _, err := v.Verify(proof, "GET", "https://h/p", accessToken); err != nil {
		t.Fatalf("verify with matching ath: %v", err)
	}
	badProof := makeDPoPProofWithATH(t, s, "GET", "https://h/p", now, "jti-ath-2", dpopAccessTokenHash("different"))
	if _, err := v.Verify(badProof, "GET", "https://h/p", accessToken); !errors.Is(err, ErrDPoPMismatch) {
		t.Fatalf("verify with wrong ath err = %v, want ErrDPoPMismatch", err)
	}
	missingATH := makeDPoPProof(t, s, "GET", "https://h/p", now, "jti-ath-3")
	if _, err := v.Verify(missingATH, "GET", "https://h/p", accessToken); !errors.Is(err, ErrDPoPMismatch) {
		t.Fatalf("verify with missing ath err = %v, want ErrDPoPMismatch", err)
	}
}

func TestDPoPThumbprintIsStable(t *testing.T) {
	// two parses of the same JWK must produce the same thumbprint
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":"%s"}`, base64.RawURLEncoding.EncodeToString(pub))
	_, jkt1, err := parseJWK([]byte(jwk))
	if err != nil {
		t.Fatal(err)
	}
	_, jkt2, err := parseJWK([]byte(jwk))
	if err != nil {
		t.Fatal(err)
	}
	if jkt1 != jkt2 {
		t.Fatalf("thumbprints differ: %s vs %s", jkt1, jkt2)
	}
}

func TestDPoPRejectsBadKtyOrCurve(t *testing.T) {
	if _, _, err := parseJWK([]byte(`{"kty":"RSA","n":"AA","e":"AQAB"}`)); err == nil {
		t.Fatal("expected error for RSA")
	}
	if _, _, err := parseJWK([]byte(`{"kty":"EC","crv":"P-521","x":"AA","y":"AA"}`)); err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

func TestDPoPParseJWKRejectsOffCurve(t *testing.T) {
	x := big.NewInt(1).Bytes()
	y := big.NewInt(1).Bytes()
	jwk := fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y))
	if _, _, err := parseJWK([]byte(jwk)); err == nil {
		t.Fatal("expected off-curve rejection")
	}
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
