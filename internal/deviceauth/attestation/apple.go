package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// AppleAppAttestVerifier validates Apple App Attest attestation objects.
//
// The flow follows Apple's "Validating Apps That Connect to Your Server"
// guidance (developer.apple.com/documentation/devicecheck):
//
//  1. Decode the CBOR attestation object: {fmt:"apple-appattest", attStmt:{x5c:[...], receipt}, authData}.
//  2. Verify the x5c chain ends at the embedded Apple App Attestation Root
//     CA (or a configured override).
//  3. Compute nonce = SHA-256(authData || clientDataHash). Extract the
//     credCert's nonce extension (1.2.840.113635.100.8.2), which contains
//     a DER OCTET STRING wrapping the SHA-256 we expect, and compare.
//  4. Pull the public key from the credCert's SubjectPublicKeyInfo. Compute
//     credId = SHA-256(public key X || Y). Compare against the credId
//     baked into authData. Equality proves the certificate is for *this*
//     device-bound key.
//
// The verifier returns hardware-assurance results when the Apple chain
// validates and the nonce + key id checks pass.
type AppleAppAttestVerifier struct {
	roots     *x509.CertPool
	clock     func() time.Time
	bundleIDs map[string]struct{}
	teamID    string
}

// AppleConfig configures the Apple App Attest verifier.
type AppleConfig struct {
	// Roots overrides the default Apple App Attestation Root CA pool. The
	// embedded production root is used when nil.
	Roots *x509.CertPool
	// BundleIDs is the set of expected app bundle identifiers that may
	// appear in authData's rpIdHash field. Production should pin a single
	// id; tests may pass several.
	BundleIDs []string
	// TeamID is the Apple developer team id; combined with BundleID it
	// derives the rpIdHash that must match authData[:32].
	TeamID string
	// Clock overrides time.Now (tests).
	Clock func() time.Time
}

// NewAppleAppAttestVerifier returns a verifier configured for the given
// bundle ids and team id. If cfg.Roots is nil, the embedded Apple root is
// installed.
func NewAppleAppAttestVerifier(cfg AppleConfig) (*AppleAppAttestVerifier, error) {
	roots := cfg.Roots
	if roots == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(appleAppAttestRootCAPEM)) {
			return nil, errors.New("attestation: embedded Apple root CA failed to parse")
		}
		roots = pool
	}
	if cfg.TeamID == "" || len(cfg.BundleIDs) == 0 {
		return nil, errors.New("attestation: AppleConfig requires TeamID and at least one BundleID")
	}
	bundleSet := make(map[string]struct{}, len(cfg.BundleIDs))
	for _, b := range cfg.BundleIDs {
		bundleSet[b] = struct{}{}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	v := &AppleAppAttestVerifier{
		roots:     roots,
		clock:     clock,
		bundleIDs: bundleSet,
		teamID:    cfg.TeamID,
	}
	return v, nil
}

// Format implements [Verifier].
func (v *AppleAppAttestVerifier) Format() string { return FormatAppleAppAttest }

// Verify implements [Verifier].
func (v *AppleAppAttestVerifier) Verify(_ context.Context, in Input) (*Result, error) {
	raw, err := base64.StdEncoding.DecodeString(in.Statement)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(in.Statement)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode", ErrInvalidStatement)
		}
	}
	root, _, err := decodeCBOR(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: cbor decode", ErrInvalidStatement)
	}
	if root.major != 5 {
		return nil, fmt.Errorf("%w: root not a map", ErrInvalidStatement)
	}
	fmtVal, _ := root.lookup("fmt")
	if fmtVal.text != FormatAppleAppAttest {
		return nil, fmt.Errorf("%w: fmt=%q want=%q", ErrInvalidStatement, fmtVal.text, FormatAppleAppAttest)
	}
	authData, ok := root.lookup("authData")
	if !ok || authData.major != 2 {
		return nil, fmt.Errorf("%w: missing authData", ErrInvalidStatement)
	}
	att, ok := root.lookup("attStmt")
	if !ok || att.major != 5 {
		return nil, fmt.Errorf("%w: missing attStmt", ErrInvalidStatement)
	}
	x5c, ok := att.lookup("x5c")
	if !ok || x5c.major != 4 || len(x5c.array) == 0 {
		return nil, fmt.Errorf("%w: missing x5c", ErrInvalidStatement)
	}

	chain := make([]*x509.Certificate, 0, len(x5c.array))
	for _, item := range x5c.array {
		if item.major != 2 {
			return nil, fmt.Errorf("%w: x5c element not a byte string", ErrInvalidStatement)
		}
		cert, err := x509.ParseCertificate(item.bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrChainInvalid, err)
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.clock(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChainInvalid, err)
	}

	// Nonce check: SHA256(authData || clientDataHash) must equal the value
	// in the leaf's 1.2.840.113635.100.8.2 extension (an OCTET STRING
	// wrapping a SHA-256).
	expected := sha256.New()
	expected.Write(authData.bytes)
	expected.Write(in.ClientDataHash[:])
	expectedNonce := expected.Sum(nil)
	if err := checkAppleNonceExtension(leaf, expectedNonce); err != nil {
		return nil, err
	}

	// rpIdHash: first 32 bytes of authData. Attested credential data begins
	// at byte 37 and carries a 16-byte AAGUID followed by a 2-byte credId
	// length at bytes 53:55, so reject truncated inputs before slicing.
	if len(authData.bytes) < 55 {
		return nil, fmt.Errorf("%w: authData too short", ErrInvalidStatement)
	}
	rpIDHash := authData.bytes[:32]
	if !v.matchRPIDHash(rpIDHash) {
		return nil, fmt.Errorf("%w: rpIdHash does not match any configured bundle id / team", ErrInvalidStatement)
	}

	// credId is at authData[37:37+credIdLen].
	credIDLen := binary.BigEndian.Uint16(authData.bytes[53:55])
	if 55+int(credIDLen) > len(authData.bytes) {
		return nil, fmt.Errorf("%w: credId extends past authData", ErrInvalidStatement)
	}
	credID := authData.bytes[55 : 55+int(credIDLen)]

	// The leaf's public key, when hashed (X||Y), should equal credId.
	ecpub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || ecpub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: leaf is not P-256", ErrInvalidStatement)
	}
	xy, err := p256UncompressedXY(ecpub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	keyHash := sha256.Sum256(xy)
	if !equalBytes(keyHash[:], credID) {
		return nil, ErrKeyIDMismatch
	}

	pkix, err := x509.MarshalPKIXPublicKey(ecpub)
	if err != nil {
		return nil, fmt.Errorf("attestation: marshal pubkey: %w", err)
	}

	return &Result{
		AssuranceLevel: "hardware",
		PublicKey:      pkix,
		KeyID:          hex.EncodeToString(credID),
		Vendor:         FormatAppleAppAttest,
		Diagnostics: map[string]string{
			"leaf_subject":   leaf.Subject.String(),
			"leaf_issuer":    leaf.Issuer.String(),
			"chain_length":   fmt.Sprintf("%d", len(chain)),
			"rp_id_hash_hex": hex.EncodeToString(rpIDHash),
		},
	}, nil
}

func (v *AppleAppAttestVerifier) matchRPIDHash(rpIDHash []byte) bool {
	for bundle := range v.bundleIDs {
		expected := sha256.Sum256([]byte(v.teamID + "." + bundle))
		if equalBytes(rpIDHash, expected[:]) {
			return true
		}
	}
	return false
}

// nonceOID is the Apple-specific extension OID that carries the device-
// scoped nonce in the App Attest credential cert.
var nonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

func checkAppleNonceExtension(cert *x509.Certificate, expected []byte) error {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(nonceOID) {
			continue
		}
		// The extension value is an ASN.1 SEQUENCE whose first element is
		// an OCTET STRING wrapping the 32-byte nonce. Apple uses the
		// outer OCTET STRING in the extension itself per X.509 §4.2, then
		// nests another OCTET STRING for the value. We unwrap layers
		// until we find a 32-byte octet string and compare.
		raw := ext.Value
		// Try to unwrap one or two SEQUENCE/OCTET STRING layers.
		for i := 0; i < 4; i++ {
			var inner asn1.RawValue
			if _, err := asn1.Unmarshal(raw, &inner); err != nil {
				break
			}
			raw = inner.Bytes
			if len(raw) == 32 && equalBytes(raw, expected) {
				return nil
			}
		}
		// Last-resort scan for a 32-byte run that matches expected.
		for i := 0; i+32 <= len(ext.Value); i++ {
			if equalBytes(ext.Value[i:i+32], expected) {
				return nil
			}
		}
		return ErrNonceMismatch
	}
	return fmt.Errorf("%w: leaf missing 1.2.840.113635.100.8.2 nonce extension", ErrChainInvalid)
}

// p256UncompressedXY converts an ecdsa.PublicKey on P-256 to its 64-byte
// big-endian X || Y serialization without touching the deprecated raw
// coordinate fields. The crypto/ecdh package returns the SEC1 uncompressed
// point format (0x04 || X || Y); we strip the 0x04 prefix.
func p256UncompressedXY(pub *ecdsa.PublicKey) ([]byte, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	raw := ecdhPub.Bytes()
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("attestation: unexpected SEC1 encoding length %d", len(raw))
	}
	return raw[1:], nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
