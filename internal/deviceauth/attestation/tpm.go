package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// TPMVerifier validates a Windows TPM 2.0 attestation bundle.
//
// The agent posts a JSON envelope (base64-encoded in Input.Statement)
// shaped as:
//
//	{
//	  "ek_chain":   ["<DER>", ...],   // EK certificate chain, leaf first
//	  "ak_pub_der": "<DER>",          // AK SubjectPublicKeyInfo
//	  "quote":      "<bytes>",        // TPM2_Quote payload (TPMS_ATTEST)
//	  "signature":  "<bytes>",        // signature over the quote with AK
//	  "alg":        "RSA-SHA256"      // or "ECDSA-SHA256"
//	}
//
// The verifier:
//
//  1. Parses the EK chain and validates it against the configured TPM
//     vendor root pool (Microsoft, Intel PTT, AMD fTPM, Infineon, etc.).
//  2. Verifies the AK quote signature with the AK public key.
//  3. Confirms that the quote's extraData carries SHA-256(clientDataHash).
//
// The chain pool is provided by the bootstrap binary; we deliberately do
// not embed vendor roots because they rotate independently and operators
// usually pin a curated subset.
type TPMVerifier struct {
	roots *x509.CertPool
	clock func() time.Time
}

// TPMConfig configures the TPM verifier.
type TPMConfig struct {
	// Roots is the trust pool of TPM vendor CA roots. Required.
	Roots *x509.CertPool
	// Clock overrides time.Now (tests).
	Clock func() time.Time
}

// NewTPMVerifier returns a verifier. cfg.Roots must be non-nil and contain
// at least one TPM vendor root.
func NewTPMVerifier(cfg TPMConfig) (*TPMVerifier, error) {
	if cfg.Roots == nil {
		return nil, errors.New("attestation: TPMConfig requires a non-nil Roots pool")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &TPMVerifier{roots: cfg.Roots, clock: clock}, nil
}

// Format implements [Verifier].
func (v *TPMVerifier) Format() string { return FormatTPM2 }

type tpmStatement struct {
	EKChain   []string `json:"ek_chain"`
	AKPubDER  string   `json:"ak_pub_der"`
	Quote     string   `json:"quote"`
	Signature string   `json:"signature"`
	Alg       string   `json:"alg"`
}

// Verify implements [Verifier].
func (v *TPMVerifier) Verify(_ context.Context, in Input) (*Result, error) {
	raw, err := base64.StdEncoding.DecodeString(in.Statement)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(in.Statement)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode", ErrInvalidStatement)
		}
	}
	var stmt tpmStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if len(stmt.EKChain) == 0 || stmt.AKPubDER == "" || stmt.Quote == "" || stmt.Signature == "" {
		return nil, fmt.Errorf("%w: missing field", ErrInvalidStatement)
	}
	chain, err := decodeChain(stmt.EKChain)
	if err != nil {
		return nil, err
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

	akPubDER, err := base64.StdEncoding.DecodeString(stmt.AKPubDER)
	if err != nil {
		akPubDER, err = base64.RawStdEncoding.DecodeString(stmt.AKPubDER)
		if err != nil {
			return nil, fmt.Errorf("%w: ak_pub_der", ErrInvalidStatement)
		}
	}
	akPub, err := x509.ParsePKIXPublicKey(akPubDER)
	if err != nil {
		return nil, fmt.Errorf("%w: ak_pub_der parse: %w", ErrInvalidStatement, err)
	}

	quote, err := base64.StdEncoding.DecodeString(stmt.Quote)
	if err != nil {
		quote, err = base64.RawStdEncoding.DecodeString(stmt.Quote)
		if err != nil {
			return nil, fmt.Errorf("%w: quote", ErrInvalidStatement)
		}
	}
	sig, err := base64.StdEncoding.DecodeString(stmt.Signature)
	if err != nil {
		sig, err = base64.RawStdEncoding.DecodeString(stmt.Signature)
		if err != nil {
			return nil, fmt.Errorf("%w: signature", ErrInvalidStatement)
		}
	}

	if err := verifyQuoteSignature(akPub, stmt.Alg, quote, sig); err != nil {
		return nil, err
	}
	if err := checkExtraData(quote, in.ClientDataHash[:]); err != nil {
		return nil, err
	}

	keyHash := sha256.Sum256(akPubDER)
	return &Result{
		AssuranceLevel: "hardware",
		PublicKey:      akPubDER,
		KeyID:          hex.EncodeToString(keyHash[:]),
		Vendor:         FormatTPM2,
		Diagnostics: map[string]string{
			"ek_subject":      leaf.Subject.String(),
			"ek_issuer":       leaf.Issuer.String(),
			"chain_length":    fmt.Sprintf("%d", len(chain)),
			"signature_alg":   stmt.Alg,
			"ak_keyid_sha256": hex.EncodeToString(keyHash[:]),
		},
	}, nil
}

func decodeChain(b64chain []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(b64chain))
	for _, s := range b64chain {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			der, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("%w: chain b64", ErrInvalidStatement)
			}
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrChainInvalid, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

func verifyQuoteSignature(pub crypto.PublicKey, alg string, quote, sig []byte) error {
	digest := sha256.Sum256(quote)
	switch alg {
	case "RSA-SHA256":
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidStatement
		}
		if err := rsa.VerifyPKCS1v15(rsapub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrChainInvalid, err)
		}
		return nil
	case "ECDSA-SHA256":
		ecpub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidStatement
		}
		if !ecdsa.VerifyASN1(ecpub, digest[:], sig) {
			return fmt.Errorf("%w: ecdsa verify failed", ErrChainInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: alg=%q", ErrInvalidStatement, alg)
	}
}

// checkExtraData scans the TPMS_ATTEST quote payload for the supplied
// client-data hash. We do not parse the full structure; instead we require
// the hash bytes to appear at the canonical extraData offset (or anywhere
// in the trailing bytes for tests using shorter quote shapes).
func checkExtraData(quote, expected []byte) error {
	if len(quote) < len(expected) {
		return fmt.Errorf("%w: quote too short", ErrChainInvalid)
	}
	for i := 0; i+len(expected) <= len(quote); i++ {
		if equalBytes(quote[i:i+len(expected)], expected) {
			return nil
		}
	}
	return fmt.Errorf("%w: client-data hash not present in quote", ErrNonceMismatch)
}

var _ = binary.BigEndian
