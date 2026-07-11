package complianceexchange

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type protectedHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// CryptoSigner adapts a standard-library crypto.Signer to detached package
// signatures. ES256 signatures are converted from ASN.1 to the fixed-width JWS
// representation; Ed25519 signs the JWS signing input directly.
type CryptoSigner struct {
	AlgorithmName string
	KeyIDValue    string
	PrivateKey    crypto.Signer
}

func (s CryptoSigner) Algorithm() string { return strings.TrimSpace(s.AlgorithmName) }
func (s CryptoSigner) KeyID() string     { return strings.TrimSpace(s.KeyIDValue) }

func (s CryptoSigner) Sign(_ context.Context, signingInput []byte) ([]byte, error) {
	if s.PrivateKey == nil {
		return nil, errors.New("private signer is required")
	}
	switch s.Algorithm() {
	case AlgorithmEdDSA:
		if _, ok := s.PrivateKey.Public().(ed25519.PublicKey); !ok {
			return nil, errors.New("EdDSA signer does not expose an Ed25519 public key")
		}
		return s.PrivateKey.Sign(rand.Reader, signingInput, crypto.Hash(0))
	case AlgorithmES256:
		publicKey, ok := s.PrivateKey.Public().(*ecdsa.PublicKey)
		if !ok || publicKey.Curve != elliptic.P256() {
			return nil, errors.New("ES256 signer does not expose a P-256 public key")
		}
		digest := sha256.Sum256(signingInput)
		der, err := s.PrivateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return ecdsaDERToJWS(der)
	default:
		return nil, ErrUnsupportedAlg
	}
}

// SignDetached creates compact JWS detached-content serialization. The empty
// middle segment means the manifest bytes travel separately.
func SignDetached(ctx context.Context, manifest []byte, signer Signer) (string, error) {
	if signer == nil {
		return "", errors.New("signer is required")
	}
	algorithm := strings.TrimSpace(signer.Algorithm())
	if !allowedAlgorithm(algorithm) {
		return "", ErrUnsupportedAlg
	}
	keyID := strings.TrimSpace(signer.KeyID())
	if keyID == "" {
		return "", errors.New("signer key ID is required")
	}
	header, err := json.Marshal(protectedHeader{Algorithm: algorithm, KeyID: keyID, Type: SignatureType})
	if err != nil {
		return "", fmt.Errorf("marshal signature header: %w", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	payloadSegment := base64.RawURLEncoding.EncodeToString(manifest)
	signingInput := []byte(headerSegment + "." + payloadSegment)
	signature, err := signer.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("sign manifest: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return "", errors.New("signer returned a signature with an invalid size")
	}
	return headerSegment + ".." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifyDetached(ctx context.Context, manifest []byte, compact string, trust TrustResolver) (protectedHeader, error) {
	if trust == nil {
		return protectedHeader{}, errors.New("trust resolver is required")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] != "" || parts[2] == "" {
		return protectedHeader{}, ErrSignatureInvalid
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return protectedHeader{}, ErrSignatureInvalid
	}
	var header protectedHeader
	decoder := json.NewDecoder(strings.NewReader(string(headerBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		return protectedHeader{}, ErrSignatureInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return protectedHeader{}, ErrSignatureInvalid
	}
	if !allowedAlgorithm(header.Algorithm) || strings.TrimSpace(header.KeyID) == "" || header.Type != SignatureType {
		return protectedHeader{}, ErrSignatureInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return protectedHeader{}, ErrSignatureInvalid
	}
	publicKey, err := trust.ResolveTrustedKey(ctx, header.KeyID, header.Algorithm)
	if err != nil || publicKey == nil {
		return protectedHeader{}, ErrSignatureInvalid
	}
	payloadSegment := base64.RawURLEncoding.EncodeToString(manifest)
	signingInput := []byte(parts[0] + "." + payloadSegment)
	switch header.Algorithm {
	case AlgorithmEdDSA:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(key, signingInput, signature) {
			return protectedHeader{}, ErrSignatureInvalid
		}
	case AlgorithmES256:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || len(signature) != 64 {
			return protectedHeader{}, ErrSignatureInvalid
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		digest := sha256.Sum256(signingInput)
		if !ecdsa.Verify(key, digest[:], r, s) {
			return protectedHeader{}, ErrSignatureInvalid
		}
	default:
		return protectedHeader{}, ErrSignatureInvalid
	}
	return header, nil
}

func allowedAlgorithm(value string) bool {
	return value == AlgorithmEdDSA || value == AlgorithmES256
}

func ecdsaDERToJWS(der []byte) ([]byte, error) {
	var parsed struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, errors.New("ES256 signer returned a malformed signature")
	}
	if parsed.R.BitLen() > 256 || parsed.S.BitLen() > 256 {
		return nil, errors.New("ES256 signer returned an oversized signature")
	}
	signature := make([]byte, 64)
	parsed.R.FillBytes(signature[:32])
	parsed.S.FillBytes(signature[32:])
	return signature, nil
}
