package deviceauth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// DecodePEMPrivateKey parses a PEM-encoded PKCS#8 Ed25519 private key.
func DecodePEMPrivateKey(pemBytes string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemBytes)))
	if block == nil {
		return nil, fmt.Errorf("deviceauth: no PEM block decoded for private key")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("deviceauth: parse PKCS#8 private key: %w", err)
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("deviceauth: PEM private key is not Ed25519")
		}
		return ed, nil
	default:
		return nil, fmt.Errorf("deviceauth: unexpected PEM block %q for private key", block.Type)
	}
}

// DecodePEMPublicKey parses a PEM-encoded PKIX Ed25519 public key.
func DecodePEMPublicKey(pemBytes string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemBytes)))
	if block == nil {
		return nil, fmt.Errorf("deviceauth: no PEM block decoded for public key")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("deviceauth: parse PKIX public key: %w", err)
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("deviceauth: PEM public key is not Ed25519")
		}
		return ed, nil
	default:
		return nil, fmt.Errorf("deviceauth: unexpected PEM block %q for public key", block.Type)
	}
}
