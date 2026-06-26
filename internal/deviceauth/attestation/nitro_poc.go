package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const FormatAWSNitroEnclavePOC = "aws-nitro-enclave-poc"

type NitroPOCConfig struct {
	Measurements []string
}

type NitroPOCVerifier struct {
	measurements map[string]struct{}
}

type nitroPOCStatement struct {
	ModuleID    string `json:"module_id"`
	ImageSHA384 string `json:"image_sha384"`
	PublicKey   string `json:"public_key_der"`
	Nonce       string `json:"nonce"`
}

func NewNitroPOCVerifier(cfg NitroPOCConfig) (*NitroPOCVerifier, error) {
	measurements := map[string]struct{}{}
	for _, measurement := range cfg.Measurements {
		measurement = strings.ToLower(strings.TrimSpace(measurement))
		if measurement == "" {
			continue
		}
		measurements[measurement] = struct{}{}
	}
	if len(measurements) == 0 {
		return nil, errors.New("attestation: Nitro POC verifier requires at least one measurement")
	}
	return &NitroPOCVerifier{measurements: measurements}, nil
}

func (v *NitroPOCVerifier) Format() string { return FormatAWSNitroEnclavePOC }

func (v *NitroPOCVerifier) Verify(_ context.Context, in Input) (*Result, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.Statement))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(in.Statement))
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode", ErrInvalidStatement)
		}
	}
	var stmt nitroPOCStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	measurement := strings.ToLower(strings.TrimSpace(stmt.ImageSHA384))
	if measurement == "" {
		return nil, fmt.Errorf("%w: image_sha384 is required", ErrInvalidStatement)
	}
	if _, ok := v.measurements[measurement]; !ok {
		return nil, fmt.Errorf("%w: Nitro image measurement is not trusted", ErrChainInvalid)
	}
	nonce, err := decodeBase64AttestationField(stmt.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce", ErrInvalidStatement)
	}
	if len(nonce) != len(in.ClientDataHash) || !equalBytes(nonce, in.ClientDataHash[:]) {
		return nil, ErrNonceMismatch
	}
	pubDER, err := decodeBase64AttestationField(stmt.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: public_key_der", ErrInvalidStatement)
	}
	if _, err := x509.ParsePKIXPublicKey(pubDER); err != nil {
		return nil, fmt.Errorf("%w: public_key_der parse: %w", ErrInvalidStatement, err)
	}
	keyHash := sha256.Sum256(pubDER)
	return &Result{
		AssuranceLevel: "software",
		PublicKey:      pubDER,
		KeyID:          hex.EncodeToString(keyHash[:]),
		Vendor:         FormatAWSNitroEnclavePOC,
		Diagnostics: map[string]string{
			"module_id":        strings.TrimSpace(stmt.ModuleID),
			"image_sha384":     measurement,
			"attestation_mode": "poc",
		},
	}, nil
}

func decodeBase64AttestationField(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, errors.New("invalid base64")
}
