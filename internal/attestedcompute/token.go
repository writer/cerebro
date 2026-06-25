package attestedcompute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	AttestationFormatAWSNitroEnclavePOC = "aws-nitro-enclave-poc"
	EventKindGraphDelta                 = "attested_compute.graph_delta"
	TokenPrefix                         = "tok_"
)

type Tokenizer struct {
	key []byte
}

func NewTokenizer(key []byte) (*Tokenizer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("attested compute token key must be at least 32 bytes")
	}
	return &Tokenizer{key: append([]byte(nil), key...)}, nil
}

func (t *Tokenizer) Token(domain string, value string) string {
	if t == nil || len(t.key) == 0 {
		return ""
	}
	domain = strings.TrimSpace(domain)
	value = strings.TrimSpace(value)
	if domain == "" || value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, t.key)
	_, _ = mac.Write([]byte("attested-compute"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte("v1"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	sum := mac.Sum(nil)
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(sum[:18])
}

func TokenURN(tenantID string, entityType string, token string) string {
	tenantID = strings.TrimSpace(tenantID)
	entityType = strings.TrimSpace(entityType)
	token = strings.TrimSpace(token)
	if tenantID == "" || !safeEntityTypeSegment(entityType) || !TokenLike(token) {
		return ""
	}
	return "urn:cerebro:" + tenantID + ":attested:" + entityType + ":" + token
}

func safeEntityTypeSegment(entityType string) bool {
	entityType = strings.TrimSpace(entityType)
	if entityType == "" || TokenLike(entityType) || !strings.Contains(entityType, ".") {
		return false
	}
	for _, char := range strings.ToLower(entityType) {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
		case char == '.' || char == '_' || char == '-':
		default:
			return false
		}
	}
	return true
}

func TokenLike(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, TokenPrefix) {
		return false
	}
	if len(value) <= len(TokenPrefix) {
		return false
	}
	for _, char := range strings.TrimPrefix(value, TokenPrefix) {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '-' || char == '_':
		default:
			return false
		}
	}
	return true
}
