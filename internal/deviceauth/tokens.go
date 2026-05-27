package deviceauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// RefreshTokenBytes is the size of the random part of a refresh or bootstrap
// token. 32 bytes (256 bits) is the OAuth 2.0 best-practice minimum and
// matches the existing capability-token size in internal/bootstrap/auth.go.
const RefreshTokenBytes = 32

// GenerateOpaqueToken returns a fresh, cryptographically random opaque token
// suitable for use as a refresh token or a bootstrap token. The plaintext is
// returned to the caller exactly once; only its [HashToken] digest should
// ever be persisted.
func GenerateOpaqueToken() (string, error) {
	buf := make([]byte, RefreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewFamilyID returns a fresh family identifier for a new refresh-token
// lineage. Every refresh-rotation step keeps the family id and increments
// generation; replay of any consumed token revokes the family.
func NewFamilyID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "fam_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// NormalizeOpaqueToken trims the token and rejects empty input. Callers
// should pass the result of this function to [HashToken].
func NormalizeOpaqueToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("deviceauth: opaque token is empty")
	}
	return token, nil
}
