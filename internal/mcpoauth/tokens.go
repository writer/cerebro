package mcpoauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

const opaqueTokenBytes = 32

func NewOpaqueToken(prefix string) (string, error) {
	buf := make([]byte, opaqueTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	if strings.TrimSpace(prefix) == "" {
		return token, nil
	}
	return strings.TrimSpace(prefix) + "_" + token, nil
}

func NormalizeOpaqueToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("mcpoauth: opaque token is empty")
	}
	return token, nil
}

func NewFamilyID() (string, error) {
	return NewOpaqueToken("fam")
}
