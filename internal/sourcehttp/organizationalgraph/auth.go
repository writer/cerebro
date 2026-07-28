package organizationalgraph

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

const (
	tenantAuthHeader     = "X-Cerebro-Tenant"
	minSharedSecretBytes = 32
)

var tenantAuthContext = []byte("cerebro-organizational-graph/tenant/v1\x00")

type tenantAuthenticator struct {
	secret []byte
}

func newTenantAuthenticator(sharedSecret string) (tenantAuthenticator, error) {
	if len([]byte(sharedSecret)) < minSharedSecretBytes {
		return tenantAuthenticator{}, errors.New("rust organizational graph shared secret must be at least 32 bytes")
	}
	return tenantAuthenticator{secret: []byte(sharedSecret)}, nil
}

func (a tenantAuthenticator) authorize(request *http.Request, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return errors.New("rust organizational graph tenant ID is required")
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write(tenantAuthContext)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len([]byte(tenantID))))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(tenantID))
	request.Header.Set(tenantAuthHeader, tenantID)
	request.Header.Set("Authorization", "Bearer "+hex.EncodeToString(mac.Sum(nil)))
	return nil
}
