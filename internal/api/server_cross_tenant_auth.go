package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type crossTenantAuthError struct {
	status  int
	message string
}

func (e crossTenantAuthError) Error() string {
	return e.message
}

func (s *Server) requireSignedCrossTenantIngest() bool {
	if s == nil || s.app == nil || s.app.Config == nil {
		return false
	}
	if s.app.Config.GraphCrossTenantRequireSignedIngest {
		return true
	}
	return strings.TrimSpace(s.app.Config.GraphCrossTenantSigningKey) != ""
}

func (s *Server) verifyCrossTenantIngestAuth(r *http.Request, body []byte) error {
	if !s.requireSignedCrossTenantIngest() {
		return nil
	}
	if s == nil || s.app == nil || s.app.Config == nil {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "cross-tenant ingest authentication unavailable"}
	}

	signingKey := strings.TrimSpace(s.app.Config.GraphCrossTenantSigningKey)
	if signingKey == "" {
		return crossTenantAuthError{status: http.StatusServiceUnavailable, message: "cross-tenant ingest signing key is not configured"}
	}

	timestampRaw := strings.TrimSpace(r.Header.Get("X-Cerebro-Timestamp"))
	if timestampRaw == "" {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "missing X-Cerebro-Timestamp header"}
	}
	timestamp, err := parseCrossTenantTimestamp(timestampRaw)
	if err != nil {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "invalid X-Cerebro-Timestamp header"}
	}

	maxSkew := s.app.Config.GraphCrossTenantSignatureSkew
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	now := time.Now().UTC()
	if timestamp.Before(now.Add(-maxSkew)) || timestamp.After(now.Add(maxSkew)) {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "cross-tenant ingest signature timestamp outside allowed skew"}
	}

	nonce := strings.TrimSpace(r.Header.Get("X-Cerebro-Nonce"))
	if nonce == "" {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "missing X-Cerebro-Nonce header"}
	}

	receivedSignature := strings.TrimSpace(r.Header.Get("X-Cerebro-Signature"))
	if receivedSignature == "" {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "missing X-Cerebro-Signature header"}
	}
	receivedSignature = strings.TrimPrefix(strings.ToLower(receivedSignature), "sha256=")
	if receivedSignature == "" {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "invalid X-Cerebro-Signature header"}
	}

	expected := signCrossTenantIngestPayload(signingKey, timestampRaw, nonce, body)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(receivedSignature)) != 1 {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "cross-tenant ingest signature verification failed"}
	}
	if err := s.checkAndTrackCrossTenantNonce(nonce, now); err != nil {
		return err
	}
	return nil
}

func parseCrossTenantTimestamp(raw string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC(), nil
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func signCrossTenantIngestPayload(secret, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(nonce))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) checkAndTrackCrossTenantNonce(nonce string, now time.Time) error {
	if s == nil || s.app == nil || s.app.Config == nil {
		return crossTenantAuthError{status: http.StatusUnauthorized, message: "cross-tenant ingest nonce validation unavailable"}
	}
	replayTTL := s.app.Config.GraphCrossTenantReplayTTL
	if replayTTL <= 0 {
		replayTTL = 24 * time.Hour
	}

	s.crossTenantReplayMu.Lock()
	defer s.crossTenantReplayMu.Unlock()

	expireBefore := now.Add(-replayTTL)
	for seenNonce, seenAt := range s.crossTenantReplay {
		if seenAt.Before(expireBefore) {
			delete(s.crossTenantReplay, seenNonce)
		}
	}
	if seenAt, exists := s.crossTenantReplay[nonce]; exists && seenAt.After(expireBefore) {
		return crossTenantAuthError{status: http.StatusConflict, message: fmt.Sprintf("cross-tenant ingest nonce replay detected: %s", nonce)}
	}
	s.crossTenantReplay[nonce] = now
	return nil
}
