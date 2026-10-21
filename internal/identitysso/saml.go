package identitysso

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// MaxSAMLReplayWindow bounds how long a consumed assertion is remembered, so
// an IdP-supplied NotOnOrAfter far in the future cannot grow the cache.
const MaxSAMLReplayWindow = 24 * time.Hour

const maxSAMLIDLength = 256

// SAMLAssertionInput is the request body for consuming a verified assertion.
type SAMLAssertionInput struct {
	ConnectionID string    `json:"connectionId"`
	AssertionID  string    `json:"assertionId"`
	RequestID    string    `json:"requestId"`
	NotOnOrAfter time.Time `json:"notOnOrAfter"`
}

// NormalizeSAMLAssertion validates an assertion use. NotOnOrAfter must be in
// the future; the stored expiry is clamped to MaxSAMLReplayWindow from now.
func NormalizeSAMLAssertion(input SAMLAssertionInput, now time.Time) (ports.SAMLAssertionUse, error) {
	var use ports.SAMLAssertionUse
	use.ConnectionID = strings.TrimSpace(input.ConnectionID)
	if !ValidResourceID(use.ConnectionID) {
		return use, invalid("connectionId is invalid")
	}
	use.AssertionID = strings.TrimSpace(input.AssertionID)
	if err := checkToken("assertionId", use.AssertionID, maxSAMLIDLength); err != nil {
		return use, err
	}
	use.RequestID = strings.TrimSpace(input.RequestID)
	if err := checkToken("requestId", use.RequestID, maxSAMLIDLength); err != nil {
		return use, err
	}
	if input.NotOnOrAfter.IsZero() {
		return use, invalid("notOnOrAfter is required")
	}
	if !input.NotOnOrAfter.After(now) {
		return use, invalid("notOnOrAfter must be in the future")
	}
	use.ConsumedAt = now.UTC()
	use.ExpiresAt = input.NotOnOrAfter.UTC()
	if latest := now.Add(MaxSAMLReplayWindow).UTC(); use.ExpiresAt.After(latest) {
		use.ExpiresAt = latest
	}
	return use, nil
}
