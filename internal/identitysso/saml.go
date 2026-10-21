package identitysso

import (
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// MaxSAMLReplayWindow is the longest assertion validity accepted. Assertions
// valid for longer are refused rather than clamped: a clamped record would be
// pruned while the assertion could still be presented.
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
// the future and no more than MaxSAMLReplayWindow from now.
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
	if use.ExpiresAt.After(now.Add(MaxSAMLReplayWindow)) {
		return use, invalid("notOnOrAfter must be within %s", MaxSAMLReplayWindow)
	}
	return use, nil
}
