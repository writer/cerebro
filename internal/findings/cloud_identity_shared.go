package findings

import (
	"encoding/json"
	"fmt"

	"github.com/writer/cerebro/internal/cloudidentity"
)

// cloudIdentityPrincipalEntityType and cloudIdentityPrincipalURNKind must stay
// byte-identical to the literals used by the cloud_identity source projector
// (internal/sourceprojection/cloud_identity.go). The two packages cannot share
// an unexported Go constant, so the contract is this comment plus the
// behavior tests that assert the finding's resource URNs resolve against the
// projected graph.
const (
	cloudIdentityPrincipalEntityType = "cloud_identity.principal"
	cloudIdentityPrincipalURNKind    = "cloud_identity_principal"
)

// cloudIdentityDigest preserves the JSON encoding used for evidence identities.
func cloudIdentityDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal cloud identity value: %w", err)
	}
	return cloudidentity.DigestJSON(payload)
}
