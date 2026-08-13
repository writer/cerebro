package oktaasset

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalThreatInsightState returns a stable payload and immutable event ID
// for one logical threat configuration state.
func CanonicalThreatInsightState(domain, action string, zones []string) ([]byte, string, error) {
	canonicalZones := append([]string{}, zones...)
	sort.Strings(canonicalZones)
	payload, err := json.Marshal(map[string]any{"domain": domain, "action": action, "exclude_zones": canonicalZones})
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(payload)
	return payload, fmt.Sprintf("okta-threat-insight-sha256-%x", digest), nil
}
