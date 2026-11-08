package cloudidentitysource

import (
	"encoding/json"
	"fmt"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// digestStruct preserves the JSON encoding used for structured cloud evidence.
// Serialization errors remain errors, not evidence about cloud state.
func digestStruct(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("cloudidentitysource: digest value: %w", err)
	}
	return ci.DigestJSON(payload)
}
