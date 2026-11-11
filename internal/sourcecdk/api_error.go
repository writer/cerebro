package sourcecdk

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DecodeAPIError builds a classified *HTTPStatusError for a non-2xx JSON API
// response. It extracts a human-readable message from a JSON object body by
// trying messageKeys in order, falling back to the raw trimmed body and then
// to fallbackMessage (typically the caller's net/http status text, since the
// Source CDK keeps no net/http dependency of its own) when neither yields
// anything usable. service names the failing endpoint in the wrapped error
// text (e.g. "VulnView API").
func DecodeAPIError(service string, statusCode int, body []byte, fallbackMessage string, messageKeys ...string) error {
	message := strings.TrimSpace(string(body))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range messageKeys {
			if value := (JSONScalar{Value: payload[key]}).Flattened(); value != "" {
				message = value
				break
			}
		}
	}
	if message == "" {
		message = fallbackMessage
	}
	return &HTTPStatusError{Code: statusCode, Message: fmt.Sprintf("%s returned %d: %s", service, statusCode, message)}
}
