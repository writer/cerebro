package runtime

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ResponseActionError struct {
	Message          string               `json:"error"`
	Code             string               `json:"code"`
	Remediation      string               `json:"remediation,omitempty"`
	SupportedActions []ResponseActionType `json:"supported_actions,omitempty"`
}

func (e *ResponseActionError) Error() string {
	payload, err := json.Marshal(e)
	if err != nil {
		return e.Message
	}
	return string(payload)
}

func unsupportedResponseActionError(action ResponseActionType, supported []ResponseActionType) *ResponseActionError {
	return &ResponseActionError{
		Message:          fmt.Sprintf("unsupported action type: %s", action),
		Code:             "unsupported_action",
		Remediation:      formatResponseRemediation(supported),
		SupportedActions: supported,
	}
}

func formatResponseRemediation(supported []ResponseActionType) string {
	if len(supported) == 0 {
		return "No supported action types are currently configured."
	}
	values := make([]string, 0, len(supported))
	for _, action := range supported {
		values = append(values, string(action))
	}
	return fmt.Sprintf("Use one of the supported response actions: %s.", strings.Join(values, ", "))
}
