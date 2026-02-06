package agents

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type ToolError struct {
	Message               string   `json:"error"`
	Code                  string   `json:"code"`
	Remediation           string   `json:"remediation,omitempty"`
	SupportedServices     []string `json:"supported_services,omitempty"`
	SupportedActions      []string `json:"supported_actions,omitempty"`
	SupportedProviders    []string `json:"supported_providers,omitempty"`
	SupportedResourceType []string `json:"supported_resource_types,omitempty"`
}

func (e *ToolError) Error() string {
	payload, err := json.Marshal(e)
	if err != nil {
		return e.Message
	}
	return string(payload)
}

func (e *ToolError) JSON() string {
	return e.Error()
}

func (e *ToolError) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"error": e.Message,
		"code":  e.Code,
	}
	if e.Remediation != "" {
		result["remediation"] = e.Remediation
	}
	if len(e.SupportedServices) > 0 {
		result["supported_services"] = e.SupportedServices
	}
	if len(e.SupportedActions) > 0 {
		result["supported_actions"] = e.SupportedActions
	}
	if len(e.SupportedProviders) > 0 {
		result["supported_providers"] = e.SupportedProviders
	}
	if len(e.SupportedResourceType) > 0 {
		result["supported_resource_types"] = e.SupportedResourceType
	}
	return result
}

func UnsupportedServiceError(provider, service string, supported []string) *ToolError {
	label := "service"
	if provider != "" {
		label = fmt.Sprintf("%s service", provider)
	}
	return &ToolError{
		Message:           fmt.Sprintf("unsupported %s: %s", label, service),
		Code:              "unsupported_service",
		Remediation:       formatRemediation("services", supported),
		SupportedServices: supported,
	}
}

func UnsupportedActionError(service, action string, supported []string) *ToolError {
	label := "action"
	if service != "" {
		label = fmt.Sprintf("%s action", service)
	}
	return &ToolError{
		Message:          fmt.Sprintf("unsupported %s: %s", label, action),
		Code:             "unsupported_action",
		Remediation:      formatRemediation("actions", supported),
		SupportedActions: supported,
	}
}

func UnsupportedProviderError(provider string, supported []string) *ToolError {
	return &ToolError{
		Message:            fmt.Sprintf("unsupported provider: %s", provider),
		Code:               "unsupported_provider",
		Remediation:        formatRemediation("providers", supported),
		SupportedProviders: supported,
	}
}

func UnsupportedResourceTypeError(service, resourceType string, supported []string) *ToolError {
	label := "resource type"
	if service != "" {
		label = fmt.Sprintf("%s resource type", service)
	}
	return &ToolError{
		Message:               fmt.Sprintf("unsupported %s: %s", label, resourceType),
		Code:                  "unsupported_resource_type",
		Remediation:           formatRemediation("resource types", supported),
		SupportedResourceType: supported,
	}
}

func formatRemediation(label string, supported []string) string {
	if len(supported) == 0 {
		return "No supported options are currently configured."
	}
	return fmt.Sprintf("Use one of the supported %s: %s.", label, strings.Join(supported, ", "))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func toolErrorOutput(err error) string {
	var toolErr *ToolError
	if errors.As(err, &toolErr) {
		return toolErr.JSON()
	}
	return err.Error()
}

func toolErrorValue(err error) interface{} {
	var toolErr *ToolError
	if errors.As(err, &toolErr) {
		return toolErr.AsMap()
	}
	return err.Error()
}
