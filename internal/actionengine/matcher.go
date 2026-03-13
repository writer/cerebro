package actionengine

import (
	"fmt"
	"strings"
)

func PlaybookMatchesSignal(playbook Playbook, signal Signal) bool {
	if !playbook.Enabled {
		return false
	}
	for _, trigger := range playbook.Triggers {
		if TriggerMatchesSignal(trigger, signal) {
			return true
		}
	}
	return false
}

func TriggerMatchesSignal(trigger Trigger, signal Signal) bool {
	if strings.TrimSpace(trigger.Kind) != "" && !strings.EqualFold(strings.TrimSpace(trigger.Kind), strings.TrimSpace(signal.Kind)) {
		return false
	}
	if strings.TrimSpace(trigger.Severity) != "" && !severityMatches(signal.Severity, trigger.Severity, trigger.SeverityMatchMode) {
		return false
	}
	if strings.TrimSpace(trigger.PolicyID) != "" && !strings.EqualFold(strings.TrimSpace(trigger.PolicyID), strings.TrimSpace(signal.PolicyID)) {
		return false
	}
	if strings.TrimSpace(trigger.Category) != "" && !strings.EqualFold(strings.TrimSpace(trigger.Category), strings.TrimSpace(signal.Category)) {
		return false
	}
	if strings.TrimSpace(trigger.RuleID) != "" && !strings.EqualFold(strings.TrimSpace(trigger.RuleID), strings.TrimSpace(signal.RuleID)) {
		return false
	}
	if len(trigger.Tags) > 0 && !signalHasAnyTag(signal, trigger.Tags) {
		return false
	}
	for key, expected := range trigger.Conditions {
		actual, ok := signalFieldValue(signal, key)
		if !ok {
			return false
		}
		if strings.TrimSpace(strings.ToLower(actual)) != strings.TrimSpace(strings.ToLower(expected)) {
			return false
		}
	}
	return true
}

func signalHasAnyTag(signal Signal, tags []string) bool {
	for _, expected := range tags {
		expected = strings.TrimSpace(expected)
		if expected == "" {
			continue
		}
		for _, actual := range signal.Tags {
			if strings.EqualFold(strings.TrimSpace(actual), expected) {
				return true
			}
		}
	}
	return false
}

func signalFieldValue(signal Signal, key string) (string, bool) {
	normalized := strings.TrimSpace(strings.ToLower(key))
	switch normalized {
	case "id":
		return signal.ID, signal.ID != ""
	case "kind", "type":
		return signal.Kind, signal.Kind != ""
	case "severity":
		return signal.Severity, signal.Severity != ""
	case "policy_id":
		return signal.PolicyID, signal.PolicyID != ""
	case "category":
		return signal.Category, signal.Category != ""
	case "rule_id":
		return signal.RuleID, signal.RuleID != ""
	case "resource_id":
		return signal.ResourceID, signal.ResourceID != ""
	case "resource_type":
		return signal.ResourceType, signal.ResourceType != ""
	}
	if signal.Attributes != nil {
		if value, ok := signal.Attributes[key]; ok {
			return value, true
		}
	}
	if signal.Data == nil {
		return "", false
	}
	value, ok := signal.Data[key]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%v", value), true
}

func severityMatches(actual, required string, mode SeverityMatchMode) bool {
	actual = strings.TrimSpace(strings.ToLower(actual))
	required = strings.TrimSpace(strings.ToLower(required))
	if actual == "" || required == "" {
		return actual == required
	}
	if mode == "" || mode == SeverityMatchExact {
		return actual == required
	}
	return severityRank(actual) >= severityRank(required)
}

func severityRank(value string) int {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
