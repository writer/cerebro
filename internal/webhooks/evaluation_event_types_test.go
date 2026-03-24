package webhooks

import "testing"

func TestDefaultEventTypesIncludeEvaluationLifecycleEvents(t *testing.T) {
	required := []EventType{
		EventEvaluationTurnCompleted,
		EventEvaluationConversationCompleted,
		EventEvaluationAgentToolCall,
		EventEvaluationAgentCost,
	}

	defaults := DefaultEventTypes()
	for _, eventType := range required {
		if !containsEventType(defaults, eventType) {
			t.Fatalf("expected default event types to include %q, got %#v", eventType, defaults)
		}
		if !isValidEventType(eventType) {
			t.Fatalf("expected %q to be a valid event type", eventType)
		}
	}
}

func containsEventType(values []EventType, target EventType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
