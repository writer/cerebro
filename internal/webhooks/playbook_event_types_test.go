package webhooks

import "testing"

func TestDefaultEventTypesIncludePlaybookLifecycleEvents(t *testing.T) {
	required := []EventType{
		EventPlatformPlaybookRunStarted,
		EventPlatformPlaybookStageCompleted,
		EventPlatformPlaybookActionExecuted,
		EventPlatformPlaybookRunCompleted,
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
