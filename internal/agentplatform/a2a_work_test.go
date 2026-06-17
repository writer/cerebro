package agentplatform

import (
	"encoding/json"
	"testing"
)

func TestDecodeA2ASendMessageParamsAllowsProtocolExtensions(t *testing.T) {
	raw := json.RawMessage(`{
		"tenant": "writer",
		"message": {
			"role": "ROLE_USER",
			"messageId": "message-1",
			"contextId": "ctx-1",
			"parts": [{"text": "Build an evidence packet", "mediaType": "text/plain"}],
			"protocolExtension": {"traceId": "trace-1"}
		},
		"configuration": {
			"acceptedOutputModes": ["application/json"],
			"returnImmediately": true,
			"streamingPreference": "poll"
		},
		"metadata": {"skillId": "agent-evidence-packet"},
		"futureProtocolField": true
	}`)

	params, err := DecodeA2ASendMessageParams(raw)
	if err != nil {
		t.Fatalf("DecodeA2ASendMessageParams() error = %v", err)
	}
	if params.Message.MessageID != "message-1" {
		t.Fatalf("messageId = %q, want message-1", params.Message.MessageID)
	}
	if !params.Configuration.ReturnImmediately {
		t.Fatal("returnImmediately = false, want true")
	}
}

func TestDecodeA2AParamsRejectsMultipleJSONValues(t *testing.T) {
	raw := json.RawMessage(`{"id":"task-1"} {"id":"task-2"}`)

	if _, err := DecodeA2AGetTaskParams(raw); err == nil {
		t.Fatal("DecodeA2AGetTaskParams() error = nil, want multiple JSON values error")
	}
}
