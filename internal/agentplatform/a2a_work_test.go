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

func TestEvidencePacketRequestHeuristicIgnoresNonStructAction(t *testing.T) {
	request, found, err := EvidencePacketRequestFromA2ASendMessage(A2ASendMessageParams{
		Message: A2AMessage{
			Parts: []A2APart{{
				Text: "Build an evidence packet",
				Data: map[string]any{
					"action": "message/send",
				},
			}},
		},
	})
	if err != nil {
		t.Fatalf("EvidencePacketRequestFromA2ASendMessage() error = %v", err)
	}
	if !found {
		t.Fatal("found = false, want text part to produce a request")
	}
	if request.Question != "Build an evidence packet" {
		t.Fatalf("Question = %q, want text part question", request.Question)
	}
}
