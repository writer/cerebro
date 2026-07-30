package graphagent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestSlackSelfAndWorkTodayUsesAgentReceiptEvidence(t *testing.T) {
	receiptURN := "urn:cerebro:writer:trusted_endpoint_event:agent-receipt-1"
	store := &askStore{rows: []ports.CypherRow{{
		Values: map[string]any{
			"receipt_urn":        receiptURN,
			"receipt_label":      "receipt-1",
			"captured_at":        "2026-07-30T01:20:00Z",
			"phase":              "completed",
			"agent_product":      "Codex",
			"action":             "git push",
			"outcome_result":     "",
			"evidence_integrity": "authenticated_device_claim",
			"receipt_id":         "receipt-1",
			"overclaim_guard":    "Today is evaluated in UTC.",
		},
	}}}
	llm := &StubLLMClient{
		StructuredResponses: [][]byte{
			[]byte(`{"confidence":"high","lane":"lookup","reason_code":"agent_work_history","requires_current_evidence":true}`),
		},
		DraftResponse: &DraftResponse{
			Rationale: "Reading minimized agent execution receipts for today.",
			Plan: &AskQueryPlan{
				Intent:     IntentAgentWorkHistory,
				Confidence: 0.99,
				Limit:      25,
			},
		},
		Summary: "I’m Cerebro, Writer’s security operations assistant. Today’s receipt evidence includes a completed `git push` action at `urn:cerebro:writer:trusted_endpoint_event:agent-receipt-1`. This proves the minimized tool action, not broader task completion.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	events := streamSlackAsk(t, service, AskRequest{
		TenantID: "writer",
		Question: "What can you tell me about yourself and your work today?",
		Surface:  "slack",
	})

	if len(store.requests) != 1 {
		t.Fatalf("graph requests = %d, want 1", len(store.requests))
	}
	if len(llm.DraftRequests) != 1 || len(llm.SummaryRequests) != 1 {
		t.Fatalf("graph model calls = draft %d summary %d, want one planner and one synthesis call", len(llm.DraftRequests), len(llm.SummaryRequests))
	}
	if len(llm.StructuredRequests) != 1 {
		t.Fatalf("structured router calls = %d, want 1", len(llm.StructuredRequests))
	}
	if !strings.Contains(store.requests[0].Query, "trusted_endpoint.agent_execution_receipt_observation") ||
		!strings.Contains(store.requests[0].Query, "captured_at >= $today_utc") {
		t.Fatalf("graph query = %q, want current UTC agent receipt template", store.requests[0].Query)
	}
	summary := requireSummaryEvent(t, events)
	if summary.ExecutionLane != "lookup" {
		t.Fatalf("execution lane = %q, want lookup", summary.ExecutionLane)
	}
	if summary.ConversationValidation != nil {
		t.Fatalf("conversation validation = %#v, want none", summary.ConversationValidation)
	}
	if summary.CitationValidation == nil || !summary.CitationValidation.OK {
		t.Fatalf("citation validation = %#v, want receipt-backed answer", summary.CitationValidation)
	}
	if !strings.Contains(summary.Markdown, "Cerebro") || !strings.Contains(summary.Markdown, receiptURN) {
		t.Fatalf("summary = %q, want identity and cited work receipt", summary.Markdown)
	}
}

func TestSlackMixedSelfAndEvidenceRequestPreservesGraphLookup(t *testing.T) {
	store := &askStore{rows: []ports.CypherRow{{
		Values: map[string]any{
			"entity_urn":  "urn:cerebro:writer:asset:alpha",
			"entity_type": "asset",
			"label":       "alpha",
		},
	}}}
	llm := &StubLLMClient{
		StructuredResponses: [][]byte{
			[]byte(`{"confidence":"high","lane":"lookup","reason_code":"mixed_request","requires_current_evidence":true}`),
		},
		Summary: "Review `urn:cerebro:writer:asset:alpha` first.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	events := streamSlackAsk(t, service, AskRequest{
		TenantID: "writer",
		Question: "Who are you, and show the latest connector health?",
		Surface:  "slack",
	})

	if len(store.requests) != 1 {
		t.Fatalf("graph requests = %d, want 1", len(store.requests))
	}
	summary := requireSummaryEvent(t, events)
	if summary.ExecutionLane != "lookup" {
		t.Fatalf("execution lane = %q, want lookup", summary.ExecutionLane)
	}
	if summary.CitationValidation == nil || !summary.CitationValidation.OK {
		t.Fatalf("citation validation = %#v, want ok", summary.CitationValidation)
	}
	if summary.ConversationValidation != nil {
		t.Fatalf("conversation validation = %#v, want none", summary.ConversationValidation)
	}
}

func TestSlackConversationLoopRepairsACriticRejectedDraft(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{StructuredResponses: [][]byte{
		[]byte(`{"confidence":"high","lane":"converse","reason_code":"self_context","requires_current_evidence":false}`),
		validSlackConversationDraft("I reviewed all of today's security changes. Ask me what changed."),
		[]byte(`{
			"approved":false,
			"policy_check_ids":["identity_truthful","capability_scope_bounded","work_scope_explicit","no_current_evidence_claims","next_action_actionable"],
			"violations":["The draft invents completed work."]
		}`),
		validSlackConversationDraft("I’m Cerebro. I can use governed evidence and this thread’s retained context. I do not have a verified cross-thread work log in this request. Ask one concrete security question."),
		[]byte(`{
			"approved":true,
			"policy_check_ids":["identity_truthful","capability_scope_bounded","work_scope_explicit","no_current_evidence_claims","next_action_actionable"],
			"violations":[]
		}`),
	}}
	service := NewService(store, llm, ValidatorOptions{})

	events := streamSlackAsk(t, service, AskRequest{
		TenantID: "writer",
		Question: "Tell me about yourself and your work today.",
		Surface:  "slack",
	})

	summary := requireSummaryEvent(t, events)
	if summary.ConversationValidation == nil {
		t.Fatal("conversation validation missing")
	}
	if summary.ConversationValidation.DraftAttempts != 2 ||
		summary.ConversationValidation.CriticAttempts != 2 ||
		!summary.ConversationValidation.CriticApproved ||
		summary.ConversationValidation.FallbackUsed {
		t.Fatalf("conversation validation = %#v, want repaired second round", summary.ConversationValidation)
	}
	if strings.Contains(summary.Markdown, "I reviewed all of today's") {
		t.Fatalf("summary retained rejected claim: %q", summary.Markdown)
	}
}

func TestSlackRouterFailureRefusesWithoutGuessingOrQuerying(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{StructuredResponses: [][]byte{
		[]byte(`{"lane":"converse"}`),
		[]byte(`{"lane":"converse"}`),
	}}
	service := NewService(store, llm, ValidatorOptions{})

	events := streamSlackAsk(t, service, AskRequest{
		TenantID: "writer",
		Question: "Tell me about your current findings.",
		Surface:  "slack",
	})

	if len(store.requests) != 0 {
		t.Fatalf("graph requests = %d, want 0", len(store.requests))
	}
	summary := requireSummaryEvent(t, events)
	if summary.UnsupportedQuery == nil || summary.UnsupportedQuery.Code != "slack_route_unavailable" {
		t.Fatalf("unsupported query = %#v, want route refusal", summary.UnsupportedQuery)
	}
	if !strings.Contains(summary.Markdown, "safe Slack execution lane") {
		t.Fatalf("summary = %q, want bounded route failure", summary.Markdown)
	}
}

func TestSlackRouterRepairsAnInvalidFirstDecision(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{StructuredResponses: [][]byte{
		[]byte(`{"confidence":"high","lane":"converse","reason_code":"evidence_lookup","requires_current_evidence":false}`),
		[]byte(`{"confidence":"high","lane":"lookup","reason_code":"evidence_lookup","requires_current_evidence":true}`),
	}}
	service := NewService(store, llm, ValidatorOptions{})

	route, attempts, err := service.routeSlackTurn(
		context.Background(),
		AskRequest{TenantID: "writer", Question: "Tell me about your Okta findings.", Surface: slackSurface},
		"offline-recorded-model",
		nil,
	)
	if err != nil {
		t.Fatalf("routeSlackTurn() error = %v", err)
	}
	if route.Lane != "lookup" || attempts != 2 {
		t.Fatalf("route = %#v after %d attempts, want lookup after repair", route, attempts)
	}
	if got := llm.StructuredRequests[1].Context["prior_failure"]; got != "route_policy_invalid" {
		t.Fatalf("second route prior_failure = %#v, want route_policy_invalid", got)
	}
}

func TestSlackConversationUsesBoundedFallbackAfterTwoInvalidDrafts(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{StructuredResponses: [][]byte{
		[]byte(`{"markdown":"missing required fields"}`),
		[]byte(`{"markdown":"still missing required fields"}`),
		[]byte(`{"markdown":"third invalid draft"}`),
		[]byte(`{"markdown":"fourth invalid draft"}`),
	}}
	service := NewService(store, llm, ValidatorOptions{})

	result := service.runSlackConversationLoop(
		context.Background(),
		AskRequest{TenantID: "writer", Question: "What can you do?", Surface: slackSurface},
		"offline-recorded-model",
		nil,
		slackTurnRoute{
			Confidence: "high",
			Lane:       "converse",
			ReasonCode: "self_context",
		},
		1,
	)
	if !result.Validation.OK ||
		!result.Validation.FallbackUsed ||
		result.Validation.CriticApproved ||
		result.Validation.DraftAttempts != 4 ||
		result.Validation.CriticAttempts != 0 {
		t.Fatalf("fallback validation = %#v, want bounded four-draft fallback", result.Validation)
	}
	if result.Markdown != slackConversationFallback {
		t.Fatalf("fallback markdown = %q, want fixed bounded fallback", result.Markdown)
	}
}

func streamSlackAsk(t *testing.T, service *Service, request AskRequest) []Event {
	t.Helper()
	var events []Event
	if err := service.Stream(context.Background(), request, func(event Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	return events
}

func requireSummaryEvent(t *testing.T, events []Event) SummaryEvent {
	t.Helper()
	for _, event := range events {
		if event.Name != EventSummary {
			continue
		}
		summary, ok := event.Data.(SummaryEvent)
		if !ok {
			t.Fatalf("summary event data = %T", event.Data)
		}
		return summary
	}
	t.Fatal("summary event missing")
	return SummaryEvent{}
}

func validSlackConversationDraft(markdown string) []byte {
	payload, _ := json.Marshal(map[string]any{
		"claims": []map[string]string{
			{"fact_id": "identity_cerebro_security_ops_assistant", "kind": "identity", "source_ref": "manifest://cerebro/slack-capabilities/v1"},
			{"fact_id": "capability_governed_evidence_questions", "kind": "capability", "source_ref": "manifest://cerebro/slack-capabilities/v1"},
			{"fact_id": "boundary_no_cross_thread_work_log", "kind": "scope_boundary", "source_ref": "manifest://cerebro/slack-capabilities/v1"},
		},
		"markdown":     markdown,
		"next_actions": []string{"Ask one concrete security question."},
		"work_scope":   "thread_only",
	})
	return payload
}
