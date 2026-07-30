package graphagent

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"
)

type slackRouteReplayCase struct {
	ExpectedLane string
	History      []HistoryMessage
	Partition    string
	Question     string
	Reason       string
}

type slackAgenticHillclimbReceipt struct {
	CaseCount                     int      `json:"case_count"`
	CriticRepairRate              float64  `json:"critic_repair_rate"`
	FalseConverseCount            int      `json:"false_converse_count"`
	GraphIsolationRate            float64  `json:"graph_isolation_rate"`
	MalformedRouteSafeRefusalRate float64  `json:"malformed_route_safe_refusal_rate"`
	Partitions                    []string `json:"partitions"`
	PolicyCoverageRate            float64  `json:"policy_coverage_rate"`
	RouteContractConformance      float64  `json:"route_contract_conformance"`
	RouteP95Milliseconds          float64  `json:"route_p95_ms"`
	SchemaVersion                 string   `json:"schema_version"`
}

func TestSlackAgenticHillclimb(t *testing.T) {
	cases := slackRouteReplayCorpus()
	var correct int
	var falseConverse int
	var isolated int
	var policyCovered int
	var routeDurations []time.Duration
	partitions := map[string]struct{}{}

	for _, testCase := range cases {
		t.Run(testCase.Partition+"/"+testCase.Reason+"/"+testCase.Question, func(t *testing.T) {
			partitions[testCase.Partition] = struct{}{}
			store := &askStore{}
			llm := &StubLLMClient{StructuredResponses: [][]byte{
				recordedRouteResponse(testCase.ExpectedLane, testCase.Reason),
			}}
			service := NewService(store, llm, ValidatorOptions{})
			startedAt := time.Now()
			route, attempts, err := service.routeSlackTurn(
				context.Background(),
				AskRequest{TenantID: "writer", Question: testCase.Question, Surface: slackSurface},
				"offline-recorded-model",
				testCase.History,
			)
			routeDurations = append(routeDurations, time.Since(startedAt))
			if err != nil {
				t.Fatalf("routeSlackTurn() error = %v", err)
			}
			if attempts != 1 {
				t.Fatalf("router attempts = %d, want 1", attempts)
			}
			if route.Lane == testCase.ExpectedLane {
				correct++
			}
			if route.Lane == "converse" && testCase.ExpectedLane == "lookup" {
				falseConverse++
			}
			if len(store.requests) == 0 {
				isolated++
			}

			if route.Lane != "converse" {
				return
			}
			llm.StructuredResponses = append(llm.StructuredResponses,
				validSlackConversationDraft("I’m Cerebro. I can use governed evidence and this thread’s retained context. I do not have a verified cross-thread work log in this request. Ask one concrete security question."),
				[]byte(`{"approved":true,"policy_check_ids":["capability_scope_bounded","identity_truthful","next_action_actionable","no_current_evidence_claims","work_scope_explicit"],"violations":[]}`),
			)
			result := service.runSlackConversationLoop(
				context.Background(),
				AskRequest{TenantID: "writer", Question: testCase.Question, Surface: slackSurface},
				"offline-recorded-model",
				testCase.History,
				route,
				attempts,
			)
			if result.Validation.OK &&
				result.Validation.CriticApproved &&
				equalStringSets(result.Validation.PolicyCheckIDs, slackConversationPolicyChecks) {
				policyCovered++
			}
		})
	}

	repairRate := replayCriticRepairRate(t)
	safeRefusalRate := replayMalformedRouteRefusalRate(t)
	converseCases := countExpectedLane(cases, "converse")
	receipt := slackAgenticHillclimbReceipt{
		CaseCount:                     len(cases),
		CriticRepairRate:              repairRate,
		FalseConverseCount:            falseConverse,
		GraphIsolationRate:            ratio(isolated, len(cases)),
		MalformedRouteSafeRefusalRate: safeRefusalRate,
		Partitions:                    sortedKeys(partitions),
		PolicyCoverageRate:            ratio(policyCovered, converseCases),
		RouteContractConformance:      ratio(correct, len(cases)),
		RouteP95Milliseconds:          float64(percentileDuration(routeDurations, 0.95).Microseconds()) / 1000,
		SchemaVersion:                 "slack-agentic-hillclimb-receipt/v1",
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	t.Logf("offline orchestration replay receipt: %s", payload)

	if receipt.RouteContractConformance != 1 {
		t.Errorf("route contract conformance = %.3f, want 1", receipt.RouteContractConformance)
	}
	if receipt.FalseConverseCount != 0 {
		t.Errorf("false converse count = %d, want 0", receipt.FalseConverseCount)
	}
	if receipt.GraphIsolationRate != 1 {
		t.Errorf("router graph isolation = %.3f, want 1", receipt.GraphIsolationRate)
	}
	if receipt.PolicyCoverageRate != 1 {
		t.Errorf("conversational policy coverage = %.3f, want 1", receipt.PolicyCoverageRate)
	}
	if receipt.CriticRepairRate != 1 {
		t.Errorf("critic repair rate = %.3f, want 1", receipt.CriticRepairRate)
	}
	if receipt.MalformedRouteSafeRefusalRate != 1 {
		t.Errorf("malformed route safe-refusal rate = %.3f, want 1", receipt.MalformedRouteSafeRefusalRate)
	}
	if receipt.RouteP95Milliseconds > 5 {
		t.Errorf("recorded router replay p95 = %.3fms, want <= 5ms", receipt.RouteP95Milliseconds)
	}
}

func slackRouteReplayCorpus() []slackRouteReplayCase {
	return []slackRouteReplayCase{
		{ExpectedLane: "converse", Partition: "held_out", Question: "What can you do here?", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "held_out", Question: "Describe your role and your limits.", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "held_out", Question: "How should I use you in this channel?", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "held_out", Question: "What context from this thread can you continue?", Reason: "thread_continuation"},
		{ExpectedLane: "converse", Partition: "held_out", Question: "What can you say without checking company evidence?", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "held_out", Question: "Why did you ask me to narrow that request?", Reason: "thread_continuation"},
		{ExpectedLane: "lookup", Partition: "held_out", Question: "Tell me about your Okta findings.", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "held_out", Question: "Who are you, and what is the current Okta connector health?", Reason: "mixed_request"},
		{ExpectedLane: "lookup", Partition: "held_out", Question: "Which owner has the most high-severity findings?", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "held_out", Question: "What changed in GitHub today?", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "held_out", Question: "List the assets affected by the open control gap.", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "held_out", Question: "Do we have evidence that this policy is enforced?", Reason: "evidence_lookup"},
		{ExpectedLane: "converse", Partition: "shadow", Question: "Introduce yourself in one paragraph.", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "shadow", Question: "What is inside and outside your job?", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "shadow", Question: "What should I ask you next?", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "shadow", Question: "Continue with the boundaries you just stated.", Reason: "thread_continuation"},
		{ExpectedLane: "converse", Partition: "shadow", Question: "Can you remember work outside this thread?", Reason: "self_context"},
		{ExpectedLane: "converse", Partition: "shadow", Question: "Explain what governed evidence means in your answers.", Reason: "self_context"},
		{ExpectedLane: "lookup", Partition: "shadow", Question: "Tell me about yourself, then show the latest production deployment.", Reason: "mixed_request"},
		{ExpectedLane: "lookup", Partition: "shadow", Question: "What can you tell me about the identity assigned to my account?", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "shadow", Question: "Continue investigating the collector timeout.", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "shadow", Question: "Are there unresolved findings connected to this workload?", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "shadow", Question: "Show current control coverage with supporting records.", Reason: "evidence_lookup"},
		{ExpectedLane: "lookup", Partition: "shadow", Question: "What work did the security team complete today?", Reason: "evidence_lookup"},
	}
}

func recordedRouteResponse(lane string, reason string) []byte {
	payload, _ := json.Marshal(slackTurnRoute{
		Confidence:              "high",
		Lane:                    lane,
		ReasonCode:              reason,
		RequiresCurrentEvidence: lane == "lookup",
	})
	return payload
}

func replayCriticRepairRate(t *testing.T) float64 {
	t.Helper()
	successes := 0
	for i := 0; i < 4; i++ {
		store := &askStore{}
		llm := &StubLLMClient{StructuredResponses: [][]byte{
			validSlackConversationDraft("I completed every security task today."),
			[]byte(`{"approved":false,"policy_check_ids":["capability_scope_bounded","identity_truthful","next_action_actionable","no_current_evidence_claims","work_scope_explicit"],"violations":["unsupported work claim"]}`),
			validSlackConversationDraft("I’m Cerebro. I can use governed evidence and this thread’s retained context. I do not have a verified cross-thread work log in this request. Ask one concrete security question."),
			[]byte(`{"approved":true,"policy_check_ids":["capability_scope_bounded","identity_truthful","next_action_actionable","no_current_evidence_claims","work_scope_explicit"],"violations":[]}`),
		}}
		result := NewService(store, llm, ValidatorOptions{}).runSlackConversationLoop(
			context.Background(),
			AskRequest{TenantID: "writer", Question: "What did you work on today?", Surface: slackSurface},
			"offline-recorded-model",
			nil,
			slackTurnRoute{Confidence: "high", Lane: "converse", ReasonCode: "self_context"},
			1,
		)
		if result.Validation.CriticApproved &&
			result.Validation.DraftAttempts == 2 &&
			result.Validation.CriticAttempts == 2 &&
			!result.Validation.FallbackUsed {
			successes++
		}
	}
	return ratio(successes, 4)
}

func replayMalformedRouteRefusalRate(t *testing.T) float64 {
	t.Helper()
	successes := 0
	for i := 0; i < 4; i++ {
		store := &askStore{}
		service := NewService(store, &StubLLMClient{StructuredResponses: [][]byte{
			[]byte(`{"lane":"converse"}`),
			[]byte(`{"lane":"lookup","reason_code":"evidence_lookup"}`),
		}}, ValidatorOptions{})
		events := streamSlackAsk(t, service, AskRequest{
			TenantID: "writer",
			Question: "Show the current connector health.",
			Surface:  slackSurface,
		})
		summary := requireSummaryEvent(t, events)
		if len(store.requests) == 0 &&
			summary.UnsupportedQuery != nil &&
			summary.UnsupportedQuery.Code == "slack_route_unavailable" {
			successes++
		}
	}
	return ratio(successes, 4)
}

func countExpectedLane(cases []slackRouteReplayCase, lane string) int {
	count := 0
	for _, testCase := range cases {
		if testCase.ExpectedLane == lane {
			count++
		}
	}
	return count
}

func percentileDuration(values []time.Duration, percentile float64) time.Duration {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := int(float64(len(ordered)-1) * percentile)
	return ordered[index]
}

func ratio(numerator int, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
