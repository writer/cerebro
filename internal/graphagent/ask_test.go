package graphagent

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestServiceStreamsSuccessfulAskSequence(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"entity_urn":  "urn:cerebro:example:asset:alpha",
				"entity_type": "asset",
				"label":       "alpha",
			},
		}},
		graph: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:example:asset:alpha", EntityType: "asset", Label: "alpha"},
		},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Counting risky entities.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:example:asset:alpha` first.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "example",
		Question: "Which entities are risky?",
		ScopeURN: "urn:cerebro:example:asset:alpha",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	progressEvent, ok := events[0].Data.(ProgressEvent)
	if !ok {
		t.Fatalf("progress event data = %T", events[0].Data)
	}
	if progressEvent.Stage != "drafting_query" {
		t.Fatalf("first progress stage = %q, want drafting_query", progressEvent.Stage)
	}
	rowsEvent, ok := events[6].Data.(RowsEvent)
	if !ok {
		t.Fatalf("rows event data = %T", events[6].Data)
	}
	if len(rowsEvent.Rows) != 1 || rowsEvent.Rows[0]["entity_urn"] != "urn:cerebro:example:asset:alpha" {
		t.Fatalf("rows = %#v", rowsEvent.Rows)
	}
	if rowsEvent.Graph == nil || rowsEvent.Graph.Root == nil {
		t.Fatalf("graph neighborhood missing")
	}
	summaryEvent, ok := events[8].Data.(SummaryEvent)
	if !ok {
		t.Fatalf("summary event data = %T", events[8].Data)
	}
	if len(summaryEvent.Citations) != 1 || summaryEvent.Citations[0].URN != "urn:cerebro:example:asset:alpha" {
		t.Fatalf("citations = %#v", summaryEvent.Citations)
	}
	if summaryEvent.CitationValidation == nil || !summaryEvent.CitationValidation.OK {
		t.Fatalf("citation validation = %#v, want ok", summaryEvent.CitationValidation)
	}
	doneEvent := events[9].Data.(DoneEvent)
	if doneEvent.Timings.DraftMS < 0 || doneEvent.Timings.SummarizeMS < 0 || doneEvent.Timings.CitationValidationMS < 0 {
		t.Fatalf("done timings = %#v, want non-negative timings", doneEvent.Timings)
	}
	if len(store.requests) != 1 || store.requests[0].Params["tenant_id"] != "example" {
		t.Fatalf("store requests = %#v", store.requests)
	}
}

func TestServiceUsesDeterministicFastPathForCommonTopRiskAsk(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"finding_urn":                       "urn:cerebro:writer:finding:open-repo",
				"finding_label":                     "Open repository finding",
				"resource_urn":                      "urn:cerebro:writer:repo:alpha",
				"resource_label":                    "repo-alpha",
				"resource_type":                     "github.code.repository",
				"relation_attributes_json_internal": `{"risk_score":88,"status":"open"}`,
				"finding_attributes_json_internal":  `{"severity":"HIGH"}`,
			},
		}},
	}
	llm := &StubLLMClient{
		DraftErr: errors.New("draft should be skipped"),
		Summary:  "One open repository finding remains.",
	}
	service := NewServiceWithOptions(store, llm, ValidatorOptions{}, ServiceOptions{EnableDeterministicFastPath: true})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Show open high-risk repository findings",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	progressEvent := events[0].Data.(ProgressEvent)
	if progressEvent.Stage != "planning_query" {
		t.Fatalf("first progress stage = %q, want planning_query", progressEvent.Stage)
	}
	if len(llm.DraftRequests) != 0 {
		t.Fatalf("DraftCypher called %#v, want deterministic fast path to skip drafting", llm.DraftRequests)
	}
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Source != "deterministic_fast_path" || !planEvent.Deterministic || planEvent.Plan.Intent != IntentTopRiskFindings {
		t.Fatalf("query plan event = %#v, want deterministic fast path top-risk plan", planEvent)
	}
	if !strings.Contains(store.requests[0].Query, "toLower(filter_status) = 'open'") || !strings.Contains(store.requests[0].Query, "resource.entity_type = 'github.code.repository'") {
		t.Fatalf("store request should push supported filters into Cypher:\n%s", store.requests[0].Query)
	}
}

func TestServiceUsesGraphEvidenceBeforeQuestionnaireSummary(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"control_urn":                       "urn:cerebro:writer:policy:control:iam-1",
				"control_label":                     "Access control",
				"control_ref":                       "IAM-1",
				"control_attributes_json_internal":  `{"policy_type":"control","control_id":"IAM-1","status":"monitored"}`,
				"support_urn":                       "urn:cerebro:writer:okta_policy_rule:mfa-global",
				"support_label":                     "Okta MFA rule",
				"support_type":                      "okta.policy_rule",
				"support_source_id":                 "okta",
				"support_relation":                  "supports",
				"support_attributes_json_internal":  `{"status":"active","source_system":"okta"}`,
				"evidence_urn":                      "urn:cerebro:writer:runtime_evidence:okta-mfa-snapshot",
				"evidence_label":                    "Okta MFA snapshot",
				"evidence_type":                     "runtime_evidence",
				"evidence_source_id":                "okta",
				"evidence_relation":                 "has_evidence",
				"evidence_attributes_json_internal": `{"evidence_type":"okta_policy","status":"ready"}`,
				"source_urn":                        "urn:cerebro:writer:source:okta",
				"source_label":                      "Okta",
				"source_attributes_json_internal":   `{"status":"healthy","last_sync_at":"2026-06-29T12:00:00Z"}`,
			},
		}},
	}
	llm := &StubLLMClient{
		DraftErr: errors.New("draft should be skipped"),
		Summary:  "Okta MFA is supported by `urn:cerebro:writer:runtime_evidence:okta-mfa-snapshot`; review any uncovered lifecycle claims manually.",
	}
	service := NewServiceWithOptions(store, llm, ValidatorOptions{}, ServiceOptions{EnableDeterministicFastPath: true})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Does Okta enforce MFA for access?",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	if len(llm.DraftRequests) != 0 {
		t.Fatalf("DraftCypher called %#v, want deterministic graph retrieval before LLM summary", llm.DraftRequests)
	}
	if len(llm.SummaryRequests) != 1 {
		t.Fatalf("Summary requests = %#v, want one grounded LLM summary", llm.SummaryRequests)
	}
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Plan.Intent != IntentQuestionnaireEvidence || planEvent.Source != "deterministic_fast_path" {
		t.Fatalf("query plan event = %#v, want questionnaire evidence fast path", planEvent)
	}
	if !strings.Contains(store.requests[0].Query, "qauto_match_text CONTAINS 'okta'") || !strings.Contains(store.requests[0].Query, "relation: 'has_evidence'") {
		t.Fatalf("store request did not retrieve bounded questionnaire graph evidence:\n%s", store.requests[0].Query)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	for field, want := range map[string]any{
		"control_status":      "monitored",
		"support_status":      "active",
		"evidence_status":     "ready",
		"source_status":       "healthy",
		"source_last_sync_at": "2026-06-29T12:00:00Z",
	} {
		if got := rowsEvent.Rows[0][field]; got != want {
			t.Fatalf("%s = %#v, want %#v in sanitized questionnaire row %#v", field, got, want, rowsEvent.Rows[0])
		}
	}
	if got := rowsEvent.Rows[0]["status"]; got != nil {
		t.Fatalf("status = %#v, want no unprefixed status collision in questionnaire row %#v", got, rowsEvent.Rows[0])
	}
	if _, leaked := rowsEvent.Rows[0]["source_attributes_json_internal"]; leaked {
		t.Fatalf("rows leaked raw source attributes: %#v", rowsEvent.Rows[0])
	}
	summaryEvent := events[8].Data.(SummaryEvent)
	if len(summaryEvent.Citations) != 1 || summaryEvent.Citations[0].URN != "urn:cerebro:writer:runtime_evidence:okta-mfa-snapshot" {
		t.Fatalf("citations = %#v, want cited evidence urn", summaryEvent.Citations)
	}
}

func TestValidateRequestRejectsUnsupportedModel(t *testing.T) {
	err := ValidateRequest(AskRequest{
		TenantID: "writer",
		Question: "Show risky assets",
		Model:    "openrouter/private-model",
	})
	if err == nil {
		t.Fatal("ValidateRequest() error = nil, want unsupported model error")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ValidateRequest() error = %v, want ErrInvalidRequest", err)
	}
}

func TestValidateRequestAllowsConfiguredModelAliases(t *testing.T) {
	for _, model := range []string{"", DefaultModel, "claude-opus-4-7", "claude-haiku-4-5-20251001"} {
		t.Run(model, func(t *testing.T) {
			err := ValidateRequest(AskRequest{
				TenantID: "writer",
				Question: "Show risky assets",
				Model:    model,
			})
			if err != nil {
				t.Fatalf("ValidateRequest() error = %v", err)
			}
		})
	}
}

func TestCollectGraphProbeCachesTenantCounts(t *testing.T) {
	resetGraphProbeCountsCacheForTest()
	defer resetGraphProbeCountsCacheForTest()
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"name":  "source",
				"count": int64(3),
			},
		}},
	}
	request := AskRequest{TenantID: "writer", Question: "What is risky?"}

	first := collectGraphProbe(context.Background(), store, request, askParams(request))
	if first.SourceCount != 3 {
		t.Fatalf("first probe source count = %d, want 3", first.SourceCount)
	}
	if len(store.requests) != 2 {
		t.Fatalf("store requests after first probe = %d, want 2", len(store.requests))
	}
	second := collectGraphProbe(context.Background(), store, request, askParams(request))
	if second.SourceCount != 3 {
		t.Fatalf("second probe source count = %d, want cached 3", second.SourceCount)
	}
	if len(store.requests) != 2 {
		t.Fatalf("store requests after second probe = %d, want tenant count cache hit", len(store.requests))
	}
}

func TestServiceRefusesValidatorRejectedCypher(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{DraftResponse: &DraftResponse{
		Rationale: "Attempting a write query.",
		Cypher:    `MATCH (e:Entity {tenant_id: $tenant_id}) DELETE e LIMIT 25`,
	}}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "delete risky nodes"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventSummary, EventDone})
	cypherEvent := events[4].Data.(CypherEvent)
	if cypherEvent.Validator.OK {
		t.Fatalf("validator ok = true, want false")
	}
	summary := events[5].Data.(SummaryEvent)
	if summary.UnsupportedQuery == nil || summary.UnsupportedQuery.Code != "validator_refusal" || len(summary.UnsupportedQuery.SuggestedRewrites) == 0 {
		t.Fatalf("unsupported query rescue = %#v, want validator refusal with structured suggestions", summary.UnsupportedQuery)
	}
	if !stringSliceContains(summary.UnsupportedQuery.SupportedIntents, IntentQuestionnaireEvidence) {
		t.Fatalf("supported intents = %#v, want questionnaire evidence intent", summary.UnsupportedQuery.SupportedIntents)
	}
	if !stringSliceContains(summary.UnsupportedQuery.SuggestedRewrites, "Answer an Okta MFA questionnaire item from bounded graph evidence.") {
		t.Fatalf("suggested rewrites = %#v, want questionnaire evidence rewrite", summary.UnsupportedQuery.SuggestedRewrites)
	}
	done := events[6].Data.(DoneEvent)
	if !done.CypherRefused {
		t.Fatalf("done.CypherRefused = false, want true")
	}
	if len(store.requests) != 0 {
		t.Fatalf("store executed rejected query: %#v", store.requests)
	}
}

func TestServiceRefusesUnsupportedPlanOnlyDraftAsConversionFailure(t *testing.T) {
	store := &askStore{}
	llm := &StubLLMClient{DraftResponse: &DraftResponse{
		Rationale: "Planning filtered high-risk findings.",
		Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"owner": "security"}},
	}}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "show security-owned risk findings"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventCypher, EventSummary, EventDone})
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Source != "conversion_refusal" || len(planEvent.Diagnostics) == 0 || planEvent.Diagnostics[0].Code != "query_plan_conversion_failed" {
		t.Fatalf("query plan event = %#v, want conversion refusal diagnostic", planEvent)
	}
	cypherEvent := events[3].Data.(CypherEvent)
	if cypherEvent.Validator.OK || strings.Contains(cypherEvent.Validator.Reason, "LLM refused") {
		t.Fatalf("cypher validator = %#v, want backend conversion refusal", cypherEvent.Validator)
	}
	if !strings.Contains(cypherEvent.Validator.Reason, "could not be converted") {
		t.Fatalf("refusal reason = %q, want conversion failure", cypherEvent.Validator.Reason)
	}
	summaryEvent := events[4].Data.(SummaryEvent)
	if summaryEvent.UnsupportedQuery == nil || summaryEvent.UnsupportedQuery.Code != "query_plan_conversion_failed" {
		t.Fatalf("unsupported query = %#v, want conversion rescue", summaryEvent.UnsupportedQuery)
	}
	if len(store.requests) != 0 {
		t.Fatalf("store executed conversion-refused query: %#v", store.requests)
	}
}

func TestServiceClassifiesEmptyDraftAsLLMRefusal(t *testing.T) {
	service := NewService(&askStore{}, &StubLLMClient{DraftResponse: &DraftResponse{}}, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "example", Question: "what is risky?"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventCypher, EventSummary, EventDone})
	summary := events[4].Data.(SummaryEvent)
	if summary.UnsupportedQuery == nil || summary.UnsupportedQuery.Code != "llm_refusal" {
		t.Fatalf("unsupported query = %#v, want llm_refusal", summary.UnsupportedQuery)
	}
}

func TestServiceFlagsUngroundedSummaryURNs(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"finding_urn": "urn:cerebro:writer:finding:alpha",
				"resource_urns": []any{
					"urn:cerebro:writer:repo:writerinternal/cerebro",
				},
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Finding scoped graph rows.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS finding_urn
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:writer:finding:missing` immediately.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "writer", Question: "What is risky?"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	summary := events[8].Data.(SummaryEvent)
	if summary.CitationValidation == nil || summary.CitationValidation.OK {
		t.Fatalf("citation validation = %#v, want ungrounded warning", summary.CitationValidation)
	}
	if got := strings.Join(summary.CitationValidation.Warnings, ","); !strings.Contains(got, "summary_urn_not_row_backed") {
		t.Fatalf("warnings = %v, want summary grounding warning", summary.CitationValidation.Warnings)
	}
}

func TestServiceConvertsFindingSourceAggregationDraft(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{
			{
				Values: map[string]any{
					"finding_urn":                      "urn:cerebro:writer:finding:alpha",
					"source_id":                        "fallback",
					"finding_attributes_json_internal": "{\n  \"source_family\": \"okta\"\n}",
				},
			},
			{
				Values: map[string]any{
					"finding_urn":                      "urn:cerebro:writer:finding:beta",
					"source_id":                        "fallback",
					"finding_attributes_json_internal": `{"sourceFamily":"okta"}`,
				},
			},
			{
				Values: map[string]any{
					"finding_urn":                      "urn:cerebro:writer:finding:gamma",
					"source_id":                        "fallback",
					"finding_attributes_json_internal": `{"source_system":"GitHub \"Enterprise\""}`,
				},
			},
		},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Counting findings by source family.",
			Cypher: `MATCH (f:Entity {tenant_id: $tenant_id})
WHERE f.entity_type = 'Finding'
OPTIONAL MATCH (f)-[r:RELATION]->(src:Entity {tenant_id: $tenant_id})
WHERE r.relation = 'HAS_SOURCE' OR r.relation = 'BELONGS_TO_SOURCE'
WITH f, src,
     coalesce(src.label,
              apoc.convert.fromJsonMap(f.attributes_json).source_family,
              apoc.convert.fromJsonMap(f.attributes_json).sourceFamily,
              'Unknown') AS source_family
RETURN source_family, count(f) AS finding_count
ORDER BY finding_count DESC
LIMIT 10`,
		},
		Summary: "okta has the most findings.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{TenantID: "writer", Question: "top finding sources"}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Plan.Intent != IntentAggregateFindingsBySource || !planEvent.Deterministic || !planEvent.Corrected {
		t.Fatalf("query plan event = %#v, want deterministic corrected source aggregation", planEvent)
	}
	cypher := events[4].Data.(CypherEvent)
	if !cypher.Validator.OK {
		t.Fatalf("validator = %#v, want ok", cypher.Validator)
	}
	if strings.Contains(cypher.Cypher, "apoc.") || strings.Contains(cypher.Cypher, "HAS_SOURCE") || strings.Contains(cypher.Cypher, "entity_type = 'Finding'") {
		t.Fatalf("cypher was not canonicalized:\n%s", cypher.Cypher)
	}
	if len(store.requests) != 1 || !strings.Contains(store.requests[0].Query, "entity_type: 'finding'") || !strings.Contains(store.requests[0].Query, "finding_attributes_json_internal") {
		t.Fatalf("store request = %#v", store.requests)
	}
	if strings.Contains(store.requests[0].Query, "split(split") || strings.Contains(store.requests[0].Query, "count(DISTINCT f)") {
		t.Fatalf("store request should leave JSON parsing and aggregation to Go:\n%s", store.requests[0].Query)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	if len(rowsEvent.Rows) != 2 {
		t.Fatalf("rows = %#v, want two source groups", rowsEvent.Rows)
	}
	if rowsEvent.Rows[0]["source_family"] != "okta" || rowsEvent.Rows[0]["finding_count"] != int64(2) {
		t.Fatalf("first source row = %#v, want okta count 2", rowsEvent.Rows[0])
	}
	if rowsEvent.Rows[1]["source_family"] != `GitHub "Enterprise"` || rowsEvent.Rows[1]["finding_count"] != int64(1) {
		t.Fatalf("second source row = %#v, want escaped source_system fallback", rowsEvent.Rows[1])
	}
}

func TestServicePostProcessesTopRiskFindingRows(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{
			{
				Values: map[string]any{
					"finding_urn":                       "urn:cerebro:writer:finding:alpha",
					"finding_label":                     "Alpha",
					"resource_urn":                      "urn:cerebro:writer:asset:alpha",
					"resource_label":                    "Alpha resource",
					"relation_attributes_json_internal": `{}`,
					"finding_attributes_json_internal":  `{"risk_score":"40","severity":"CRITICAL"}`,
				},
			},
			{
				Values: map[string]any{
					"finding_urn":                       "urn:cerebro:writer:finding:beta",
					"finding_label":                     "Beta",
					"resource_urn":                      "urn:cerebro:writer:asset:beta",
					"resource_label":                    "Beta resource",
					"relation_attributes_json_internal": "{\n  \"risk_score\": 95\n}",
					"finding_attributes_json_internal":  `{"severity":"HIGH"}`,
				},
			},
			{
				Values: map[string]any{
					"finding_urn":                       "urn:cerebro:writer:finding:gamma",
					"finding_label":                     "Gamma",
					"resource_urn":                      "urn:cerebro:writer:asset:gamma",
					"resource_label":                    "Gamma resource",
					"relation_attributes_json_internal": `{}`,
					"finding_attributes_json_internal":  `{}`,
				},
			},
		},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Ranking risky findings.",
			Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Limit: 2},
		},
		Summary: "Beta is highest risk.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Show top risk findings for this asset",
		ScopeURN: "urn:cerebro:writer:asset:beta",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if len(store.requests) != 1 || !strings.Contains(store.requests[0].Query, "relation_attributes_json_internal") {
		t.Fatalf("store request = %#v, want internal relation attributes", store.requests)
	}
	if !strings.Contains(store.requests[0].Query, "WHERE $scope_urn = '' OR resource.urn = $scope_urn OR finding.urn = $scope_urn") {
		t.Fatalf("store request missing scope predicate:\n%s", store.requests[0].Query)
	}
	if strings.Contains(store.requests[0].Query, "split(split") || strings.Contains(store.requests[0].Query, "CASE toUpper") {
		t.Fatalf("store request should leave JSON parsing and ranking to Go:\n%s", store.requests[0].Query)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	if len(rowsEvent.Rows) != 2 {
		t.Fatalf("rows = %#v, want two limited top-risk rows", rowsEvent.Rows)
	}
	first := rowsEvent.Rows[0]
	if first["finding_urn"] != "urn:cerebro:writer:finding:beta" || first["risk_score"] != 95 || first["severity"] != "HIGH" {
		t.Fatalf("first top-risk row = %#v, want beta risk 95 HIGH", first)
	}
	if _, exists := first["finding_attributes_json_internal"]; exists {
		t.Fatalf("internal finding attributes leaked: %#v", first)
	}
	if _, exists := first["relation_attributes_json_internal"]; exists {
		t.Fatalf("internal relation attributes leaked: %#v", first)
	}
}

func TestServicePostProcessesTopRiskSeverityPrecedence(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"finding_urn":                       "urn:cerebro:writer:finding:alpha",
				"finding_label":                     "Alpha",
				"resource_urn":                      "urn:cerebro:writer:asset:alpha",
				"resource_label":                    "Alpha resource",
				"relation_attributes_json_internal": `{"severity":"LOW"}`,
				"finding_attributes_json_internal":  `{"effective_severity":"CRITICAL","severity":"MEDIUM"}`,
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Ranking risky findings.",
			Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Limit: 1},
		},
		Summary: "Alpha is critical.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Show top risk findings",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	if len(rowsEvent.Rows) != 1 || rowsEvent.Rows[0]["severity"] != "CRITICAL" {
		t.Fatalf("rows = %#v, want finding effective severity before relation plain severity", rowsEvent.Rows)
	}
}

func TestServiceDoesNotPostProcessLLMFallbackRows(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"finding_urn":   "urn:cerebro:writer:finding:alpha",
				"finding_label": "Alpha",
				"risk_score":    88,
				"severity":      "HIGH",
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Ranking filtered risky findings.",
			Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"source_family": "okta"}, Limit: 10},
			Cypher: `MATCH (finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
RETURN finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       88 AS risk_score,
       'HIGH' AS severity
LIMIT 10`,
		},
		Summary: "Alpha is highest risk.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Show Okta top risk findings",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	planEvent := events[2].Data.(QueryPlanEvent)
	if planEvent.Deterministic || planEvent.Source != "llm" {
		t.Fatalf("query plan event = %#v, want LLM fallback", planEvent)
	}
	if len(store.requests) != 1 || store.requests[0].RowLimit != 10 {
		t.Fatalf("store request = %#v, want fallback row limit", store.requests)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	if len(rowsEvent.Rows) != 1 || rowsEvent.Rows[0]["risk_score"] != 88 || rowsEvent.Rows[0]["severity"] != "HIGH" {
		t.Fatalf("rows = %#v, want unmodified fallback rows", rowsEvent.Rows)
	}
}

func TestServiceRefusesSaturatedPostProcessingCandidateWindow(t *testing.T) {
	rows := make([]ports.CypherRow, 0, postProcessingCandidateRowLimit)
	for i := 0; i < postProcessingCandidateRowLimit; i++ {
		rows = append(rows, ports.CypherRow{Values: map[string]any{
			"finding_urn":                      "urn:cerebro:writer:finding:" + strconv.Itoa(i),
			"source_id":                        "github",
			"finding_attributes_json_internal": `{"source_family":"github"}`,
		}})
	}
	store := &askStore{rows: rows}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Counting findings by source family.",
			Plan:      &AskQueryPlan{Intent: IntentAggregateFindingsBySource, Limit: 10},
		},
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "top finding sources",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventSummary, EventDone})
	if len(store.requests) != 1 || store.requests[0].RowLimit != postProcessingCandidateRowLimit {
		t.Fatalf("store requests = %#v, want candidate row limit", store.requests)
	}
	summaryEvent := events[6].Data.(SummaryEvent)
	if !strings.Contains(summaryEvent.Markdown, "more graph rows than can be safely post-processed") {
		t.Fatalf("summary = %q, want saturated candidate refusal", summaryEvent.Markdown)
	}
	done := events[7].Data.(DoneEvent)
	if !done.CypherRefused {
		t.Fatalf("done.CypherRefused = false, want true")
	}
}

func TestServicePushesTopRiskFiltersBeforeCandidateLimit(t *testing.T) {
	rows := []ports.CypherRow{{
		Values: map[string]any{
			"finding_urn":                       "urn:cerebro:writer:finding:open-repo",
			"finding_label":                     "Open repository finding",
			"resource_urn":                      "urn:cerebro:writer:repo:alpha",
			"resource_label":                    "repo-alpha",
			"resource_type":                     "github.code.repository",
			"relation_attributes_json_internal": `{"risk_score":88,"severity":"HIGH","status":"open"}`,
			"finding_attributes_json_internal":  `{}`,
		},
	}}
	store := &askStore{rows: rows}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Filtering open repository risk.",
			Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Limit: 10, Filters: map[string]string{"status": "open", "resource_type": "repository"}},
		},
		Summary: "One open repository finding remains.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Show open high-risk repository findings",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	assertEventNames(t, events, []string{EventProgress, EventRationale, EventQueryPlan, EventProgress, EventCypher, EventProgress, EventRows, EventProgress, EventSummary, EventDone})
	if !strings.Contains(store.requests[0].Query, "toLower(filter_status) = 'open'") || !strings.Contains(store.requests[0].Query, "resource.entity_type = 'github.code.repository'") {
		t.Fatalf("store request should push supported filters into Cypher:\n%s", store.requests[0].Query)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	if len(rowsEvent.Rows) != 1 {
		t.Fatalf("rows = %#v, want one filtered top-risk row", rowsEvent.Rows)
	}
	done := events[9].Data.(DoneEvent)
	if done.CypherRefused {
		t.Fatalf("done.CypherRefused = true, want filtered saturated candidate window to proceed")
	}
}

func TestResourceTypeMatchesRepositoryFilterByEntityTypeOnly(t *testing.T) {
	if resourceTypeMatchesFilter("github.runner", "repository") {
		t.Fatal("repository filter matched github.runner because its URN contains repo")
	}
	if !resourceTypeMatchesFilter("github.code.repository", "repository") {
		t.Fatal("repository filter did not match github.code.repository entity type")
	}
}

func TestServiceSanitizesInternalFindingAttributes(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"finding_urn":                      "urn:cerebro:writer:finding:quoted-summary",
				"finding_label":                    "Quoted finding",
				"summary":                          "",
				"status":                           "",
				"severity":                         "",
				"finding_attributes_json_internal": `{"summary":"Okta policy rule \"Admins\" is INACTIVE","status":"open","severity":"HIGH","risk_score":"47"}`,
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Explaining the scoped finding.",
			Plan:      &AskQueryPlan{Intent: IntentExplainFinding, Limit: 25},
		},
		Summary: "Quoted finding should be reviewed.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Explain this finding",
		ScopeURN: "urn:cerebro:writer:finding:quoted-summary",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	row := rowsEvent.Rows[0]
	if _, exists := row["finding_attributes_json_internal"]; exists {
		t.Fatalf("internal attributes leaked in row: %#v", row)
	}
	if got := row["summary"]; got != `Okta policy rule "Admins" is INACTIVE` {
		t.Fatalf("summary = %q, want full quoted summary", got)
	}
	if got := row["severity"]; got != "HIGH" {
		t.Fatalf("severity = %q, want HIGH", got)
	}
}

func TestServiceSanitizesInternalSourceAttributes(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"source_urn":                      "urn:cerebro:writer:source:github",
				"source_label":                    "GitHub",
				"source_id":                       "github",
				"runtime_id":                      "runtime-1",
				"source_attributes_json_internal": `{"status":"healthy","last_sync_minutes":3,"last_error":"none"}`,
			},
		}},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Checking source health.",
			Plan:      &AskQueryPlan{Intent: IntentConnectorHealth, Limit: 25},
		},
		Summary: "GitHub is healthy.",
	}
	service := NewService(store, llm, ValidatorOptions{})

	var events []Event
	err := service.Stream(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Show GitHub health",
		ScopeURN: "urn:cerebro:writer:source:github",
	}, func(event Event) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	rowsEvent := events[6].Data.(RowsEvent)
	row := rowsEvent.Rows[0]
	if _, exists := row["source_attributes_json_internal"]; exists {
		t.Fatalf("internal source attributes leaked in row: %#v", row)
	}
	if got := row["status"]; got != "healthy" {
		t.Fatalf("status = %q, want healthy", got)
	}
	if got := row["last_sync_minutes"]; got != "3" {
		t.Fatalf("last_sync_minutes = %q, want 3", got)
	}
	if len(store.requests) != 1 || !strings.Contains(store.requests[0].Query, "source_attributes_json_internal") {
		t.Fatalf("store request = %#v, want internal source attributes", store.requests)
	}
}

func TestSanitizeInternalAttributesKeepsOnlyBoundedScalars(t *testing.T) {
	rows := []map[string]any{{
		"finding_attributes_json_internal": `{"summary":"` + strings.Repeat("a", maxInternalAttributeValueBytes+20) + `","status":{"nested":true},"risk_score":73}`,
	}}

	sanitizeInternalRowFields(rows)

	row := rows[0]
	if _, exists := row["finding_attributes_json_internal"]; exists {
		t.Fatalf("internal attributes leaked in row: %#v", row)
	}
	summary, ok := row["summary"].(string)
	if !ok {
		t.Fatalf("summary = %#v, want string", row["summary"])
	}
	if len(summary) != maxInternalAttributeValueBytes {
		t.Fatalf("summary length = %d, want %d", len(summary), maxInternalAttributeValueBytes)
	}
	if _, exists := row["status"]; exists {
		t.Fatalf("structured status should not be merged into row: %#v", row)
	}
	if got := row["risk_score"]; got != "73" {
		t.Fatalf("risk_score = %q, want 73", got)
	}
}

func TestSanitizeInternalAttributesDropsRawGraphAttributes(t *testing.T) {
	type projectedNode struct {
		Props map[string]any
	}
	rows := []map[string]any{{
		"attributes_json":                  `{"secret":"raw"}`,
		"finding_attributes_json":          `{"secret":"raw"}`,
		"finding_attributes_json_internal": `{"severity":"HIGH"}`,
		"node":                             projectedNode{Props: map[string]any{"urn": "urn:cerebro:writer:asset:alpha", "attributes_json": `{"secret":"raw"}`}},
		"nested":                           map[string]any{"safe": "value", "attributes_json": `{"secret":"raw"}`},
	}}

	sanitizeInternalRowFields(rows)

	row := rows[0]
	for _, key := range []string{"attributes_json", "finding_attributes_json", "finding_attributes_json_internal"} {
		if _, exists := row[key]; exists {
			t.Fatalf("%s leaked in row: %#v", key, row)
		}
	}
	if got := row["severity"]; got != "HIGH" {
		t.Fatalf("severity = %q, want HIGH", got)
	}
	if got := row["node"]; got != redactedGraphRowValue {
		t.Fatalf("node = %#v, want redacted graph value", got)
	}
	nested, ok := row["nested"].(map[string]any)
	if !ok || nested["safe"] != "value" {
		t.Fatalf("nested = %#v, want sanitized map", row["nested"])
	}
	if _, exists := nested["attributes_json"]; exists {
		t.Fatalf("nested raw attributes leaked: %#v", nested)
	}
}

func TestServiceRequiresTenantID(t *testing.T) {
	service := NewService(&askStore{}, NewStubLLMClient(), ValidatorOptions{})
	err := service.Stream(context.Background(), AskRequest{Question: "hello"}, func(Event) error { return nil })
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Stream() error = %v, want tenant_id validation", err)
	}
}

func assertEventNames(t *testing.T, events []Event, want []string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("events len = %d, want %d (%#v)", len(events), len(want), events)
	}
	for i, name := range want {
		if events[i].Name != name {
			t.Fatalf("event[%d] = %q, want %q", i, events[i].Name, name)
		}
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type askStore struct {
	requests []ports.CypherQueryRequest
	rows     []ports.CypherRow
	graph    *ports.EntityNeighborhood
}

func (s *askStore) Ping(context.Context) error { return nil }

func (s *askStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	if s.graph != nil {
		return s.graph, nil
	}
	return nil, ports.ErrGraphEntityNotFound
}

func (s *askStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	if len(request.Query) >= len("EXPLAIN ") && request.Query[:len("EXPLAIN ")] == "EXPLAIN " {
		return nil, nil
	}
	return s.rows, nil
}

var _ ports.GraphQueryStore = (*askStore)(nil)
