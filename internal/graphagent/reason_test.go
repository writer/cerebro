package graphagent

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestServiceReasonReturnsStructuredGraphEnvelope(t *testing.T) {
	store := &askStore{
		rows: []ports.CypherRow{{
			Values: map[string]any{
				"entity_urn":  "urn:cerebro:writer:asset:alpha",
				"entity_type": "asset",
				"label":       "alpha",
			},
		}},
		graph: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:asset:alpha", EntityType: "asset", Label: "alpha"},
		},
	}
	llm := &StubLLMClient{
		DraftResponse: &DraftResponse{
			Rationale: "Finding scoped graph rows.",
			Cypher: `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS entity_urn, e.entity_type AS entity_type, e.label AS label
LIMIT 25`,
		},
		Summary: "Review `urn:cerebro:writer:asset:alpha` first.",
	}
	service := NewServiceWithOptions(store, llm, ValidatorOptions{}, ServiceOptions{
		EnableGraphProbes: true,
	})

	response, err := service.Reason(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "Which scoped asset should I review?",
		ScopeURN: "urn:cerebro:writer:asset:alpha",
	})
	if err != nil {
		t.Fatalf("Reason() error = %v", err)
	}
	if response.TraceID == "" || response.Provenance.TraceID != response.TraceID {
		t.Fatalf("trace/provenance = %#v", response.Provenance)
	}
	if response.Probe == nil {
		t.Fatal("response missing graph probe")
	}
	if response.QueryPlan == nil || response.QueryPlan.Plan.Intent == "" {
		t.Fatalf("query plan = %#v, want populated plan", response.QueryPlan)
	}
	if response.Cypher == nil || !response.Cypher.Validator.OK {
		t.Fatalf("cypher = %#v, want validated query", response.Cypher)
	}
	if len(response.Rows) != 1 || response.Rows[0]["entity_urn"] != "urn:cerebro:writer:asset:alpha" {
		t.Fatalf("rows = %#v", response.Rows)
	}
	if response.Graph == nil || response.Graph.Root == nil {
		t.Fatal("response missing graph neighborhood")
	}
	if response.AnswerMarkdown != "Review `urn:cerebro:writer:asset:alpha` first." {
		t.Fatalf("answer = %q", response.AnswerMarkdown)
	}
	if len(response.Citations) != 1 || response.Citations[0].URN != "urn:cerebro:writer:asset:alpha" {
		t.Fatalf("citations = %#v", response.Citations)
	}
	if response.CitationValidation == nil || !response.CitationValidation.OK {
		t.Fatalf("citation validation = %#v", response.CitationValidation)
	}
	if response.Provenance.Surface != "graph-reasoning" || response.Provenance.CitationStatus != "valid" {
		t.Fatalf("provenance = %#v, want valid graph reasoning provenance", response.Provenance)
	}
	if len(response.Provenance.SourceURNs) != 1 || response.Provenance.SourceURNs[0] != "urn:cerebro:writer:asset:alpha" {
		t.Fatalf("source urns = %#v", response.Provenance.SourceURNs)
	}
}

func TestServiceReasonPreservesUnsupportedQuery(t *testing.T) {
	service := NewService(&askStore{}, &StubLLMClient{DraftResponse: &DraftResponse{
		Rationale: "Planning filtered high-risk findings.",
		Plan:      &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"owner": "security"}},
	}}, ValidatorOptions{})

	response, err := service.Reason(context.Background(), AskRequest{
		TenantID: "writer",
		Question: "show security-owned risk findings",
	})
	if err != nil {
		t.Fatalf("Reason() error = %v", err)
	}
	if response.UnsupportedQuery == nil || response.UnsupportedQuery.Code != "query_plan_conversion_failed" {
		t.Fatalf("unsupported query = %#v", response.UnsupportedQuery)
	}
	if response.Provenance.FallbackReason != "query_plan_conversion_failed" {
		t.Fatalf("fallback reason = %q", response.Provenance.FallbackReason)
	}
}
