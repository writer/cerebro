package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestPlatformEntitiesListAndDetail(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	baseProps := map[string]any{
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}

	g.AddNode(&graph.Node{
		ID:         "service:payments",
		Kind:       graph.NodeKindService,
		Name:       "Payments",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskHigh,
		Findings:   []string{"finding:public-endpoint"},
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneJSONMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:         "database:payments",
		Kind:       graph.NodeKindDatabase,
		Name:       "Payments DB",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskMedium,
		Tags:       map[string]string{"env": "prod"},
		Properties: cloneJSONMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:s3:::logs",
		Kind:     graph.NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     graph.RiskLow,
		Tags:     map[string]string{"env": "prod"},
		Properties: map[string]any{
			"observed_at":         baseAt.UTC().Format(time.RFC3339),
			"valid_from":          baseAt.UTC().Format(time.RFC3339),
			"recorded_at":         baseAt.UTC().Format(time.RFC3339),
			"transaction_from":    baseAt.UTC().Format(time.RFC3339),
			"block_public_acls":   true,
			"block_public_policy": true,
			"logging_enabled":     true,
			"versioning_status":   "Enabled",
			"encrypted":           true,
			"bucket_name":         "logs",
		},
	})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "person:bob@example.com", Kind: graph.NodeKindPerson, Name: "Bob", Properties: cloneJSONMap(baseProps)})
	g.AddNode(&graph.Node{ID: "identity_alias:slack:payments-owner", Kind: graph.NodeKindIdentityAlias, Name: "payments-owner", Properties: map[string]any{
		"alias_type":       "slack",
		"source_system":    "slack",
		"observed_at":      baseAt.UTC().Format(time.RFC3339),
		"valid_from":       baseAt.UTC().Format(time.RFC3339),
		"recorded_at":      baseAt.UTC().Format(time.RFC3339),
		"transaction_from": baseAt.UTC().Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{
		ID:         "service:payments->database:payments:depends_on",
		Source:     "service:payments",
		Target:     "database:payments",
		Kind:       graph.EdgeKindDependsOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneJSONMap(baseProps),
	})
	g.AddEdge(&graph.Edge{
		ID:         "identity_alias:slack:payments-owner->person:alice@example.com:alias_of",
		Source:     "identity_alias:slack:payments-owner",
		Target:     "person:alice@example.com",
		Kind:       graph.EdgeKindAliasOf,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneJSONMap(baseProps),
	})
	g.AddNode(&graph.Node{
		ID:         "evidence:runbook",
		Kind:       graph.NodeKindEvidence,
		Name:       "Runbook",
		Provider:   "cmdb",
		Properties: map[string]any{"evidence_type": "document", "observed_at": baseAt.UTC().Format(time.RFC3339), "valid_from": baseAt.UTC().Format(time.RFC3339), "recorded_at": baseAt.UTC().Format(time.RFC3339), "transaction_from": baseAt.UTC().Format(time.RFC3339)},
	})
	if _, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
		ID:              "observation:payments:manual-review",
		SubjectID:       "service:payments",
		ObservationType: "manual_review_signal",
		Summary:         "Analyst confirmed service ownership context",
		SourceSystem:    "analyst",
		ObservedAt:      baseAt.Add(30 * time.Minute),
		ValidFrom:       baseAt.Add(30 * time.Minute),
		RecordedAt:      baseAt.Add(30 * time.Minute),
		TransactionFrom: baseAt.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("write observation: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:alice",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:alice@example.com",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceName:      "CMDB",
		SourceType:      "system",
		SourceSystem:    "cmdb",
		ObservedAt:      baseAt.Add(45 * time.Minute),
		ValidFrom:       baseAt.Add(45 * time.Minute),
		RecordedAt:      baseAt.Add(45 * time.Minute),
		TransactionFrom: baseAt.Add(45 * time.Minute),
	}); err != nil {
		t.Fatalf("write alice claim: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:payments:owner:bob",
		SubjectID:       "service:payments",
		Predicate:       "owner",
		ObjectID:        "person:bob@example.com",
		SourceSystem:    "slack",
		ObservedAt:      baseAt.Add(90 * time.Minute),
		ValidFrom:       baseAt.Add(90 * time.Minute),
		RecordedAt:      baseAt.Add(90 * time.Minute),
		TransactionFrom: baseAt.Add(90 * time.Minute),
	}); err != nil {
		t.Fatalf("write bob claim: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:logs:encrypted:true",
		SubjectID:       "arn:aws:s3:::logs",
		Predicate:       "encrypted",
		ObjectValue:     "true",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceSystem:    "aws",
		ObservedAt:      baseAt.Add(50 * time.Minute),
		ValidFrom:       baseAt.Add(50 * time.Minute),
		RecordedAt:      baseAt.Add(50 * time.Minute),
		TransactionFrom: baseAt.Add(50 * time.Minute),
	}); err != nil {
		t.Fatalf("write encrypted claim: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:logs:public_access:false",
		SubjectID:       "arn:aws:s3:::logs",
		Predicate:       "public_access",
		ObjectValue:     "false",
		EvidenceIDs:     []string{"evidence:runbook"},
		SourceSystem:    "aws",
		ObservedAt:      baseAt.Add(55 * time.Minute),
		ValidFrom:       baseAt.Add(55 * time.Minute),
		RecordedAt:      baseAt.Add(55 * time.Minute),
		TransactionFrom: baseAt.Add(55 * time.Minute),
	}); err != nil {
		t.Fatalf("write public access claim: %v", err)
	}
	graph.NormalizeEntityAssetSupport(g, baseAt.Add(95*time.Minute))

	list := do(t, s, http.MethodGet, "/api/v1/platform/entities?category=resource&provider=aws&tag_key=env&tag_value=prod&limit=2", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if listBody["count"].(float64) != 2 {
		t.Fatalf("expected page size 2, got %#v", listBody["count"])
	}
	pagination := listBody["pagination"].(map[string]any)
	if pagination["total"].(float64) != 3 || pagination["has_more"] != true {
		t.Fatalf("unexpected pagination: %#v", pagination)
	}
	summary := listBody["summary"].(map[string]any)
	if summary["knowledge_backed_entities"].(float64) != 2 || summary["resource_entities"].(float64) != 3 {
		t.Fatalf("unexpected entity summary: %#v", summary)
	}
	entities := listBody["entities"].([]any)
	first := entities[0].(map[string]any)
	if first["id"] != "service:payments" {
		t.Fatalf("expected high-risk service first, got %#v", first["id"])
	}
	if _, ok := first["canonical_ref"]; ok {
		t.Fatalf("expected list response to omit detail-only canonical_ref, got %#v", first["canonical_ref"])
	}
	if _, ok := first["external_refs"]; ok {
		t.Fatalf("expected list response to omit detail-only external_refs, got %#v", first["external_refs"])
	}
	if _, ok := first["aliases"]; ok {
		t.Fatalf("expected list response to omit detail-only aliases, got %#v", first["aliases"])
	}

	detail := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments", nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity detail, got %d: %s", detail.Code, detail.Body.String())
	}
	detailBody := decodeJSON(t, detail)
	knowledge := detailBody["knowledge"].(map[string]any)
	if knowledge["claim_count"].(float64) != 2 || knowledge["evidence_count"].(float64) != 1 || knowledge["observation_count"].(float64) != 1 {
		t.Fatalf("unexpected knowledge block: %#v", knowledge)
	}
	relationships := detailBody["relationships"].([]any)
	if len(relationships) == 0 {
		t.Fatalf("expected relationship summaries, got %#v", detailBody["relationships"])
	}
	relationship := relationships[0].(map[string]any)
	if relationship["edge_kind"] != string(graph.EdgeKindDependsOn) {
		t.Fatalf("expected depends_on relationship, got %#v", relationship)
	}
	if _, ok := detailBody["canonical_ref"].(map[string]any); !ok {
		t.Fatalf("expected canonical_ref on detail, got %#v", detailBody["canonical_ref"])
	}
	if refs, ok := detailBody["external_refs"].([]any); !ok || len(refs) == 0 {
		t.Fatalf("expected external_refs on detail, got %#v", detailBody["external_refs"])
	}
	bucket := do(t, s, http.MethodGet, "/api/v1/platform/entities/arn:aws:s3:::logs", nil)
	if bucket.Code != http.StatusOK {
		t.Fatalf("expected 200 for bucket detail, got %d: %s", bucket.Code, bucket.Body.String())
	}
	bucketBody := decodeJSON(t, bucket)
	if facets, ok := bucketBody["facets"].([]any); !ok || len(facets) < 4 {
		t.Fatalf("expected bucket facets, got %#v", bucketBody["facets"])
	}
	if posture, ok := bucketBody["posture"].(map[string]any); !ok || posture["active_claim_count"].(float64) < 2 {
		t.Fatalf("expected posture summary, got %#v", bucketBody["posture"])
	}
	if subresources, ok := bucketBody["subresources"].([]any); !ok || len(subresources) < 3 {
		t.Fatalf("expected bucket subresources, got %#v", bucketBody["subresources"])
	}
	person := do(t, s, http.MethodGet, "/api/v1/platform/entities/person:alice@example.com", nil)
	if person.Code != http.StatusOK {
		t.Fatalf("expected 200 for person detail, got %d: %s", person.Code, person.Body.String())
	}
	personBody := decodeJSON(t, person)
	if aliases, ok := personBody["aliases"].([]any); !ok || len(aliases) != 1 {
		t.Fatalf("expected person aliases, got %#v", personBody["aliases"])
	}
	facets := do(t, s, http.MethodGet, "/api/v1/platform/entities/facets", nil)
	if facets.Code != http.StatusOK {
		t.Fatalf("expected 200 for facet catalog, got %d: %s", facets.Code, facets.Body.String())
	}
	facetBody := decodeJSON(t, facets)
	if facetBody["kind"] != "EntityFacetContractCatalog" {
		t.Fatalf("unexpected facet catalog: %#v", facetBody)
	}
}

func TestPlatformEntitySearchAndSuggest(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{
		ID:       "arn:aws:s3:::audit-logs",
		Kind:     graph.NodeKindBucket,
		Name:     "Audit Logs",
		Provider: "aws",
		Region:   "us-east-1",
	})
	g.AddNode(&graph.Node{
		ID:       "person:alice@example.com",
		Kind:     graph.NodeKindPerson,
		Name:     "Alice Example",
		Provider: "workspace",
	})
	g.BuildIndex()

	search := do(t, s, http.MethodGet, "/api/v1/platform/entities/search?q=s3+bucket&limit=5", nil)
	if search.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity search, got %d: %s", search.Code, search.Body.String())
	}
	searchBody := decodeJSON(t, search)
	if searchBody["count"].(float64) < 1 {
		t.Fatalf("expected at least one search result, got %#v", searchBody)
	}
	first := searchBody["results"].([]any)[0].(map[string]any)
	entity := first["entity"].(map[string]any)
	if entity["id"] != "arn:aws:s3:::audit-logs" {
		t.Fatalf("expected bucket search hit, got %#v", entity["id"])
	}

	suggest := do(t, s, http.MethodGet, "/api/v1/platform/entities/suggest?prefix=ali&limit=5", nil)
	if suggest.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity suggest, got %d: %s", suggest.Code, suggest.Body.String())
	}
	suggestBody := decodeJSON(t, suggest)
	if suggestBody["count"].(float64) < 1 {
		t.Fatalf("expected at least one suggestion, got %#v", suggestBody)
	}
	suggestion := suggestBody["suggestions"].([]any)[0].(map[string]any)
	if suggestion["entity_id"] != "person:alice@example.com" {
		t.Fatalf("expected alice suggestion, got %#v", suggestion)
	}
}

func TestPlatformEntitySummaryReport(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	baseAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	props := map[string]any{
		"observed_at":         baseAt.UTC().Format(time.RFC3339),
		"valid_from":          baseAt.UTC().Format(time.RFC3339),
		"recorded_at":         baseAt.UTC().Format(time.RFC3339),
		"transaction_from":    baseAt.UTC().Format(time.RFC3339),
		"block_public_acls":   true,
		"block_public_policy": true,
		"logging_enabled":     true,
		"encrypted":           true,
		"versioning_status":   "Enabled",
	}
	g.AddNode(&graph.Node{
		ID:         "arn:aws:s3:::logs",
		Kind:       graph.NodeKindBucket,
		Name:       "Audit Logs",
		Provider:   "aws",
		Account:    "123456789012",
		Region:     "us-east-1",
		Risk:       graph.RiskLow,
		Properties: props,
	})
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:              "claim:logs:encrypted:true",
		SubjectID:       "arn:aws:s3:::logs",
		Predicate:       "encrypted",
		ObjectValue:     "true",
		SourceSystem:    "aws",
		ObservedAt:      baseAt.Add(time.Hour),
		ValidFrom:       baseAt.Add(time.Hour),
		RecordedAt:      baseAt.Add(time.Hour),
		TransactionFrom: baseAt.Add(time.Hour),
	}); err != nil {
		t.Fatalf("write claim: %v", err)
	}
	graph.NormalizeEntityAssetSupport(g, baseAt.Add(90*time.Minute))

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/entity-summary?entity_id=arn:aws:s3:::logs&max_posture_claims=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity summary report, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if _, ok := body["entity"].(map[string]any); !ok {
		t.Fatalf("expected entity block, got %#v", body["entity"])
	}
	if overview, ok := body["overview"].(map[string]any); !ok || overview["headline"] != "Audit Logs" {
		t.Fatalf("unexpected overview: %#v", body["overview"])
	}
	if posture, ok := body["posture"].(map[string]any); !ok || len(posture["claims"].([]any)) != 1 {
		t.Fatalf("unexpected posture section: %#v", body["posture"])
	}
	if subresources, ok := body["subresources"].(map[string]any); !ok || len(subresources["items"].([]any)) == 0 {
		t.Fatalf("unexpected subresources section: %#v", body["subresources"])
	}
}

func TestPlatformEntityPointInTimeAndDiff(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "degraded",
			"owner":            "team-payments",
			"observed_at":      base.Add(2 * time.Hour).UTC().Format(time.RFC3339),
			"valid_from":       base.UTC().Format(time.RFC3339),
			"recorded_at":      base.UTC().Format(time.RFC3339),
			"transaction_from": base.UTC().Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatal("expected seeded service node")
	}
	node.PropertyHistory = map[string][]graph.PropertySnapshot{
		"status": []graph.PropertySnapshot{
			{Timestamp: base, Value: "healthy"},
			{Timestamp: base.Add(2 * time.Hour), Value: "degraded"},
		},
		"owner": []graph.PropertySnapshot{
			{Timestamp: base.Add(2 * time.Hour), Value: "team-payments"},
		},
	}

	at := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments/at?timestamp=2026-03-10T09:30:00Z", nil)
	if at.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity at-time, got %d: %s", at.Code, at.Body.String())
	}
	atBody := decodeJSON(t, at)
	entity := atBody["entity"].(map[string]any)
	properties := entity["properties"].(map[string]any)
	if got := properties["status"]; got != "healthy" {
		t.Fatalf("expected historical status healthy, got %#v", got)
	}
	if _, ok := properties["owner"]; ok {
		t.Fatalf("did not expect owner at 09:30, got %#v", properties["owner"])
	}
	reconstruction := atBody["reconstruction"].(map[string]any)
	if reconstruction["property_history_applied"] != true || reconstruction["historical_core_fields"] != false {
		t.Fatalf("unexpected reconstruction metadata: %#v", reconstruction)
	}

	diff := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments/diff?from=2026-03-10T09:00:00Z&to=2026-03-10T12:00:00Z", nil)
	if diff.Code != http.StatusOK {
		t.Fatalf("expected 200 for entity diff, got %d: %s", diff.Code, diff.Body.String())
	}
	diffBody := decodeJSON(t, diff)
	if diffBody["entity_id"] != "service:payments" {
		t.Fatalf("expected entity_id service:payments, got %#v", diffBody["entity_id"])
	}
	changedKeys, ok := diffBody["changed_keys"].([]any)
	if !ok || len(changedKeys) < 2 {
		t.Fatalf("expected changed_keys, got %#v", diffBody["changed_keys"])
	}

	missingTimestamp := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments/at", nil)
	if missingTimestamp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing timestamp, got %d: %s", missingTimestamp.Code, missingTimestamp.Body.String())
	}
	if body := decodeJSON(t, missingTimestamp); body["error"] != "timestamp is required" {
		t.Fatalf("expected missing timestamp error, got %#v", body)
	}
}

func TestPlatformEntityTimeDiffAcrossDeletion(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	deletedAt := base.Add(2 * time.Hour)
	g.AddNode(&graph.Node{
		ID:       "service:legacy",
		Kind:     graph.NodeKindService,
		Name:     "Legacy",
		Provider: "aws",
		Properties: map[string]any{
			"status":           "retiring",
			"observed_at":      base.UTC().Format(time.RFC3339),
			"valid_from":       base.UTC().Format(time.RFC3339),
			"valid_to":         deletedAt.UTC().Format(time.RFC3339),
			"recorded_at":      base.UTC().Format(time.RFC3339),
			"transaction_from": base.UTC().Format(time.RFC3339),
			"transaction_to":   deletedAt.UTC().Format(time.RFC3339),
		},
	})
	node, ok := g.GetNode("service:legacy")
	if !ok || node == nil {
		t.Fatal("expected seeded deleted node")
	}
	node.CreatedAt = base
	node.UpdatedAt = base
	node.DeletedAt = &deletedAt
	node.PropertyHistory = nil

	diff := do(t, s, http.MethodGet, "/api/v1/platform/entities/service:legacy/diff?from=2026-03-10T10:00:00Z&to=2026-03-10T12:00:00Z&recorded_at=2026-03-10T12:00:00Z", nil)
	if diff.Code != http.StatusOK {
		t.Fatalf("expected 200 for deleted-entity diff, got %d: %s", diff.Code, diff.Body.String())
	}
	body := decodeJSON(t, diff)
	if body["entity_id"] != "service:legacy" {
		t.Fatalf("expected deleted entity id, got %#v", body["entity_id"])
	}
	after := body["after"].(map[string]any)["entity"].(map[string]any)
	if after["id"] != "service:legacy" {
		t.Fatalf("expected tombstone after entity id, got %#v", after)
	}
	changes, ok := body["property_changes"].([]any)
	if !ok || len(changes) == 0 {
		t.Fatalf("expected deletion diff property changes, got %#v", body)
	}
	foundStatus := false
	for _, raw := range changes {
		change := raw.(map[string]any)
		if change["key"] != "status" {
			continue
		}
		foundStatus = true
		if change["before"] != "retiring" {
			t.Fatalf("expected status removal before=retiring, got %#v", change)
		}
		if _, ok := change["after"]; ok {
			t.Fatalf("expected removed property to omit after value, got %#v", change)
		}
	}
	if !foundStatus {
		t.Fatalf("expected deletion diff to include status removal, got %#v", body["property_changes"])
	}
}

func TestPlatformEntitiesRejectInvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/entities?risk=unknown", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid risk, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities?has_findings=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid has_findings, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/service:payments?valid_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid valid_at, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/search", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing search query, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/suggest", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing suggest prefix, got %d: %s", w.Code, w.Body.String())
	}

	longValue := strings.Repeat("a", maxPlatformEntityQueryLength+1)

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities?q="+longValue, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized entity list q, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/search?q="+longValue, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized entity search q, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/suggest?prefix="+longValue, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized suggest prefix, got %d: %s", w.Code, w.Body.String())
	}

	runeValue := strings.Repeat("世", 300)

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities?q="+runeValue, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for rune-bounded entity list q, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/search?q="+runeValue, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for rune-bounded entity search q, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/entities/suggest?prefix="+runeValue, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for rune-bounded suggest prefix, got %d: %s", w.Code, w.Body.String())
	}
}
