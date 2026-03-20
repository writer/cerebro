package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/warehouse"
)

func TestEnsureSecurityGraph_ConcurrentInitSingleInstance(t *testing.T) {
	a := &App{}

	const workers = 32
	graphs := make(chan *graph.Graph, workers)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			graphs <- a.ensureSecurityGraph()
		}()
	}

	wg.Wait()
	close(graphs)

	var first *graph.Graph
	for g := range graphs {
		if g == nil {
			t.Fatal("expected initialized graph, got nil")
		}
		if first == nil {
			first = g
			continue
		}
		if g != first {
			t.Fatalf("expected a single graph instance, got %p and %p", first, g)
		}
	}
}

func TestHandleTapCloudEventWaitsForGraphReady(t *testing.T) {
	a := &App{graphReady: make(chan struct{})}
	evt := events.CloudEvent{
		Type: "ensemble.tap.salesforce.opportunity.updated",
		Time: time.Now().UTC(),
		Data: map[string]any{
			"id": "opp-blocked",
			"snapshot": map[string]any{
				"name": "Blocked Opportunity",
			},
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- a.handleTapCloudEvent(context.Background(), evt)
	}()

	select {
	case err := <-done:
		t.Fatalf("expected tap event to wait for graph readiness, got early result: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(a.graphReady)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleTapCloudEvent returned error after graph became ready: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleTapCloudEvent did not resume after graph became ready")
	}

	if a.SecurityGraph == nil {
		t.Fatal("expected security graph to be created after readiness gate opened")
	}
	if _, ok := a.SecurityGraph.GetNode("salesforce:opportunity:opp-blocked"); !ok {
		t.Fatal("expected tap event node to be applied after graph readiness")
	}
}

func TestHandleGraphCloudEvent_AuditMutationPersistsCDCEvents(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	a := &App{Warehouse: store}
	evt := events.CloudEvent{
		ID:     "evt-audit-1",
		Source: "urn:aws:cloudtrail",
		Type:   "aws.cloudtrail.asset.changed",
		Time:   time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"table_name":  "aws_ec2_security_groups",
			"resource_id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
			"change_type": "modified",
			"account_id":  "123456789012",
			"region":      "us-east-1",
			"payload": map[string]any{
				"arn":            "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
				"group_id":       "sg-123",
				"group_name":     "web",
				"account_id":     "123456789012",
				"region":         "us-east-1",
				"ip_permissions": []map[string]any{{"IpRanges": []map[string]any{{"CidrIp": "0.0.0.0/0"}}}},
			},
		},
	}

	if err := a.handleGraphCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleGraphCloudEvent failed: %v", err)
	}
	if len(store.CDCBatches) != 1 || len(store.CDCBatches[0]) != 1 {
		t.Fatalf("expected one persisted audit CDC event, got %#v", store.CDCBatches)
	}
	got := store.CDCBatches[0][0]
	if got.TableName != "aws_ec2_security_groups" {
		t.Fatalf("expected table aws_ec2_security_groups, got %q", got.TableName)
	}
	if got.Provider != "aws" {
		t.Fatalf("expected provider aws, got %q", got.Provider)
	}
	if got.ResourceID != "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123" {
		t.Fatalf("unexpected resource id %q", got.ResourceID)
	}
}

func TestHandleGraphCloudEvent_AuditMutationSkipsInvalidBatchRecords(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	a := &App{Warehouse: store}
	evt := events.CloudEvent{
		ID:     "evt-audit-batch-invalid-1",
		Source: "urn:aws:cloudtrail",
		Type:   "aws.cloudtrail.asset.changed",
		Time:   time.Date(2026, 3, 14, 12, 30, 0, 0, time.UTC),
		Data: map[string]any{
			"mutations": []any{
				map[string]any{
					"payload": map[string]any{"id": "missing-table"},
				},
				map[string]any{
					"table_name":  "aws_ec2_security_groups",
					"change_type": "modified",
					"resource_id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-456",
					"payload": map[string]any{
						"arn":        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-456",
						"group_id":   "sg-456",
						"group_name": "api",
					},
				},
				map[string]any{
					"table_name":  "aws_ec2_security_groups",
					"change_type": "modified",
					"payload":     map[string]any{},
				},
			},
		},
	}

	if err := a.handleGraphCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleGraphCloudEvent failed: %v", err)
	}
	if len(store.CDCBatches) != 1 || len(store.CDCBatches[0]) != 1 {
		t.Fatalf("expected one persisted audit CDC event from valid subset, got %#v", store.CDCBatches)
	}
	if got := store.CDCBatches[0][0].ResourceID; got != "arn:aws:ec2:us-east-1:123456789012:security-group/sg-456" {
		t.Fatalf("unexpected persisted resource id %q", got)
	}
}

func TestParseTapType(t *testing.T) {
	system, entity, action := parseTapType("ensemble.tap.stripe.customer.created")
	if system != "stripe" || entity != "customer" || action != "created" {
		t.Fatalf("unexpected parse result: system=%q entity=%q action=%q", system, entity, action)
	}

	system, entity, action = parseTapType("ensemble.tap.activity.gong.call_completed")
	if system != "gong" || entity != "call_completed" || action != "call_completed" {
		t.Fatalf("unexpected activity parse result: system=%q entity=%q action=%q", system, entity, action)
	}

	channel, interactionType := parseTapInteractionType("ensemble.tap.interaction.gong.call_completed")
	if channel != "gong" || interactionType != "call_completed" {
		t.Fatalf("unexpected interaction parse result: channel=%q type=%q", channel, interactionType)
	}
}

func TestBuildTapBusinessEventPlan_ParsesWithoutGraph(t *testing.T) {
	evt := events.CloudEvent{
		Type: "ensemble.tap.salesforce.opportunity.updated",
		Time: time.Date(2026, 3, 11, 18, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"entity_id": "opp-1",
			"snapshot": map[string]any{
				"name":             "Renewal Opp",
				"LastModifiedDate": "2026-03-11T18:00:00Z",
				"account_id":       "acct-1",
			},
			"changes": map[string]any{
				"CloseDate": map[string]any{
					"old": "2026-04-01",
					"new": "2026-04-15",
				},
			},
		},
	}

	plan, ok := buildTapBusinessEventPlan("salesforce", "opportunity", "updated", evt.Type, evt, map[string]any{
		"close_date_push_count": 1,
	})
	if !ok {
		t.Fatal("expected business plan to be created")
	}
	if plan.Node == nil || plan.Node.ID != "salesforce:opportunity:opp-1" {
		t.Fatalf("plan.Node.ID = %v, want salesforce:opportunity:opp-1", plan.Node)
	}
	if got := toInt(plan.Node.Properties["close_date_push_count"]); got != 2 {
		t.Fatalf("close_date_push_count = %d, want 2", got)
	}
	if len(plan.TargetStubs) != 1 || plan.TargetStubs[0].ID != "salesforce:account:acct-1" {
		t.Fatalf("TargetStubs = %#v, want account stub", plan.TargetStubs)
	}
	if len(plan.Edges) != 1 || plan.Edges[0].Kind != graph.EdgeKindOwns {
		t.Fatalf("Edges = %#v, want one owns edge", plan.Edges)
	}
}

func TestBuildTapInteractionEventPlan_ParsesWithoutGraph(t *testing.T) {
	evt := events.CloudEvent{
		Type: "ensemble.tap.interaction.slack.message",
		Time: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"participants": []any{
				map[string]any{"email": "alice@example.com", "name": "Alice"},
				map[string]any{"email": "bob@example.com", "name": "Bob"},
			},
			"duration_minutes": 10,
		},
	}

	plan, ok := buildTapInteractionEventPlan(evt.Type, evt)
	if !ok {
		t.Fatal("expected interaction plan to be created")
	}
	if plan.Channel != "slack" || plan.InteractionType != "message" {
		t.Fatalf("channel/type = %q/%q, want slack/message", plan.Channel, plan.InteractionType)
	}
	if plan.Duration != 10*time.Minute {
		t.Fatalf("Duration = %s, want 10m", plan.Duration)
	}
	if len(plan.Participants) != 2 || plan.Participants[0].ID != "person:alice@example.com" || plan.Participants[1].ID != "person:bob@example.com" {
		t.Fatalf("Participants = %#v, want normalized person IDs", plan.Participants)
	}
}

func TestBuildTapActivityEventPlan_ParsesWithoutGraph(t *testing.T) {
	evt := events.CloudEvent{
		ID:   "evt-activity-1",
		Type: "ensemble.tap.activity.gong.call_completed",
		Time: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"actor": map[string]any{
				"email": "alice@example.com",
				"name":  "Alice",
			},
			"target": map[string]any{
				"id":   "deal-123",
				"type": "deal",
				"name": "Enterprise Renewal",
			},
			"action": "call_completed",
			"metadata": map[string]any{
				"duration_seconds": 1800,
			},
		},
	}

	plan, ok := buildTapActivityEventPlan("gong", "call_completed", evt)
	if !ok {
		t.Fatal("expected activity plan to be created")
	}
	if plan.Actor == nil || plan.Actor.ID != "person:alice@example.com" {
		t.Fatalf("Actor = %#v, want person:alice@example.com", plan.Actor)
	}
	if plan.Target == nil || plan.Target.ID != "gong:deal:deal-123" {
		t.Fatalf("Target = %#v, want gong:deal:deal-123", plan.Target)
	}
	if plan.Activity == nil || plan.Activity.ID != "action:gong:call_completed:evt-activity-1" {
		t.Fatalf("Activity = %#v, want action:gong:call_completed:evt-activity-1", plan.Activity)
	}
	if plan.ActivityTarget == nil || plan.ActivityTarget.Kind != graph.EdgeKindTargets {
		t.Fatalf("ActivityTarget = %#v, want targets edge", plan.ActivityTarget)
	}
}

func TestDeriveComputedFields(t *testing.T) {
	now := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)

	hubspot := deriveComputedFields("hubspot", "deal", map[string]any{
		"properties": map[string]any{
			"last_activity_date": "2026-03-01T00:00:00Z",
		},
	}, nil, nil, now)
	if _, ok := hubspot["days_since_last_activity"]; !ok {
		t.Fatal("expected days_since_last_activity for hubspot deal")
	}

	salesforce := deriveComputedFields("salesforce", "opportunity", map[string]any{
		"LastModifiedDate": "2026-02-20T00:00:00Z",
	}, map[string]any{"CloseDate": "2026-04-01"}, nil, now)
	if _, ok := salesforce["days_since_last_modified"]; !ok {
		t.Fatal("expected days_since_last_modified for salesforce opportunity")
	}
	if got := toInt(salesforce["close_date_push_count"]); got < 1 {
		t.Fatalf("expected inferred close_date_push_count >= 1, got %d", got)
	}

	stripe := deriveComputedFields("stripe", "subscription", map[string]any{
		"trial_end": "2026-03-10T00:00:00Z",
	}, nil, nil, now)
	if got := toInt(stripe["days_until_trial_end"]); got <= 0 {
		t.Fatalf("expected positive days_until_trial_end, got %d", got)
	}
}

func TestHandleTapCloudEvent_BuildsBusinessNodeAndEdge(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		Type: "ensemble.tap.hubspot.contact.updated",
		Time: time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"entity_id": "contact-1",
			"snapshot": map[string]interface{}{
				"name":       "Alice",
				"company_id": "company-1",
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	node, ok := a.SecurityGraph.GetNode("hubspot:contact:contact-1")
	if !ok {
		t.Fatal("expected contact node to be created")
	}
	if node.Kind != graph.NodeKindContact {
		t.Fatalf("expected contact node kind, got %q", node.Kind)
	}

	edges := a.SecurityGraph.GetOutEdges("hubspot:contact:contact-1")
	if len(edges) == 0 {
		t.Fatal("expected at least one relationship edge")
	}
	if edges[0].Kind != graph.EdgeKindWorksAt {
		t.Fatalf("expected edge kind %q, got %q", graph.EdgeKindWorksAt, edges[0].Kind)
	}
}

func TestHandleTapCloudEvent_SwapsGraphForLegacyFallbackMutation(t *testing.T) {
	original := graph.New()
	a := &App{SecurityGraph: original}
	evt := events.CloudEvent{
		Type: "ensemble.tap.hubspot.contact.updated",
		Time: time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"entity_id": "contact-1",
			"snapshot": map[string]any{
				"name":       "Alice",
				"company_id": "company-1",
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	current := a.CurrentSecurityGraph()
	if current == original {
		t.Fatal("expected TAP fallback mutation to swap the live graph pointer")
	}
	if _, ok := original.GetNode("hubspot:contact:contact-1"); ok {
		t.Fatal("expected original graph to remain unchanged after swap")
	}
	if _, ok := current.GetNode("hubspot:contact:contact-1"); !ok {
		t.Fatal("expected swapped graph to contain TAP fallback node")
	}
}

func TestHandleTapCloudEvent_IsIdempotentForDuplicateBusinessEvent(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		ID:   "evt-idempotent-1",
		Type: "ensemble.tap.hubspot.contact.updated",
		Time: time.Date(2026, 3, 11, 18, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"entity_id": "contact-1",
			"snapshot": map[string]interface{}{
				"name":       "Alice",
				"company_id": "company-1",
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("first handleTapCloudEvent failed: %v", err)
	}
	nodesAfterFirst := a.SecurityGraph.NodeCount()
	edgesAfterFirst := a.SecurityGraph.EdgeCount()

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("second handleTapCloudEvent failed: %v", err)
	}

	if got := a.SecurityGraph.NodeCount(); got != nodesAfterFirst {
		t.Fatalf("expected duplicate event to keep node count %d, got %d", nodesAfterFirst, got)
	}
	if got := a.SecurityGraph.EdgeCount(); got != edgesAfterFirst {
		t.Fatalf("expected duplicate event to keep edge count %d, got %d", edgesAfterFirst, got)
	}
}

func TestHandleTapCloudEvent_MaterializesEventCorrelations(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)

	prEvent := events.CloudEvent{
		ID:     "evt-pr-1",
		Source: "ensemble.tap.github",
		Type:   "ensemble.tap.github.pull_request.merged",
		Time:   base,
		Data: map[string]any{
			"repository":      "payments",
			"number":          42,
			"title":           "Fix checkout race",
			"merged_by":       "alice",
			"merged_by_email": "alice@example.com",
		},
	}
	deployEvent := events.CloudEvent{
		ID:     "evt-deploy-1",
		Source: "ensemble.tap.ci",
		Type:   "ensemble.tap.ci.deploy.completed",
		Time:   base.Add(5 * time.Minute),
		Data: map[string]any{
			"service":         "payments",
			"deploy_id":       "deploy-1",
			"environment":     "prod",
			"status":          "succeeded",
			"release_version": "2026.03.12.1",
			"actor_email":     "alice@example.com",
		},
	}
	incidentEvent := events.CloudEvent{
		ID:     "evt-incident-1",
		Source: "ensemble.tap.incident",
		Type:   "ensemble.tap.incident.timeline.created",
		Time:   base.Add(7 * time.Minute),
		Data: map[string]any{
			"incident_id":  "inc-1",
			"service":      "payments",
			"event_id":     "evt-1",
			"status":       "open",
			"severity":     "high",
			"event_type":   "created",
			"title":        "Payments incident",
			"summary":      "Checkout latency spiked",
			"performed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
			"actor_email":  "alice@example.com",
		},
	}
	for _, evt := range []events.CloudEvent{prEvent, deployEvent, incidentEvent} {
		if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
			t.Fatalf("handleTapCloudEvent failed for %s: %v", evt.Type, err)
		}
	}

	incidentEdges := a.SecurityGraph.GetOutEdges("incident:inc-1")
	if !graphEdgeExists(incidentEdges, graph.EdgeKindCausedBy, "deployment:payments:deploy-1") {
		t.Fatalf("expected incident caused_by deployment edge, got %#v", incidentEdges)
	}
	deployEdges := a.SecurityGraph.GetOutEdges("deployment:payments:deploy-1")
	if !graphEdgeExists(deployEdges, graph.EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatalf("expected deployment triggered_by PR edge, got %#v", deployEdges)
	}
}

func TestHandleTapCloudEvent_DeclarativeMappingsSwapGraphAndResolveIdentityOnCandidate(t *testing.T) {
	original := graph.New()
	a := &App{SecurityGraph: original}
	evt := events.CloudEvent{
		ID:     "evt-pr-identity-1",
		Source: "ensemble.tap.github",
		Type:   "ensemble.tap.github.pull_request.merged",
		Time:   time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"repository":      "payments",
			"number":          42,
			"title":           "Fix checkout race",
			"merged_by":       "alice",
			"merged_by_email": "alice@example.com",
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	current := a.CurrentSecurityGraph()
	if current == original {
		t.Fatal("expected declarative TAP mapping to swap the live graph pointer")
	}
	if _, ok := original.GetNode("person:alice@example.com"); ok {
		t.Fatal("expected original graph to remain unchanged after mapped identity resolution")
	}
	if _, ok := current.GetNode("person:alice@example.com"); !ok {
		t.Fatal("expected swapped graph to contain resolved person node")
	}
	if _, ok := current.GetNode("pull_request:payments:42"); !ok {
		t.Fatal("expected swapped graph to contain mapped pull request node")
	}
}

func TestQueueEventCorrelationRefresh_DebouncesHotPathRebuilds(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	a.SecurityGraph.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	a.SecurityGraph.AddNode(&graph.Node{
		ID:   "pull_request:payments:42",
		Kind: graph.NodeKindPullRequest,
		Name: "payments pr",
		Properties: map[string]any{
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	a.SecurityGraph.AddNode(&graph.Node{
		ID:   "deployment:payments:deploy-1",
		Kind: graph.NodeKindDeploymentRun,
		Name: "deploy-1",
		Properties: map[string]any{
			"service_id":  "payments",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	a.SecurityGraph.AddEdge(&graph.Edge{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})
	a.SecurityGraph.AddEdge(&graph.Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: graph.EdgeKindTargets, Effect: graph.EdgeEffectAllow})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.initEventCorrelationRefreshLoop(ctx)
	defer a.stopEventCorrelationRefreshLoop()

	a.queueEventCorrelationRefresh("tap_mapping")
	if current := a.CurrentSecurityGraph(); current != nil && graphEdgeExists(current.GetOutEdges("deployment:payments:deploy-1"), graph.EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatal("expected debounced refresh to avoid immediate rematerialization")
	}

	time.Sleep(2500 * time.Millisecond)
	current := a.CurrentSecurityGraph()
	if current == nil || !graphEdgeExists(current.GetOutEdges("deployment:payments:deploy-1"), graph.EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatal("expected debounced refresh to materialize correlation after debounce window")
	}
}

func TestHandleTapCloudEvent_InvalidCustomMapperPathDoesNotBlockPipeline(t *testing.T) {
	t.Setenv("GRAPH_EVENT_MAPPING_PATH", "/tmp/non-existent-mapper.yaml")

	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		Type: "ensemble.tap.hubspot.contact.updated",
		Time: time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"entity_id": "contact-1",
			"snapshot": map[string]interface{}{
				"name":       "Alice",
				"company_id": "company-1",
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent should fallback without error when mapper path is invalid: %v", err)
	}

	if _, ok := a.SecurityGraph.GetNode("hubspot:contact:contact-1"); !ok {
		t.Fatal("expected legacy fallback mapping to continue processing TAP event")
	}

	mapper, err := a.tapEventMapper()
	if err != nil {
		t.Fatalf("expected mapper fallback to default config, got error: %v", err)
	}
	if mapper == nil {
		t.Fatal("expected tap mapper to be initialized from default config fallback")
	}
}

func TestHandleTapCloudEvent_AccumulatesCloseDatePushCount(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	base := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)

	first := events.CloudEvent{
		Type: "ensemble.tap.salesforce.opportunity.updated",
		Time: base,
		Data: map[string]interface{}{
			"entity_id": "opp-1",
			"snapshot": map[string]interface{}{
				"name":             "Renewal Opp",
				"LastModifiedDate": "2026-03-06T12:00:00Z",
			},
			"changes": map[string]interface{}{
				"CloseDate": map[string]interface{}{
					"old": "2026-04-01",
					"new": "2026-04-15",
				},
			},
		},
	}
	if err := a.handleTapCloudEvent(context.Background(), first); err != nil {
		t.Fatalf("first event failed: %v", err)
	}

	second := events.CloudEvent{
		Type: "ensemble.tap.salesforce.opportunity.updated",
		Time: base.Add(5 * time.Minute),
		Data: map[string]interface{}{
			"entity_id": "opp-1",
			"snapshot": map[string]interface{}{
				"name":             "Renewal Opp",
				"LastModifiedDate": "2026-03-06T12:05:00Z",
			},
			"changes": map[string]interface{}{
				"CloseDate": map[string]interface{}{
					"old": "2026-04-15",
					"new": "2026-04-30",
				},
			},
		},
	}
	if err := a.handleTapCloudEvent(context.Background(), second); err != nil {
		t.Fatalf("second event failed: %v", err)
	}

	node, ok := a.SecurityGraph.GetNode("salesforce:opportunity:opp-1")
	if !ok {
		t.Fatal("expected opportunity node to exist")
	}
	if got := toInt(node.Properties["close_date_push_count"]); got != 2 {
		t.Fatalf("close_date_push_count = %d, want 2", got)
	}
}

func TestHandleTapCloudEvent_ActivitySubjectCreatesNodesAndEdges(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		ID:   "evt-activity-1",
		Type: "ensemble.tap.activity.gong.call_completed",
		Time: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"actor": map[string]interface{}{
				"email": "alice@example.com",
				"name":  "Alice",
			},
			"target": map[string]interface{}{
				"id":   "deal-123",
				"type": "deal",
				"name": "Enterprise Renewal",
			},
			"action": "call_completed",
			"metadata": map[string]interface{}{
				"duration_seconds": 1800,
			},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	actorNodeID := "person:alice@example.com"
	if node, ok := a.SecurityGraph.GetNode(actorNodeID); !ok || node.Kind != graph.NodeKindPerson {
		t.Fatalf("expected actor node %q with kind person", actorNodeID)
	}

	targetNodeID := "gong:deal:deal-123"
	if node, ok := a.SecurityGraph.GetNode(targetNodeID); !ok || node.Kind != graph.NodeKindDeal {
		t.Fatalf("expected target node %q with kind deal", targetNodeID)
	}

	activityNodeID := "action:gong:call_completed:evt-activity-1"
	activityNode, ok := a.SecurityGraph.GetNode(activityNodeID)
	if !ok {
		t.Fatalf("expected activity node %q to be created", activityNodeID)
	}
	if activityNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected activity node kind %q, got %q", graph.NodeKindAction, activityNode.Kind)
	}
	if got := activityNode.Properties["action_type"]; got != "call_completed" {
		t.Fatalf("expected activity action_type call_completed, got %v", got)
	}

	actorEdges := a.SecurityGraph.GetOutEdges(actorNodeID)
	if len(actorEdges) == 0 || actorEdges[0].Kind != graph.EdgeKindInteractedWith {
		t.Fatalf("expected actor interacted_with edge, got %#v", actorEdges)
	}
	activityEdges := a.SecurityGraph.GetOutEdges(activityNodeID)
	if len(activityEdges) == 0 || activityEdges[0].Kind != graph.EdgeKindTargets {
		t.Fatalf("expected action targets edge, got %#v", activityEdges)
	}
}

func TestHandleTapCloudEvent_UnknownActivitySourceFallsBackToGenericActivity(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		ID:   "evt-activity-unknown-1",
		Type: "ensemble.tap.activity.custom.audit_ping",
		Time: time.Date(2026, 3, 8, 12, 10, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"actor": map[string]interface{}{
				"email": "ops@example.com",
			},
			"target": map[string]interface{}{
				"id":   "entity-1",
				"type": "entity",
			},
			"action": "audit_ping",
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	activityNodeID := "activity:custom:audit_ping:evt-activity-unknown-1"
	node, ok := a.SecurityGraph.GetNode(activityNodeID)
	if !ok {
		t.Fatalf("expected fallback activity node %q", activityNodeID)
	}
	if node.Kind != graph.NodeKindActivity {
		t.Fatalf("expected fallback node kind %q, got %q", graph.NodeKindActivity, node.Kind)
	}
}

func TestHandleTapCloudEvent_InteractionSubjectCreatesPeopleAndEdge(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	now := time.Date(2026, 3, 8, 13, 0, 0, 0, time.UTC)
	evt := events.CloudEvent{
		Type: "ensemble.tap.interaction.gong.call",
		Time: now,
		Data: map[string]interface{}{
			"participants": []any{
				map[string]any{"email": "alice@example.com", "name": "Alice"},
				map[string]any{"email": "bob@example.com", "name": "Bob"},
			},
			"duration_seconds": 1800,
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleTapCloudEvent failed: %v", err)
	}

	aliceNode, ok := a.SecurityGraph.GetNode("person:alice@example.com")
	if !ok {
		t.Fatal("expected alice person node")
	}
	if aliceNode.Kind != graph.NodeKindPerson {
		t.Fatalf("expected alice node kind %q, got %q", graph.NodeKindPerson, aliceNode.Kind)
	}

	edge := findInteractionEdge(a.SecurityGraph, "person:alice@example.com", "person:bob@example.com")
	if edge == nil {
		t.Fatal("expected interaction edge between alice and bob")
	}
	if got := toInt(edge.Properties["frequency"]); got != 1 {
		t.Fatalf("expected frequency=1, got %d", got)
	}
	if got := int(toFloatForTest(edge.Properties["total_duration_seconds"])); got != 1800 {
		t.Fatalf("expected total_duration_seconds=1800, got %d", got)
	}
	if channels := stringSliceForTest(edge.Properties["interaction_channels"]); len(channels) == 0 || channels[0] != "gong" {
		t.Fatalf("expected interaction_channels to include gong, got %+v", channels)
	}
	if types := stringSliceForTest(edge.Properties["interaction_types"]); len(types) == 0 || types[0] != "call" {
		t.Fatalf("expected interaction_types to include call, got %+v", types)
	}
}

func TestHandleTapCloudEvent_InteractionSubjectAggregatesAcrossEvents(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	first := events.CloudEvent{
		Type: "ensemble.tap.interaction.slack.message",
		Time: time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"snapshot": map[string]any{
				"participants": []any{
					map[string]any{"id": "person:alice@example.com"},
					map[string]any{"id": "person:bob@example.com"},
				},
				"duration_seconds": 60,
			},
		},
	}
	second := events.CloudEvent{
		Type: "ensemble.tap.interaction.github.review",
		Time: time.Date(2026, 3, 8, 15, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"participants": []any{
				"person:bob@example.com",
				"person:alice@example.com",
			},
			"duration_minutes": 10,
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), first); err != nil {
		t.Fatalf("first interaction event failed: %v", err)
	}
	if err := a.handleTapCloudEvent(context.Background(), second); err != nil {
		t.Fatalf("second interaction event failed: %v", err)
	}

	edge := findInteractionEdge(a.SecurityGraph, "person:alice@example.com", "person:bob@example.com")
	if edge == nil {
		t.Fatal("expected interaction edge between alice and bob")
	}
	if got := toInt(edge.Properties["frequency"]); got != 2 {
		t.Fatalf("expected frequency=2, got %d", got)
	}
	if got := toInt(edge.Properties["previous_frequency"]); got != 1 {
		t.Fatalf("expected previous_frequency=1, got %d", got)
	}
	if got := int(toFloatForTest(edge.Properties["total_duration_seconds"])); got != 660 {
		t.Fatalf("expected total_duration_seconds=660, got %d", got)
	}
	if !containsStringForTest(stringSliceForTest(edge.Properties["interaction_channels"]), "slack") ||
		!containsStringForTest(stringSliceForTest(edge.Properties["interaction_channels"]), "github") {
		t.Fatalf("expected channels to include slack and github, got %+v", edge.Properties["interaction_channels"])
	}
	if !containsStringForTest(stringSliceForTest(edge.Properties["interaction_types"]), "message") ||
		!containsStringForTest(stringSliceForTest(edge.Properties["interaction_types"]), "review") {
		t.Fatalf("expected types to include message and review, got %+v", edge.Properties["interaction_types"])
	}
	lastSeen := timeFromProperty(edge.Properties["last_seen"])
	expected := time.Date(2026, 3, 8, 15, 0, 0, 0, time.UTC)
	if !lastSeen.Equal(expected) {
		t.Fatalf("expected last_seen=%s, got %s", expected.Format(time.RFC3339), lastSeen.Format(time.RFC3339))
	}
}

func TestHandleTapCloudEvent_SchemaEventRegistersRuntimeKinds(t *testing.T) {
	a := &App{SecurityGraph: graph.New()}
	evt := events.CloudEvent{
		Type: "ensemble.tap.schema.workday.updated",
		Time: time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"integration": "workday",
			"entity_types": []any{
				map[string]any{
					"kind":       "tap_test_employee_v1",
					"categories": []any{"identity", "business"},
					"properties": map[string]any{
						"title":      "string",
						"department": map[string]any{"type": "string"},
					},
					"relationships": []any{
						map[string]any{"kind": "reports_to"},
					},
				},
				map[string]any{
					"kind": "tap_test_service_v1",
				},
			},
			"edge_types": []any{"tap_test_reports_line_v1"},
		},
	}

	if err := a.handleTapCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("schema event failed: %v", err)
	}

	if !graph.IsNodeKindInCategory(graph.NodeKind("tap_test_employee_v1"), graph.NodeCategoryIdentity) {
		t.Fatal("expected dynamic employee kind to be identity")
	}
	if !graph.IsNodeKindInCategory(graph.NodeKind("tap_test_employee_v1"), graph.NodeCategoryBusiness) {
		t.Fatal("expected dynamic employee kind to be business")
	}
	if !graph.IsNodeKindInCategory(graph.NodeKind("tap_test_service_v1"), graph.NodeCategoryResource) {
		t.Fatal("expected inferred service kind to be resource")
	}
	if !graph.GlobalSchemaRegistry().IsEdgeKindRegistered(graph.EdgeKind("tap_test_reports_line_v1")) {
		t.Fatal("expected dynamic edge kind to be registered")
	}
}

func TestIsTapSchemaEventType(t *testing.T) {
	cases := []struct {
		eventType string
		want      bool
	}{
		{eventType: "ensemble.tap.schema.workday.updated", want: true},
		{eventType: "ensemble.tap.integration.schema.updated", want: true},
		{eventType: "ensemble.tap.salesforce.schema.updated", want: true},
		{eventType: "ensemble.tap.salesforce.contact.updated", want: false},
		{eventType: "ensemble.tap.interaction.slack.message", want: false},
	}

	for _, tc := range cases {
		if got := isTapSchemaEventType(tc.eventType); got != tc.want {
			t.Fatalf("isTapSchemaEventType(%q) = %v, want %v", tc.eventType, got, tc.want)
		}
	}
}

func TestParseTapSchemaEntities_ParsesWithoutGraph(t *testing.T) {
	definitions := parseTapSchemaEntities(map[string]any{
		"entities": []any{
			map[string]any{
				"kind":       "tap_test_user_v1",
				"categories": []any{"identity", "business", "identity", "ignored"},
				"schema": map[string]any{
					"email":        map[string]any{"type": "STRING", "required": true},
					"display_name": map[string]any{"data_type": "Text"},
					"score":        "number",
				},
				"required_properties": []any{"external_id", "display_name"},
				"relationships": []any{
					"member_of",
					map[string]any{"edge_kind": "reports_to"},
					"member_of",
				},
				"capabilities": []any{
					"internet_exposable",
					"privileged_identity",
					"ignored",
				},
				"description": "Test user definition",
			},
			map[string]any{
				"schema": map[string]any{"orphaned": map[string]any{"type": "string"}},
			},
		},
	})

	if len(definitions) != 1 {
		t.Fatalf("len(definitions) = %d, want 1", len(definitions))
	}

	got := definitions[0]
	if got.Kind != "tap_test_user_v1" {
		t.Fatalf("Kind = %q, want tap_test_user_v1", got.Kind)
	}
	if got.Description != "Test user definition" {
		t.Fatalf("Description = %q, want Test user definition", got.Description)
	}
	if want := []graph.NodeKindCategory{graph.NodeCategoryBusiness, graph.NodeCategoryIdentity}; len(got.Categories) != len(want) || got.Categories[0] != want[0] || got.Categories[1] != want[1] {
		t.Fatalf("Categories = %#v, want %#v", got.Categories, want)
	}
	if got.Properties["email"] != "string" || got.Properties["display_name"] != "text" || got.Properties["score"] != "number" {
		t.Fatalf("Properties = %#v, want parsed property types", got.Properties)
	}
	if want := []string{"display_name", "email", "external_id"}; len(got.Required) != len(want) || got.Required[0] != want[0] || got.Required[1] != want[1] || got.Required[2] != want[2] {
		t.Fatalf("Required = %#v, want %#v", got.Required, want)
	}
	if want := []graph.EdgeKind{"member_of", "reports_to"}; len(got.Relationships) != len(want) || got.Relationships[0] != want[0] || got.Relationships[1] != want[1] {
		t.Fatalf("Relationships = %#v, want %#v", got.Relationships, want)
	}
	if want := []graph.NodeKindCapability{graph.NodeCapabilityInternetExposable, graph.NodeCapabilityPrivilegedIdentity}; len(got.Capabilities) != len(want) || got.Capabilities[0] != want[0] || got.Capabilities[1] != want[1] {
		t.Fatalf("Capabilities = %#v, want %#v", got.Capabilities, want)
	}
}

func findInteractionEdge(g *graph.Graph, left, right string) *graph.Edge {
	for _, edge := range g.GetOutEdges(left) {
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == right {
			return edge
		}
	}
	for _, edge := range g.GetOutEdges(right) {
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == left {
			return edge
		}
	}
	return nil
}

func toFloatForTest(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	default:
		return 0
	}
}

func stringSliceForTest(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, anyToString(item))
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func containsStringForTest(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func graphEdgeExists(edges []*graph.Edge, kind graph.EdgeKind, target string) bool {
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		if edge.Kind == kind && edge.Target == target && edge.DeletedAt == nil {
			return true
		}
	}
	return false
}

func timeFromProperty(value any) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		parsed, err := time.Parse(time.RFC3339, typed)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
