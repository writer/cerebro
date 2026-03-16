package graphingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func TestLoadDefaultConfig(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	if len(config.Mappings) == 0 {
		t.Fatal("expected at least one mapping")
	}
}

func TestParseConfig_NormalizesContractDefaults(t *testing.T) {
	payload := []byte(`
mappings:
  - name: sample
    source: ensemble.tap.test.sample
    nodes:
      - id: service:{{data.service}}
        kind: service
`)
	config, err := ParseConfig(payload)
	if err != nil {
		t.Fatalf("parse config failed: %v", err)
	}
	if config.APIVersion != defaultMappingConfigAPIVersion {
		t.Fatalf("expected default apiVersion %q, got %q", defaultMappingConfigAPIVersion, config.APIVersion)
	}
	if config.Kind != defaultMappingConfigKind {
		t.Fatalf("expected default kind %q, got %q", defaultMappingConfigKind, config.Kind)
	}
	if len(config.Mappings) != 1 {
		t.Fatalf("expected one mapping, got %d", len(config.Mappings))
	}
	if config.Mappings[0].APIVersion != defaultMappingConfigAPIVersion {
		t.Fatalf("expected mapping apiVersion default, got %q", config.Mappings[0].APIVersion)
	}
	if config.Mappings[0].ContractVersion != defaultMappingContractVersion {
		t.Fatalf("expected mapping contractVersion default %q, got %q", defaultMappingContractVersion, config.Mappings[0].ContractVersion)
	}
}

func TestMapperApply_GithubPRMerged(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	now := time.Date(2026, 3, 8, 22, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-pr-1",
		Type:   "ensemble.tap.github.pull_request.merged",
		Time:   now,
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"repository":      "payments-api",
			"number":          42,
			"title":           "Improve reconciliation retries",
			"merged_by":       "alice",
			"merged_by_email": "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping to match event, got %#v", result)
	}

	service, ok := g.GetNode("service:payments-api")
	if !ok || service == nil {
		t.Fatalf("expected service node to be created, got %#v", service)
	}
	if service.Kind != graph.NodeKindService {
		t.Fatalf("expected service node kind %q, got %q", graph.NodeKindService, service.Kind)
	}
	repositoryNode, ok := g.GetNode("repository:github:payments-api")
	if !ok || repositoryNode == nil {
		t.Fatalf("expected repository node to be created, got %#v", repositoryNode)
	}
	if repositoryNode.Kind != graph.NodeKindRepository {
		t.Fatalf("expected repository node kind %q, got %q", graph.NodeKindRepository, repositoryNode.Kind)
	}
	prNode, ok := g.GetNode("pull_request:payments-api:42")
	if !ok || prNode == nil {
		t.Fatalf("expected pull request node to be created, got %#v", prNode)
	}
	if prNode.Kind != graph.NodeKindPullRequest {
		t.Fatalf("expected pull request node kind %q, got %q", graph.NodeKindPullRequest, prNode.Kind)
	}
	if observedAt := strings.TrimSpace(stringValue(service.Properties["observed_at"])); observedAt == "" {
		t.Fatalf("expected observed_at metadata on service node, got %#v", service.Properties)
	}

	outEdges := g.GetOutEdges("person:alice@example.com")
	foundContribution := false
	for _, edge := range outEdges {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindInteractedWith && edge.Target == "service:payments-api" {
			foundContribution = true
			break
		}
	}
	if !foundContribution {
		t.Fatalf("expected person -> service interacted_with edge, got %#v", outEdges)
	}
	foundRepositoryTarget := false
	for _, edge := range g.GetOutEdges("pull_request:payments-api:42") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindTargets && edge.Target == "repository:github:payments-api" {
			foundRepositoryTarget = true
			break
		}
	}
	if !foundRepositoryTarget {
		t.Fatalf("expected pull request -> repository target edge, got %#v", g.GetOutEdges("pull_request:payments-api:42"))
	}
}

func TestMapperApply_NoMatch(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(graph.New(), events.CloudEvent{
		ID:     "evt-other-1",
		Type:   "ensemble.tap.unknown.unmapped",
		Time:   time.Now().UTC(),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"repository": "payments-api"},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected mapping not to match, got %#v", result)
	}
}

func TestMapperApply_SupportTicketUpdated(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-support-1",
		Type:   "ensemble.tap.support.ticket.updated",
		Time:   now,
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"ticket_id":   "12345",
			"subject":     "Payment failures",
			"status":      "open",
			"priority":    "high",
			"update_id":   "u-1",
			"update_type": "comment",
			"agent_email": "agent@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	ticketNode, ok := g.GetNode("ticket:support:12345")
	if !ok || ticketNode == nil || ticketNode.Kind != graph.NodeKindTicket {
		t.Fatalf("expected support ticket node, got %#v", ticketNode)
	}
	actionNode, ok := g.GetNode("action:support_update:12345:u-1")
	if !ok || actionNode == nil {
		t.Fatalf("expected support update action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected support action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}
	assignmentFound := false
	for _, edge := range g.GetOutEdges("person:agent@example.com") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindAssignedTo && edge.Target == "ticket:support:12345" {
			assignmentFound = true
			break
		}
	}
	if !assignmentFound {
		t.Fatalf("expected assigned_to edge to support ticket, got %#v", g.GetOutEdges("person:agent@example.com"))
	}
	if _, ok := g.GetNode("company:"); ok {
		t.Fatal("did not expect empty optional company node")
	}
}

func TestMapperApply_SupportTicketCreatesConditionalBusinessNodes(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:agent@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Agent",
		Properties: map[string]any{
			"email": "agent@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	_, err = mapper.Apply(g, events.CloudEvent{
		ID:     "evt-support-conditional-1",
		Type:   "ensemble.tap.support.ticket.updated",
		Time:   time.Date(2026, 3, 9, 18, 5, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"ticket_id":         "12346",
			"subject":           "Renewal blocker",
			"status":            "open",
			"priority":          "high",
			"update_id":         "u-2",
			"update_type":       "escalation",
			"agent_email":       "agent@example.com",
			"customer_id":       "cust-42",
			"customer_name":     "Acme West",
			"company_id":        "comp-42",
			"company_name":      "Acme Corp",
			"subscription_id":   "sub-42",
			"subscription_name": "Enterprise Annual",
			"subscription_plan": "enterprise",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	for _, id := range []string{"customer:cust-42", "company:comp-42", "subscription:sub-42"} {
		if _, ok := g.GetNode(id); !ok {
			t.Fatalf("expected conditional node %q to exist", id)
		}
	}
	foundCustomerSubscription := false
	for _, edge := range g.GetOutEdges("customer:cust-42") {
		if edge != nil && edge.Kind == graph.EdgeKindSubscribedTo && edge.Target == "subscription:sub-42" {
			foundCustomerSubscription = true
			break
		}
	}
	if !foundCustomerSubscription {
		t.Fatalf("expected customer -> subscription edge, got %#v", g.GetOutEdges("customer:cust-42"))
	}
}

func TestMapperConditionMatches_TreatsScalarValuesAsPresent(t *testing.T) {
	mapper := &Mapper{}
	context := map[string]any{
		"data": map[string]any{
			"customer_zero":  "0",
			"customer_false": "false",
			"customer_null":  "null",
			"customer_empty": "",
		},
	}

	for _, tc := range []struct {
		name string
		when string
		want bool
	}{
		{name: "zero string", when: "{{data.customer_zero}}", want: true},
		{name: "false string", when: "{{data.customer_false}}", want: true},
		{name: "null string", when: "{{data.customer_null}}", want: true},
		{name: "empty string", when: "{{data.customer_empty}}", want: false},
	} {
		if got := mapper.conditionMatches(tc.when, context, events.CloudEvent{}); got != tc.want {
			t.Fatalf("%s: conditionMatches(%q) = %v, want %v", tc.name, tc.when, got, tc.want)
		}
	}
}

func TestMapperApply_CalendarMeetingUsesMeetingKind(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:organizer@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Organizer",
		Properties: map[string]any{
			"email": "organizer@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "payments",
		Properties: map[string]any{
			"service_id": "payments",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-meeting-1",
		Type:   "ensemble.tap.calendar.meeting.recorded",
		Time:   time.Date(2026, 3, 9, 18, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"meeting_id":      "mtg-1",
			"title":           "Payments Reliability Review",
			"organizer_email": "organizer@example.com",
			"starts_at":       "2026-03-09T18:30:00Z",
			"ends_at":         "2026-03-09T19:00:00Z",
			"service":         "payments",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	meeting, ok := g.GetNode("meeting:mtg-1")
	if !ok || meeting == nil {
		t.Fatalf("expected meeting node, got %#v", meeting)
	}
	if meeting.Kind != graph.NodeKindMeeting {
		t.Fatalf("expected meeting node kind %q, got %q", graph.NodeKindMeeting, meeting.Kind)
	}
}

func TestMapperApply_SlackThreadMessageUsesActionKind(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:author@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Author",
		Properties: map[string]any{
			"email": "author@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-slack-1",
		Type:   "ensemble.tap.slack.thread.message_posted",
		Time:   time.Date(2026, 3, 9, 19, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"channel_id":   "C123",
			"thread_ts":    "1700000000.000100",
			"message_ts":   "1700000000.000200",
			"channel_name": "payments-alerts",
			"text":         "Investigating elevated timeout rate",
			"author_email": "author@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	thread, ok := g.GetNode("thread:slack:C123:1700000000.000100")
	if !ok || thread == nil || thread.Kind != graph.NodeKindThread {
		t.Fatalf("expected thread node, got %#v", thread)
	}
	actionNode, ok := g.GetNode("action:slack_message:C123:1700000000.000200")
	if !ok || actionNode == nil {
		t.Fatalf("expected slack action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected slack action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}

	targetFound := false
	for _, edge := range g.GetOutEdges("action:slack_message:C123:1700000000.000200") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindTargets && edge.Target == "thread:slack:C123:1700000000.000100" {
			targetFound = true
			break
		}
	}
	if !targetFound {
		t.Fatalf("expected slack action to target thread, got %#v", g.GetOutEdges("action:slack_message:C123:1700000000.000200"))
	}
}

func TestMapperApply_GithubCheckRunCreatesRepositoryAndWorkflow(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:author@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Author",
		Properties: map[string]any{
			"email": "author@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-check-1",
		Type:   "ensemble.tap.github.check_run.completed",
		Time:   time.Date(2026, 3, 10, 15, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"repository":   "payments-api",
			"check_run_id": "123",
			"check_name":   "build-and-test",
			"status":       "completed",
			"conclusion":   "success",
			"actor_email":  "author@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	workflow, ok := g.GetNode("ci_workflow:github:payments-api:build-and-test")
	if !ok || workflow == nil || workflow.Kind != graph.NodeKindCIWorkflow {
		t.Fatalf("expected ci_workflow node, got %#v", workflow)
	}
	repositoryNode, ok := g.GetNode("repository:github:payments-api")
	if !ok || repositoryNode == nil || repositoryNode.Kind != graph.NodeKindRepository {
		t.Fatalf("expected repository node, got %#v", repositoryNode)
	}
	checkRun, ok := g.GetNode("check_run:payments-api:123")
	if !ok || checkRun == nil {
		t.Fatalf("expected check_run node, got %#v", checkRun)
	}
	foundWorkflowLink := false
	for _, edge := range g.GetOutEdges("check_run:payments-api:123") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "ci_workflow:github:payments-api:build-and-test" {
			foundWorkflowLink = true
			break
		}
	}
	if !foundWorkflowLink {
		t.Fatalf("expected check_run -> ci_workflow link, got %#v", g.GetOutEdges("check_run:payments-api:123"))
	}
}

func TestMapperApply_CIPipelineCreatesWorkflow(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()

	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-pipeline-1",
		Type:   "ensemble.tap.ci.pipeline.completed",
		Time:   time.Date(2026, 3, 10, 16, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"service":       "payments",
			"pipeline_id":   "pipe-1",
			"pipeline_name": "Deploy Payments",
			"run_id":        "run-9",
			"actor_email":   "build@example.com",
			"status":        "success",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	workflow, ok := g.GetNode("ci_workflow:ci:payments:pipe-1")
	if !ok || workflow == nil || workflow.Kind != graph.NodeKindCIWorkflow {
		t.Fatalf("expected ci_workflow node, got %#v", workflow)
	}
	pipelineRun, ok := g.GetNode("pipeline_run:payments:pipe-1:run-9")
	if !ok || pipelineRun == nil {
		t.Fatalf("expected pipeline_run node, got %#v", pipelineRun)
	}
	foundWorkflowLink := false
	for _, edge := range g.GetOutEdges("pipeline_run:payments:pipe-1:run-9") {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindBasedOn && edge.Target == "ci_workflow:ci:payments:pipe-1" {
			foundWorkflowLink = true
			break
		}
	}
	if !foundWorkflowLink {
		t.Fatalf("expected pipeline_run -> ci_workflow link, got %#v", g.GetOutEdges("pipeline_run:payments:pipe-1:run-9"))
	}
}

func TestMapperApply_SalesCallLoggedUsesActionKind(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:rep@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Rep",
		Properties: map[string]any{
			"email": "rep@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-sales-1",
		Type:   "ensemble.tap.sales.call.logged",
		Time:   time.Date(2026, 3, 9, 20, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"call_id":          "call-77",
			"contact_id":       "cont-123",
			"contact_name":     "Ari Lee",
			"contact_email":    "ari@example.com",
			"summary":          "Reviewed renewal and expansion timeline",
			"duration_minutes": 28,
			"rep_email":        "rep@example.com",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}

	contact, ok := g.GetNode("contact:cont-123")
	if !ok || contact == nil || contact.Kind != graph.NodeKindContact {
		t.Fatalf("expected contact node, got %#v", contact)
	}
	actionNode, ok := g.GetNode("action:sales_call:call-77")
	if !ok || actionNode == nil {
		t.Fatalf("expected sales action node, got %#v", actionNode)
	}
	if actionNode.Kind != graph.NodeKindAction {
		t.Fatalf("expected sales action node kind %q, got %q", graph.NodeKindAction, actionNode.Kind)
	}
	if _, ok := g.GetNode("company:"); ok {
		t.Fatal("did not expect empty optional company node")
	}
}

func TestMapperApply_SalesCallLoggedCreatesConditionalBusinessNodes(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:   "person:rep@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Rep",
		Properties: map[string]any{
			"email": "rep@example.com",
		},
	})

	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	_, err = mapper.Apply(g, events.CloudEvent{
		ID:     "evt-sales-conditional-1",
		Type:   "ensemble.tap.sales.call.logged",
		Time:   time.Date(2026, 3, 9, 20, 10, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"call_id":            "call-78",
			"contact_id":         "cont-124",
			"contact_name":       "Ari Lee",
			"contact_email":      "ari@example.com",
			"summary":            "Qualified expansion and next procurement steps",
			"duration_minutes":   31,
			"rep_email":          "rep@example.com",
			"company_id":         "comp-7",
			"company_name":       "Northwind",
			"company_domain":     "northwind.example",
			"lead_id":            "lead-7",
			"lead_name":          "Northwind Expansion",
			"lead_source":        "conference",
			"opportunity_id":     "opp-7",
			"opportunity_name":   "Northwind Expansion FY26",
			"opportunity_stage":  "qualified",
			"opportunity_amount": 120000,
			"deal_id":            "deal-7",
			"deal_name":          "Northwind Annual",
			"deal_stage":         "proposal",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	for _, id := range []string{"company:comp-7", "lead:lead-7", "opportunity:opp-7", "deal:deal-7"} {
		if _, ok := g.GetNode(id); !ok {
			t.Fatalf("expected conditional node %q to exist", id)
		}
	}
	foundContactCompany := false
	for _, edge := range g.GetOutEdges("contact:cont-124") {
		if edge != nil && edge.Kind == graph.EdgeKindWorksAt && edge.Target == "company:comp-7" {
			foundContactCompany = true
			break
		}
	}
	if !foundContactCompany {
		t.Fatalf("expected contact -> company works_at edge, got %#v", g.GetOutEdges("contact:cont-124"))
	}
}

func TestMapperApply_EnforceValidationRejectsInvalidWritesToDeadLetter(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "invalid_kind",
				Source: "ensemble.tap.test.invalid",
				Nodes: []NodeMapping{
					{
						ID:       "test:entity:1",
						Kind:     "nonexistent_kind",
						Name:     "Invalid",
						Provider: "test",
					},
				},
			},
		},
	}
	dlqPath := filepath.Join(t.TempDir(), "mapper.dlq.jsonl")
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-invalid-1",
		Type:   "ensemble.tap.test.invalid",
		Time:   time.Date(2026, 3, 9, 21, 0, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected mapping match, got %#v", result)
	}
	if result.NodesRejected != 1 || result.DeadLettered != 1 {
		t.Fatalf("expected one rejected/dead-lettered node, got %#v", result)
	}
	if _, ok := g.GetNode("test:entity:1"); ok {
		t.Fatal("expected invalid node to be rejected")
	}
	stats := mapper.Stats()
	if stats.NodesRejected != 1 || stats.DeadLettered != 1 {
		t.Fatalf("unexpected mapper stats: %#v", stats)
	}
	payload, err := os.ReadFile(dlqPath)
	if err != nil {
		t.Fatalf("read dead-letter file failed: %v", err)
	}
	if !strings.Contains(string(payload), "nonexistent_kind") {
		t.Fatalf("expected dead-letter payload to mention invalid kind, got %s", string(payload))
	}
}

func TestMapperApply_EnforceValidationRejectsInvalidEventContract(t *testing.T) {
	config := MappingConfig{
		APIVersion: "cerebro.graphingest/v1alpha1",
		Mappings: []EventMapping{
			{
				Name:            "event_contract",
				Source:          "ensemble.tap.test.contract.updated",
				ContractVersion: "1.0.0",
				SchemaURL:       "https://schemas.example.com/event-contract.json",
				DataEnums: map[string][]string{
					"status": []string{"open", "closed"},
				},
				Nodes: []NodeMapping{
					{
						ID:       "service:{{data.service}}",
						Kind:     "service",
						Name:     "{{data.service}}",
						Provider: "test",
						Properties: map[string]any{
							"service_id": "{{data.service}}",
						},
					},
				},
			},
		},
	}
	dlqPath := filepath.Join(t.TempDir(), "event-contract.dlq.jsonl")
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:            "evt-contract-bad-1",
		Type:          "ensemble.tap.test.contract.updated",
		Time:          time.Date(2026, 3, 9, 22, 10, 0, 0, time.UTC),
		Source:        "urn:ensemble:tap",
		SchemaVersion: "0.9.0",
		DataSchema:    "https://schemas.example.com/other.json",
		Data: map[string]any{
			"status": "invalid_status",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.EventsRejected != 1 || result.DeadLettered != 1 {
		t.Fatalf("expected one rejected/dead-lettered event, got %#v", result)
	}
	if result.Matched {
		t.Fatalf("expected Matched=false when contract validation rejects event, got %#v", result)
	}
	if len(result.NodesUpserted) > 0 || len(result.EdgesUpserted) > 0 {
		t.Fatalf("expected no writes after event-contract rejection, got %#v", result)
	}

	stats := mapper.Stats()
	if stats.EventsRejected != 1 {
		t.Fatalf("expected events_rejected=1, got %#v", stats)
	}
	if stats.EventRejectByCode[string(graph.SchemaIssueInvalidEventContract)] < 1 {
		t.Fatalf("expected invalid_event_contract reject code, got %#v", stats.EventRejectByCode)
	}
	payload, err := os.ReadFile(dlqPath)
	if err != nil {
		t.Fatalf("read dead-letter file failed: %v", err)
	}
	if !strings.Contains(string(payload), string(graph.SchemaIssueInvalidEventContract)) {
		t.Fatalf("expected dead-letter payload to include invalid_event_contract, got %s", string(payload))
	}
}

func TestMapperApply_EnrichesContractMetadataPointers(t *testing.T) {
	config := MappingConfig{
		APIVersion: "cerebro.graphingest/v1alpha1",
		Mappings: []EventMapping{
			{
				Name:            "metadata_pointers",
				Source:          "ensemble.tap.test.metadata.updated",
				ContractVersion: "2.1.0",
				SchemaURL:       "https://schemas.example.com/metadata.json",
				Nodes: []NodeMapping{
					{
						ID:       "service:{{data.service}}",
						Kind:     "service",
						Name:     "{{data.service}}",
						Provider: "test",
						Properties: map[string]any{
							"service_id": "{{data.service}}",
						},
					},
				},
			},
		},
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:            "evt-metadata-1",
		Type:          "ensemble.tap.test.metadata.updated",
		Time:          time.Date(2026, 3, 9, 22, 30, 0, 0, time.UTC),
		Source:        "urn:ensemble:tap",
		SchemaVersion: "2.1.0",
		DataSchema:    "https://schemas.example.com/metadata.json",
		Data: map[string]any{
			"service": "payments",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.EventsRejected != 0 || result.NodesRejected != 0 || result.EdgesRejected != 0 {
		t.Fatalf("expected no rejections, got %#v", result)
	}

	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatalf("expected node service:payments, got %#v", node)
	}
	for _, key := range []string{"source_schema_url", "producer_fingerprint", "contract_version", "contract_api_version", "mapping_name", "event_type", "recorded_at", "transaction_from"} {
		value := strings.TrimSpace(valueToString(node.Properties[key]))
		if value == "" {
			t.Fatalf("expected metadata pointer %q on node, got %#v", key, node.Properties)
		}
	}
}

func TestMapperApply_WarnValidationAllowsInvalidWrites(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "warn_invalid_kind",
				Source: "ensemble.tap.test.invalid.warn",
				Nodes: []NodeMapping{
					{
						ID:       "test:entity:warn",
						Kind:     "nonexistent_kind",
						Name:     "Invalid But Allowed",
						Provider: "test",
					},
				},
			},
		},
	}
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationWarn,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}

	g := graph.New()
	result, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-invalid-warn-1",
		Type:   "ensemble.tap.test.invalid.warn",
		Time:   time.Date(2026, 3, 9, 21, 5, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.NodesRejected != 0 {
		t.Fatalf("expected warn mode not to reject writes, got %#v", result)
	}
	node, ok := g.GetNode("test:entity:warn")
	if !ok || node == nil {
		t.Fatalf("expected invalid node to be written in warn mode, got %#v", node)
	}
}

func TestMapperApply_EnforceValidationRejectsInvalidProvenance(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "invalid_provenance",
				Source: "ensemble.tap.test.provenance",
				Nodes: []NodeMapping{
					{
						ID:       "service:payments",
						Kind:     "service",
						Name:     "Payments",
						Provider: "test",
						Properties: map[string]any{
							"service_id":  "payments",
							"observed_at": "{{data.observed_at}}",
							"valid_from":  "{{data.valid_from}}",
							"confidence":  "{{data.confidence}}",
						},
					},
				},
			},
		},
	}
	mapper, err := NewMapperWithOptions(config, nil, MapperOptions{
		ValidationMode: MapperValidationEnforce,
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	result, err := mapper.Apply(graph.New(), events.CloudEvent{
		ID:     "evt-provenance-1",
		Type:   "ensemble.tap.test.provenance",
		Time:   time.Date(2026, 3, 9, 21, 20, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"observed_at": "not-a-time",
			"valid_from":  "2026-03-09T21:00:00Z",
			"confidence":  "not-a-number",
		},
	})
	if err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}
	if result.NodesRejected != 0 || len(result.NodesUpserted) != 1 {
		t.Fatalf("expected mapper to normalize weak provenance instead of rejecting, got %#v", result)
	}
	g := graph.New()
	if _, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-provenance-2",
		Type:   "ensemble.tap.test.provenance",
		Time:   time.Date(2026, 3, 9, 21, 20, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data: map[string]any{
			"observed_at": "not-a-time",
			"valid_from":  "2026-03-09T21:00:00Z",
			"confidence":  "not-a-number",
		},
	}); err != nil {
		t.Fatalf("second mapper apply failed: %v", err)
	}
	node, ok := g.GetNode("service:payments")
	if !ok || node == nil {
		t.Fatalf("expected normalized node write, got %#v", node)
	}
	for _, key := range []string{"observed_at", "valid_from", "recorded_at", "transaction_from", "confidence"} {
		if strings.TrimSpace(valueToString(node.Properties[key])) == "" {
			t.Fatalf("expected normalized metadata key %q, got %#v", key, node.Properties)
		}
	}
}

func TestMapperStatsIncludesPerSourceCounters(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:   "github_match",
				Source: "ensemble.tap.github.pull_request.opened",
				Nodes: []NodeMapping{
					{
						ID:       "service:payments",
						Kind:     "service",
						Name:     "Payments",
						Provider: "github",
						Properties: map[string]any{
							"service_id": "payments",
						},
					},
				},
			},
		},
	}
	mapper, err := NewMapper(config, nil)
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}
	g := graph.New()
	if _, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-github-1",
		Type:   "ensemble.tap.github.pull_request.opened",
		Time:   time.Date(2026, 3, 9, 21, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	}); err != nil {
		t.Fatalf("mapper apply github failed: %v", err)
	}
	if _, err := mapper.Apply(g, events.CloudEvent{
		ID:     "evt-slack-1",
		Type:   "ensemble.tap.slack.unknown",
		Time:   time.Date(2026, 3, 9, 21, 31, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{},
	}); err != nil {
		t.Fatalf("mapper apply slack failed: %v", err)
	}

	stats := mapper.Stats()
	github := stats.SourceStats["github"]
	if github.EventsProcessed != 1 || github.EventsMatched != 1 {
		t.Fatalf("unexpected github source stats: %#v", github)
	}
	slack := stats.SourceStats["slack"]
	if slack.EventsProcessed != 1 || slack.EventsUnmatched != 1 {
		t.Fatalf("unexpected slack source stats: %#v", slack)
	}
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}
