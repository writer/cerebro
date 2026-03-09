package graphingest

import (
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
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
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}
