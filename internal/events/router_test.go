package events

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/webhooks"
)

func TestLoadAlertRoutingConfig_Default(t *testing.T) {
	config, err := LoadAlertRoutingConfig("")
	if err != nil {
		t.Fatalf("load default alert routing config: %v", err)
	}
	if len(config.Routes) < 3 {
		t.Fatalf("expected default config to include multiple routes, got %d", len(config.Routes))
	}
}

func TestAlertRouterRoutesToOwnerAndChannel(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{
			{
				Name: "high_findings",
				Match: AlertRouteMatch{
					EventType: "finding.created",
					Severity:  []string{"critical", "high"},
				},
				DeliverTo: []AlertRouteDelivery{
					{Type: "entity_owner", Channel: "dm"},
					{Type: "channel", Channel: "#security-alerts"},
				},
			},
		},
	}

	sender := &captureAlertSender{}
	resolver := &stubAlertResolver{
		owners: []AlertRecipient{{Type: "person", ID: "person:alice@example.com", Channel: "dm"}},
	}
	router := newRouterForTest(t, config, resolver, sender, &now)

	err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventFindingCreated,
		Timestamp: now,
		Data: map[string]interface{}{
			"severity":  "critical",
			"entity_id": "customer:acme",
		},
	})
	if err != nil {
		t.Fatalf("route event: %v", err)
	}

	if got := len(sender.messages); got != 2 {
		t.Fatalf("expected 2 routed alerts, got %d", got)
	}

	subjects := []string{sender.messages[0].subject, sender.messages[1].subject}
	sort.Strings(subjects)
	expected := []string{"ensemble.notify.dm", "ensemble.notify.security-alerts"}
	if subjects[0] != expected[0] || subjects[1] != expected[1] {
		t.Fatalf("unexpected subjects: got %v want %v", subjects, expected)
	}

	payload := decodeAlertPayload(t, sender.messages[0].payload)
	if payload["alert_type"] == "" {
		t.Fatalf("expected alert_type in routed payload, got %#v", payload)
	}
}

func TestAlertRouterThrottle(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{
			{
				Name: "risk_spike",
				Match: AlertRouteMatch{
					EventType: "risk_score.changed",
					Delta:     "> 0.3",
				},
				DeliverTo: []AlertRouteDelivery{
					{Type: "channel", Channel: "#ops-alerts"},
				},
				GroupBy:  "entity_id",
				Throttle: "5m",
			},
		},
	}

	sender := &captureAlertSender{}
	router := newRouterForTest(t, config, &stubAlertResolver{}, sender, &now)

	event := func(id string) webhooks.Event {
		return webhooks.Event{
			ID:        id,
			Type:      webhooks.EventRiskScoreChanged,
			Timestamp: now,
			Data: map[string]interface{}{
				"entity_id":   "customer:acme",
				"risk_delta":  0.41,
				"severity":    "high",
				"description": "risk spike",
			},
		}
	}

	if err := router.Route(context.Background(), event("evt-1")); err != nil {
		t.Fatalf("route first event: %v", err)
	}
	if err := router.Route(context.Background(), event("evt-2")); err != nil {
		t.Fatalf("route second event: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected second event to be throttled, got %d deliveries", got)
	}

	now = now.Add(6 * time.Minute)
	if err := router.Route(context.Background(), event("evt-3")); err != nil {
		t.Fatalf("route third event: %v", err)
	}
	if got := len(sender.messages); got != 2 {
		t.Fatalf("expected delivery after throttle window, got %d", got)
	}
}

func TestAlertRouterDigest(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{
			{
				Name: "digest",
				Match: AlertRouteMatch{
					EventType: "finding.created",
				},
				DeliverTo: []AlertRouteDelivery{
					{Type: "channel", Channel: "#security-digest"},
				},
				GroupBy: "entity_id",
				Digest:  "10m",
			},
		},
	}

	sender := &captureAlertSender{}
	router := newRouterForTest(t, config, &stubAlertResolver{}, sender, &now)

	event := func(id string) webhooks.Event {
		return webhooks.Event{
			ID:        id,
			Type:      webhooks.EventFindingCreated,
			Timestamp: now,
			Data: map[string]interface{}{
				"entity_id": "customer:acme",
				"severity":  "low",
			},
		}
	}

	if err := router.Route(context.Background(), event("evt-1")); err != nil {
		t.Fatalf("route first event: %v", err)
	}
	now = now.Add(5 * time.Minute)
	if err := router.Route(context.Background(), event("evt-2")); err != nil {
		t.Fatalf("route second event: %v", err)
	}
	if got := len(sender.messages); got != 0 {
		t.Fatalf("expected digest to defer delivery, got %d messages", got)
	}

	now = now.Add(6 * time.Minute)
	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-non-match",
		Type:      webhooks.EventScanCompleted,
		Timestamp: now,
		Data:      map[string]interface{}{"scanned": 10},
	}); err != nil {
		t.Fatalf("route trigger event: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected one digest delivery after window, got %d", got)
	}

	payload := decodeAlertPayload(t, sender.messages[0].payload)
	if payload["alert_type"] != "digest" {
		t.Fatalf("expected digest payload, got %#v", payload["alert_type"])
	}
	if payload["digest_count"] != float64(2) {
		t.Fatalf("expected digest_count=2, got %#v", payload["digest_count"])
	}
}

func TestAlertRouterEscalationAndAck(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{
			{
				Name: "critical_finding_owner",
				Match: AlertRouteMatch{
					EventType: "finding.created",
					Severity:  []string{"critical"},
				},
				DeliverTo: []AlertRouteDelivery{
					{Type: "entity_owner", Channel: "dm"},
				},
				EscalateAfter: "1m",
			},
		},
	}

	sender := &captureAlertSender{}
	resolver := &stubAlertResolver{
		owners: []AlertRecipient{
			{Type: "person", ID: "person:alice@example.com", Channel: "dm"},
		},
		managers: map[string]AlertRecipient{
			"person:alice@example.com": {Type: "person", ID: "person:manager@example.com", Channel: "dm"},
		},
	}
	router := newRouterForTest(t, config, resolver, sender, &now)

	event := webhooks.Event{
		ID:        "evt-critical-1",
		Type:      webhooks.EventFindingCreated,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id": "customer:acme",
			"severity":  "critical",
		},
	}
	if err := router.Route(context.Background(), event); err != nil {
		t.Fatalf("route event: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected initial owner alert, got %d", got)
	}

	firstPayload := decodeAlertPayload(t, sender.messages[0].payload)
	alertID, _ := firstPayload["alert_id"].(string)
	if alertID == "" {
		t.Fatalf("expected alert_id in payload: %#v", firstPayload)
	}
	if !router.Acknowledge(alertID, "person:alice@example.com") {
		t.Fatalf("expected acknowledge to clear pending alert")
	}

	now = now.Add(2 * time.Minute)
	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-tick",
		Type:      webhooks.EventScanCompleted,
		Timestamp: now,
		Data:      map[string]interface{}{"scanned": 100},
	}); err != nil {
		t.Fatalf("route tick event: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected no escalation after ack, got %d messages", got)
	}

	// Emit another critical alert without ack to validate escalation behavior.
	now = now.Add(time.Minute)
	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-critical-2",
		Type:      webhooks.EventFindingCreated,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id": "customer:acme",
			"severity":  "critical",
		},
	}); err != nil {
		t.Fatalf("route second critical event: %v", err)
	}

	now = now.Add(2 * time.Minute)
	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-tick-2",
		Type:      webhooks.EventScanCompleted,
		Timestamp: now,
		Data:      map[string]interface{}{"scanned": 101},
	}); err != nil {
		t.Fatalf("route second tick event: %v", err)
	}
	if got := len(sender.messages); got != 3 {
		t.Fatalf("expected escalation delivery, got %d messages", got)
	}

	escalation := decodeAlertPayload(t, sender.messages[2].payload)
	if escalation["alert_type"] != "escalation" {
		t.Fatalf("expected escalation payload, got %#v", escalation["alert_type"])
	}
}

func TestAlertRouterThrottlePersistsAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "router.db")
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{{
			Name: "risk_spike",
			Match: AlertRouteMatch{
				EventType: "risk_score.changed",
				Delta:     "> 0.3",
			},
			DeliverTo: []AlertRouteDelivery{{Type: "channel", Channel: "#ops-alerts"}},
			GroupBy:   "entity_id",
			Throttle:  "5m",
		}},
	}

	store, err := NewSQLiteAlertRouterStateStore(dbPath)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	sender1 := &captureAlertSender{}
	router := newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender1, store, &now)

	event := webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventRiskScoreChanged,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id":  "customer:acme",
			"risk_delta": 0.41,
			"severity":   "high",
		},
	}
	if err := router.Route(context.Background(), event); err != nil {
		t.Fatalf("route event: %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("close router: %v", err)
	}

	now = now.Add(time.Minute)
	reopenStore, err := NewSQLiteAlertRouterStateStore(dbPath)
	if err != nil {
		t.Fatalf("re-open state store: %v", err)
	}
	sender2 := &captureAlertSender{}
	router = newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender2, reopenStore, &now)
	defer func() { _ = router.Close() }()

	if err := router.Route(context.Background(), event); err != nil {
		t.Fatalf("route throttled event after restart: %v", err)
	}
	if got := len(sender2.messages); got != 0 {
		t.Fatalf("expected throttle to survive restart, got %d messages", got)
	}
}

func TestAlertRouterDigestPersistsAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "router.db")
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{{
			Name:      "digest",
			Match:     AlertRouteMatch{EventType: "finding.created"},
			DeliverTo: []AlertRouteDelivery{{Type: "channel", Channel: "#security-digest"}},
			GroupBy:   "entity_id",
			Digest:    "10m",
		}},
	}

	store, err := NewSQLiteAlertRouterStateStore(dbPath)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	sender1 := &captureAlertSender{}
	router := newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender1, store, &now)
	event := func(id string) webhooks.Event {
		return webhooks.Event{
			ID:        id,
			Type:      webhooks.EventFindingCreated,
			Timestamp: now,
			Data: map[string]interface{}{
				"entity_id": "customer:acme",
				"severity":  "low",
			},
		}
	}
	if err := router.Route(context.Background(), event("evt-1")); err != nil {
		t.Fatalf("route first event: %v", err)
	}
	now = now.Add(5 * time.Minute)
	if err := router.Route(context.Background(), event("evt-2")); err != nil {
		t.Fatalf("route second event: %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("close router: %v", err)
	}

	now = now.Add(6 * time.Minute)
	reopenStore, err := NewSQLiteAlertRouterStateStore(dbPath)
	if err != nil {
		t.Fatalf("re-open state store: %v", err)
	}
	sender2 := &captureAlertSender{}
	router = newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender2, reopenStore, &now)
	defer func() { _ = router.Close() }()

	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-tick",
		Type:      webhooks.EventScanCompleted,
		Timestamp: now,
		Data:      map[string]interface{}{"scanned": 10},
	}); err != nil {
		t.Fatalf("route tick event: %v", err)
	}
	if got := len(sender2.messages); got != 1 {
		t.Fatalf("expected persisted digest delivery after restart, got %d", got)
	}
	payload := decodeAlertPayload(t, sender2.messages[0].payload)
	if payload["digest_count"] != float64(2) {
		t.Fatalf("expected digest_count=2, got %#v", payload["digest_count"])
	}
}

func TestAlertRouterEscalationPersistsAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "router.db")
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{{
			Name: "critical_finding_owner",
			Match: AlertRouteMatch{
				EventType: "finding.created",
				Severity:  []string{"critical"},
			},
			DeliverTo:     []AlertRouteDelivery{{Type: "entity_owner", Channel: "dm"}},
			EscalateAfter: "1m",
		}},
	}
	resolver := &stubAlertResolver{
		owners: []AlertRecipient{{Type: "person", ID: "person:alice@example.com", Channel: "dm"}},
		managers: map[string]AlertRecipient{
			"person:alice@example.com": {Type: "person", ID: "person:manager@example.com", Channel: "dm"},
		},
	}

	store, err := NewSQLiteAlertRouterStateStore(dbPath)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	sender1 := &captureAlertSender{}
	router := newRouterForTestWithStore(t, config, resolver, sender1, store, &now)

	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-critical-1",
		Type:      webhooks.EventFindingCreated,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id": "customer:acme",
			"severity":  "critical",
		},
	}); err != nil {
		t.Fatalf("route critical event: %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("close router: %v", err)
	}

	now = now.Add(2 * time.Minute)
	reopenStore, err := NewSQLiteAlertRouterStateStore(dbPath)
	if err != nil {
		t.Fatalf("re-open state store: %v", err)
	}
	sender2 := &captureAlertSender{}
	router = newRouterForTestWithStore(t, config, resolver, sender2, reopenStore, &now)
	defer func() { _ = router.Close() }()

	if err := router.Route(context.Background(), webhooks.Event{
		ID:        "evt-tick",
		Type:      webhooks.EventScanCompleted,
		Timestamp: now,
		Data:      map[string]interface{}{"scanned": 100},
	}); err != nil {
		t.Fatalf("route tick event: %v", err)
	}
	if got := len(sender2.messages); got != 1 {
		t.Fatalf("expected escalation after restart, got %d messages", got)
	}
	payload := decodeAlertPayload(t, sender2.messages[0].payload)
	if payload["alert_type"] != "escalation" {
		t.Fatalf("expected escalation payload, got %#v", payload["alert_type"])
	}
}

func TestAlertRouterFallsBackToStatelessWhenPersistedStateLoadFails(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{{
			Name: "risk_spike",
			Match: AlertRouteMatch{
				EventType: "risk_score.changed",
				Delta:     "> 0.3",
			},
			DeliverTo: []AlertRouteDelivery{{Type: "channel", Channel: "#ops-alerts"}},
			GroupBy:   "entity_id",
			Throttle:  "5m",
		}},
	}
	stateStore := &failingAlertRouterStateStore{loadErr: fmt.Errorf("decode alert router state: corrupt payload")}
	sender := &captureAlertSender{}
	router := newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender, stateStore, &now)
	defer func() { _ = router.Close() }()

	event := webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventRiskScoreChanged,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id":  "customer:acme",
			"risk_delta": 0.41,
			"severity":   "high",
		},
	}
	if err := router.Route(context.Background(), event); err != nil {
		t.Fatalf("route event with corrupt persisted state: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected alert delivery after stateless fallback, got %d", got)
	}
	if stateStore.saveCalls == 0 {
		t.Fatal("expected router to resume persisting fresh state after fallback")
	}
}

func TestAlertRouterRouteKeepsInMemoryStateWhenPersistenceFailsAfterDelivery(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{{
			Name: "risk_spike",
			Match: AlertRouteMatch{
				EventType: "risk_score.changed",
				Delta:     "> 0.3",
			},
			DeliverTo: []AlertRouteDelivery{{Type: "channel", Channel: "#ops-alerts"}},
			GroupBy:   "entity_id",
			Throttle:  "5m",
		}},
	}
	stateStore := &failingAlertRouterStateStore{failSave: true}
	sender := &captureAlertSender{}
	router := newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender, stateStore, &now)
	defer func() { _ = router.Close() }()

	event := webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventRiskScoreChanged,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id":  "customer:acme",
			"risk_delta": 0.41,
			"severity":   "high",
		},
	}
	if err := router.Route(context.Background(), event); err == nil {
		t.Fatal("expected route to fail when persistence fails")
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected alert delivery before persistence failure, got %d", got)
	}

	stateStore.failSave = false
	if err := router.Route(context.Background(), event); err != nil {
		t.Fatalf("route after persistence recovery: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected in-memory throttle state to suppress duplicate delivery, got %d", got)
	}
}

func TestAlertRouterRouteRollsBackStateWhenDeliveryFails(t *testing.T) {
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC)
	config := AlertRoutingConfig{
		Routes: []AlertRoute{{
			Name: "risk_spike",
			Match: AlertRouteMatch{
				EventType: "risk_score.changed",
				Delta:     "> 0.3",
			},
			DeliverTo: []AlertRouteDelivery{{Type: "channel", Channel: "#ops-alerts"}},
			GroupBy:   "entity_id",
			Throttle:  "5m",
		}},
	}
	stateStore := &failingAlertRouterStateStore{}
	sender := &failingAlertSender{failuresRemaining: 1}
	router := newRouterForTestWithStore(t, config, &stubAlertResolver{}, sender, stateStore, &now)
	defer func() { _ = router.Close() }()

	event := webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventRiskScoreChanged,
		Timestamp: now,
		Data: map[string]interface{}{
			"entity_id":  "customer:acme",
			"risk_delta": 0.41,
			"severity":   "high",
		},
	}
	if err := router.Route(context.Background(), event); err == nil {
		t.Fatal("expected route to fail when delivery fails")
	}
	if stateStore.saveCalls != 0 {
		t.Fatalf("expected no state persistence on delivery failure, got %d saves", stateStore.saveCalls)
	}

	if err := router.Route(context.Background(), event); err != nil {
		t.Fatalf("route after delivery recovery: %v", err)
	}
	if got := len(sender.messages); got != 1 {
		t.Fatalf("expected alert to send after rollback and retry, got %d", got)
	}
}

func TestGraphAlertResolver(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "customer:acme", Kind: graph.NodeKindCustomer, Name: "Acme"})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]interface{}{
		"email": "alice@example.com",
	}})
	g.AddNode(&graph.Node{ID: "person:manager@example.com", Kind: graph.NodeKindPerson, Name: "Manager"})
	g.AddNode(&graph.Node{ID: "department:eng", Kind: graph.NodeKindDepartment, Name: "Engineering", Properties: map[string]interface{}{
		"slack_channel": "#eng-alerts",
	}})
	g.AddEdge(&graph.Edge{ID: "owner", Source: "person:alice@example.com", Target: "customer:acme", Kind: graph.EdgeKindManagedBy, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "team", Source: "person:alice@example.com", Target: "department:eng", Kind: graph.EdgeKindMemberOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "mgr", Source: "person:alice@example.com", Target: "person:manager@example.com", Kind: graph.EdgeKindReportsTo, Effect: graph.EdgeEffectAllow})

	resolver := NewGraphAlertResolver(func() *graph.Graph { return g })
	owners := resolver.ResolveEntityOwner(context.Background(), "customer:acme", webhooks.Event{})
	if len(owners) == 0 {
		t.Fatal("expected at least one owner")
	}
	if owners[0].ID != "person:alice@example.com" {
		t.Fatalf("unexpected owner: %+v", owners[0])
	}

	team := resolver.ResolveAccountTeam(context.Background(), "customer:acme", webhooks.Event{})
	if len(team) == 0 {
		t.Fatal("expected account team recipients")
	}

	manager, ok := resolver.ResolveManager(context.Background(), "person:alice@example.com")
	if !ok {
		t.Fatal("expected manager resolution")
	}
	if manager.ID != "person:manager@example.com" {
		t.Fatalf("unexpected manager recipient: %+v", manager)
	}
}

func newRouterForTest(t *testing.T, config AlertRoutingConfig, resolver AlertRecipientResolver, sender AlertSender, now *time.Time) *AlertRouter {
	t.Helper()
	router, err := NewAlertRouter(AlertRouterOptions{
		Config:        config,
		Resolver:      resolver,
		Sender:        sender,
		SubjectPrefix: "ensemble.notify",
		Now: func() time.Time {
			return now.UTC()
		},
	})
	if err != nil {
		t.Fatalf("new alert router: %v", err)
	}
	return router
}

func newRouterForTestWithStore(t *testing.T, config AlertRoutingConfig, resolver AlertRecipientResolver, sender AlertSender, store AlertRouterStateStore, now *time.Time) *AlertRouter {
	t.Helper()
	router, err := NewAlertRouter(AlertRouterOptions{
		Config:        config,
		Resolver:      resolver,
		Sender:        sender,
		StateStore:    store,
		SubjectPrefix: "ensemble.notify",
		Now: func() time.Time {
			return now.UTC()
		},
	})
	if err != nil {
		t.Fatalf("new alert router with store: %v", err)
	}
	return router
}

func decodeAlertPayload(t *testing.T, payload []byte) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return out
}

type captureAlertSender struct {
	messages []capturedAlertMessage
}

type failingAlertSender struct {
	captureAlertSender
	failuresRemaining int
}

type capturedAlertMessage struct {
	subject string
	payload []byte
}

func (c *captureAlertSender) Send(_ context.Context, subject string, payload []byte) error {
	c.messages = append(c.messages, capturedAlertMessage{
		subject: subject,
		payload: append([]byte(nil), payload...),
	})
	return nil
}

func (c *captureAlertSender) Close() error {
	return nil
}

func (f *failingAlertSender) Send(ctx context.Context, subject string, payload []byte) error {
	if f.failuresRemaining > 0 {
		f.failuresRemaining--
		return context.DeadlineExceeded
	}
	return f.captureAlertSender.Send(ctx, subject, payload)
}

func (f *failingAlertSender) Close() error {
	return nil
}

type stubAlertResolver struct {
	owners   []AlertRecipient
	team     []AlertRecipient
	managers map[string]AlertRecipient
}

type failingAlertRouterStateStore struct {
	snapshot  alertRouterStateSnapshot
	loadErr   error
	failSave  bool
	saveCalls int
}

func (s *failingAlertRouterStateStore) Load(_ context.Context) (alertRouterStateSnapshot, error) {
	if s.loadErr != nil {
		return alertRouterStateSnapshot{}, s.loadErr
	}
	return s.snapshot, nil
}

func (s *failingAlertRouterStateStore) Save(_ context.Context, snapshot alertRouterStateSnapshot) error {
	s.saveCalls++
	if s.failSave {
		return context.DeadlineExceeded
	}
	s.snapshot = snapshot
	return nil
}

func (s *failingAlertRouterStateStore) Close() error {
	return nil
}

func (s *stubAlertResolver) ResolveEntityOwner(_ context.Context, _ string, _ webhooks.Event) []AlertRecipient {
	return append([]AlertRecipient(nil), s.owners...)
}

func (s *stubAlertResolver) ResolveAccountTeam(_ context.Context, _ string, _ webhooks.Event) []AlertRecipient {
	return append([]AlertRecipient(nil), s.team...)
}

func (s *stubAlertResolver) ResolveManager(_ context.Context, personID string) (AlertRecipient, bool) {
	if s.managers == nil {
		return AlertRecipient{}, false
	}
	recipient, ok := s.managers[personID]
	return recipient, ok
}
