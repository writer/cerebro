package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func datadogEvent(kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "datadog-" + kind,
		TenantId:   "writer",
		SourceId:   "datadog",
		Kind:       kind,
		SchemaRef:  "datadog/" + kind + "/v1",
		Attributes: attrs,
	}
}

func datadogProjectionState(entities []*ports.ProjectedEntity, links []*ports.ProjectedLink) *projectionRecorder {
	state := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{},
		links:    map[string]*ports.ProjectedLink{},
	}
	for _, entity := range entities {
		if entity != nil {
			state.entities[entity.URN] = entity
		}
	}
	for _, link := range links {
		if link != nil {
			state.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = link
		}
	}
	return state
}

func TestDatadogUserProjectsEmailIdentifierAndActiveState(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(datadogEvent("datadog.users", map[string]string{
		"user_id":  "user-1",
		"email":    "alice@example.test",
		"name":     "Alice Example",
		"disabled": "false",
	}))
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	state := datadogProjectionState(entities, links)
	userURN := "urn:cerebro:writer:datadog_users:user-1"
	if entity := state.entities[userURN]; entity == nil || entity.Attributes["active"] != "true" {
		t.Fatalf("datadog user active projection missing: %#v", entity)
	}
	assertProjectedLink(t, state, userURN, relationHasIdentifier, "urn:cerebro:writer:identifier:email:alice@example.test")
}

func TestDatadogUserURNEncodingMatchesCrossReferences(t *testing.T) {
	userURN := "urn:cerebro:writer:datadog_users:user%3A1"

	entities, links, err := BuiltinRegistry().Project(datadogEvent("datadog.users", map[string]string{
		"user_id": "user:1",
		"email":   "alice@example.test",
	}))
	if err != nil {
		t.Fatalf("Project(datadog.users) error = %v", err)
	}
	if entity := datadogProjectionState(entities, links).entities[userURN]; entity == nil {
		t.Fatalf("datadog user URN = missing, want %q", userURN)
	}

	entities, links, err = BuiltinRegistry().Project(datadogEvent("datadog.incidents", map[string]string{
		"incident_id":       "inc:1",
		"title":             "Checkout outage",
		"commander_user_id": "user:1",
	}))
	if err != nil {
		t.Fatalf("Project(datadog.incidents) error = %v", err)
	}
	assertProjectedLink(t, datadogProjectionState(entities, links), userURN, relationActedOn, "urn:cerebro:writer:datadog_incidents:inc%3A1")

	entities, links, err = BuiltinRegistry().Project(datadogEvent("datadog.audit_events", map[string]string{
		"audit_id": "audit:1",
		"actor_id": "user:1",
	}))
	if err != nil {
		t.Fatalf("Project(datadog.audit_events) error = %v", err)
	}
	assertProjectedLink(t, datadogProjectionState(entities, links), userURN, relationActedOn, "urn:cerebro:writer:datadog_audit_events:audit%3A1")
}

func TestDatadogTaggedResourcesProjectTeamAndServiceEdges(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(datadogEvent("datadog.monitors", map[string]string{
		"monitor_id": "mon-1",
		"name":       "Payments latency",
		"type":       "query alert",
		"service":    "payments,checkout",
		"tags":       "service:payments,team:platform,team:payments,env:prod",
	}))
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	state := datadogProjectionState(entities, links)
	monitorURN := "urn:cerebro:writer:datadog_monitors:mon-1"
	assertProjectedLink(t, state, monitorURN, relationBelongsTo, "urn:cerebro:writer:datadog_service:payments")
	assertProjectedLink(t, state, monitorURN, relationBelongsTo, "urn:cerebro:writer:datadog_service:checkout")
	assertProjectedLink(t, state, monitorURN, relationBelongsTo, "urn:cerebro:writer:datadog_teams:platform")
	assertProjectedLink(t, state, monitorURN, relationBelongsTo, "urn:cerebro:writer:datadog_teams:payments")
	assertProjectedLink(t, state, "urn:cerebro:writer:datadog_service:payments", relationContains, monitorURN)
}

func TestDatadogIncidentProjectsCommanderTeamAndService(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(datadogEvent("datadog.incidents", map[string]string{
		"incident_id":       "inc-1",
		"title":             "Checkout outage",
		"state":             "active",
		"commander_user_id": "user-1",
		"commander_email":   "alice@example.test",
		"team_id":           "platform",
		"service":           "checkout",
	}))
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	state := datadogProjectionState(entities, links)
	incidentURN := "urn:cerebro:writer:datadog_incidents:inc-1"
	userURN := "urn:cerebro:writer:datadog_users:user-1"
	assertProjectedLink(t, state, userURN, relationActedOn, incidentURN)
	assertProjectedLink(t, state, userURN, relationHasIdentifier, "urn:cerebro:writer:identifier:email:alice@example.test")
	assertProjectedLink(t, state, incidentURN, relationBelongsTo, "urn:cerebro:writer:datadog_teams:platform")
	assertProjectedLink(t, state, incidentURN, relationBelongsTo, "urn:cerebro:writer:datadog_service:checkout")
}

func TestDatadogAuditProjectsActorAndResource(t *testing.T) {
	entities, links, err := BuiltinRegistry().Project(datadogEvent("datadog.audit_events", map[string]string{
		"audit_id":      "audit-1",
		"event_type":    "role.updated",
		"actor_id":      "user-1",
		"actor_email":   "alice@example.test",
		"resource_id":   "role:1",
		"resource_name": "Security Admin",
		"resource_type": "role",
	}))
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	state := datadogProjectionState(entities, links)
	auditURN := "urn:cerebro:writer:datadog_audit_events:audit-1"
	userURN := "urn:cerebro:writer:datadog_users:user-1"
	resourceURN := "urn:cerebro:writer:datadog_resource:role%3Arole%3A1"
	assertProjectedLink(t, state, userURN, relationActedOn, auditURN)
	assertProjectedLink(t, state, userURN, relationHasIdentifier, "urn:cerebro:writer:identifier:email:alice@example.test")
	assertProjectedLink(t, state, auditURN, relationObservedOn, resourceURN)
	assertProjectedLink(t, state, userURN, relationActedOn, resourceURN)
}
