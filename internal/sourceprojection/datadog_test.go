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

func TestDatadogRuntimeKindsAreExplicitDepthEvidence(t *testing.T) {
	cases := []struct {
		event      *cerebrov1.EventEnvelope
		entityType string
	}{
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-user-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.users",
				Attributes: map[string]string{
					"user_id": "user-1",
					"email":   "alice@example.test",
					"name":    "Alice Example",
				},
			},
			entityType: "datadog.users",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-role-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.roles",
				Attributes: map[string]string{
					"role_id": "role-1",
					"name":    "Datadog Admin",
				},
			},
			entityType: "datadog.roles",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-team-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.teams",
				Attributes: map[string]string{
					"team_id": "platform",
					"name":    "Platform",
				},
			},
			entityType: "datadog.teams",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-monitor-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.monitors",
				Attributes: map[string]string{
					"monitor_id": "monitor-1",
					"name":       "Checkout latency",
					"type":       "query alert",
					"tags":       "service:checkout,team:platform",
				},
			},
			entityType: "datadog.monitors",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-slo-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.slos",
				Attributes: map[string]string{
					"slo_id": "slo-1",
					"name":   "Checkout availability",
					"type":   "metric",
					"tags":   "service:checkout,team:platform",
				},
			},
			entityType: "datadog.slos",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-dashboard-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.dashboards",
				Attributes: map[string]string{
					"dashboard_id": "dashboard-1",
					"title":        "Checkout operations",
					"tags":         "service:checkout,team:platform",
				},
			},
			entityType: "datadog.dashboards",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-incident-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.incidents",
				Attributes: map[string]string{
					"incident_id": "incident-1",
					"title":       "Checkout outage",
					"state":       "active",
					"team_id":     "platform",
					"service":     "checkout",
				},
			},
			entityType: "datadog.incidents",
		},
		{
			event: &cerebrov1.EventEnvelope{
				Id:       "datadog-audit-event",
				TenantId: "writer",
				SourceId: "datadog",
				Kind:     "datadog.audit_events",
				Attributes: map[string]string{
					"audit_id":    "audit-1",
					"event_type":  "role.updated",
					"actor_id":    "user-1",
					"resource_id": "role-1",
				},
			},
			entityType: "datadog.audit_events",
		},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.event.Kind, func(t *testing.T) {
			if _, ok := registered[tc.event.Kind]; !ok {
				t.Fatalf("declared Datadog kind %q is not routed in the projection registry", tc.event.Kind)
			}
			entities, _, err := BuiltinRegistry().Project(tc.event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.event.Kind, err)
			}
			if !hasProjectedEntityType(entities, tc.entityType) {
				t.Fatalf("kind %q did not project %q; entities=%#v", tc.event.Kind, tc.entityType, entities)
			}
		})
	}
}
