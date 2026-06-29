package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func pagerDutyEvent(kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "pagerduty-" + kind,
		TenantId:   "writer",
		SourceId:   "pagerduty",
		Kind:       kind,
		Attributes: attrs,
	}
}

func TestProjectPagerDutyServiceEscalationDependency(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := pagerDutyEvent("pagerduty.service", map[string]string{
		"service_id":             "PS1",
		"name":                   "Checkout API",
		"status":                 "active",
		"escalation_policy_id":   "PE1",
		"escalation_policy_name": "Checkout EP",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	serviceURN := "urn:cerebro:writer:pagerduty_service:PS1"
	escalationURN := "urn:cerebro:writer:pagerduty_escalation_policy:PE1"

	svc := state.entities[serviceURN]
	if svc == nil || svc.EntityType != "pagerduty.service" {
		t.Fatalf("pagerduty.service entity missing or wrong: %#v", svc)
	}
	for key, want := range map[string]string{
		"has_escalation_policy": "true",
		"active":                "true",
	} {
		if got := svc.Attributes[key]; got != want {
			t.Fatalf("service posture attribute %q = %q, want %q", key, got, want)
		}
	}

	ep := state.entities[escalationURN]
	if ep == nil || ep.EntityType != "pagerduty.escalation_policy" {
		t.Fatalf("pagerduty.escalation_policy context entity missing or wrong: %#v", ep)
	}
	assertProjectedLink(t, state, serviceURN, relationDependsOn, escalationURN)
	assertProjectedLink(t, state, escalationURN, relationSupports, serviceURN)
}

func TestProjectPagerDutyServiceWithoutEscalationPolicy(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := pagerDutyEvent("pagerduty.service", map[string]string{
		"service_id": "PS2",
		"name":       "Orphan Service",
		"status":     "active",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	serviceURN := "urn:cerebro:writer:pagerduty_service:PS2"
	svc := state.entities[serviceURN]
	if svc == nil || svc.EntityType != "pagerduty.service" {
		t.Fatalf("pagerduty.service entity missing or wrong: %#v", svc)
	}
	if got := svc.Attributes["has_escalation_policy"]; got != "false" {
		t.Fatalf("has_escalation_policy = %q, want false", got)
	}
	if _, ok := state.entities["urn:cerebro:writer:pagerduty_escalation_policy:PE1"]; ok {
		t.Fatal("unexpected escalation policy entity for service without escalation policy")
	}
}

func TestProjectPagerDutyEscalationPolicyTeamsAndTargets(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := &cerebrov1.EventEnvelope{
		Id:       "pagerduty-escalation-policy",
		TenantId: "writer",
		SourceId: "pagerduty",
		Kind:     "pagerduty.escalation_policy",
		Attributes: map[string]string{
			"escalation_policy_id": "PE1",
			"name":                 "Checkout EP",
		},
		Payload: mustJSON(t, map[string]any{
			"id":    "PE1",
			"name":  "Checkout EP",
			"teams": []map[string]any{{"id": "PT1", "summary": "Platform"}},
			"escalation_rules": []map[string]any{{
				"targets": []map[string]any{
					{"id": "PSC1", "type": "schedule_reference", "summary": "Primary"},
					{"id": "PU1", "type": "user_reference", "summary": "Alice"},
					{"id": "PU2", "type": "user_reference_extra", "summary": "Imprecise"},
				},
			}},
		}),
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	escalationURN := "urn:cerebro:writer:pagerduty_escalation_policy:PE1"
	teamURN := "urn:cerebro:writer:pagerduty_team:PT1"
	scheduleURN := "urn:cerebro:writer:pagerduty_schedule:PSC1"
	userURN := "urn:cerebro:writer:pagerduty_user:PU1"
	assertProjectedLink(t, state, escalationURN, relationBelongsTo, teamURN)
	assertProjectedLink(t, state, teamURN, relationContains, escalationURN)
	assertProjectedLink(t, state, escalationURN, relationDependsOn, scheduleURN)
	assertProjectedLink(t, state, escalationURN, relationDependsOn, userURN)
	assertProjectedLinkMissing(t, state, escalationURN, relationDependsOn, "urn:cerebro:writer:pagerduty_user:PU2")
}

func TestProjectPagerDutyUserEmailIdentifier(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := pagerDutyEvent("pagerduty.user", map[string]string{
		"user_id": "PU1",
		"name":    "Alice",
		"email":   "alice@writer.com",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:pagerduty_user:PU1"
	emailURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	if entity := state.entities[userURN]; entity == nil || entity.EntityType != "pagerduty.user" {
		t.Fatalf("pagerduty.user entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, userURN, relationHasIdentifier, emailURN)
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
}

func TestProjectPagerDutyIntegrationServiceVendorDependency(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := pagerDutyEvent("pagerduty.integration", map[string]string{
		"integration_id": "PI1",
		"name":           "Datadog",
		"service_id":     "PS1",
		"service_name":   "Checkout API",
		"vendor_id":      "PV1",
		"vendor_name":    "Datadog",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	integrationURN := "urn:cerebro:writer:pagerduty_integration:PI1"
	serviceURN := "urn:cerebro:writer:pagerduty_service:PS1"
	vendorURN := "urn:cerebro:writer:pagerduty_vendor:PV1"

	if entity := state.entities[integrationURN]; entity == nil || entity.EntityType != "pagerduty.integration" {
		t.Fatalf("pagerduty.integration entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[serviceURN]; entity == nil || entity.EntityType != "pagerduty.service" {
		t.Fatalf("pagerduty.service context entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[vendorURN]; entity == nil || entity.EntityType != "pagerduty.vendor" {
		t.Fatalf("pagerduty.vendor context entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, integrationURN, relationBelongsTo, serviceURN)
	assertProjectedLink(t, state, serviceURN, relationContains, integrationURN)
	assertProjectedLink(t, state, integrationURN, relationDependsOn, vendorURN)
}

func TestRegistryRoutesPagerDutyDeclaredKinds(t *testing.T) {
	cases := []struct {
		event      *cerebrov1.EventEnvelope
		entityType string
	}{
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-user", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.user", Attributes: map[string]string{"user_id": "PU1", "name": "Alice"}}, entityType: "pagerduty.user"},
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-team", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.team", Attributes: map[string]string{"team_id": "PT1", "name": "Platform"}}, entityType: "pagerduty.team"},
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-service", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.service", Attributes: map[string]string{"service_id": "PS1", "status": "active", "escalation_policy_id": "PE1"}}, entityType: "pagerduty.service"},
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-schedule", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.schedule", Attributes: map[string]string{"schedule_id": "PSC1", "name": "Primary"}}, entityType: "pagerduty.schedule"},
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-escalation-policy", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.escalation_policy", Attributes: map[string]string{"escalation_policy_id": "PE1", "name": "Checkout EP"}}, entityType: "pagerduty.escalation_policy"},
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-integration", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.integration", Attributes: map[string]string{"integration_id": "PI1", "service_id": "PS1", "vendor_id": "PV1"}}, entityType: "pagerduty.integration"},
		{event: &cerebrov1.EventEnvelope{Id: "pagerduty-vendor", TenantId: "writer", SourceId: "pagerduty", Kind: "pagerduty.vendor", Attributes: map[string]string{"vendor_id": "PV1", "name": "Datadog"}}, entityType: "pagerduty.vendor"},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.event.Kind, func(t *testing.T) {
			if _, ok := registered[tc.event.Kind]; !ok {
				t.Fatalf("declared PagerDuty kind %q is not routed in the projection registry", tc.event.Kind)
			}
			entities, _, err := BuiltinRegistry().Project(tc.event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.event.Kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to projector producing %q; entities=%#v", tc.event.Kind, tc.entityType, entities)
			}
		})
	}
}
