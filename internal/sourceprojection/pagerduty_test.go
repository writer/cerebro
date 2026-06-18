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
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"pagerduty.user", map[string]string{"user_id": "PU1", "name": "Alice"}, "pagerduty.user"},
		{"pagerduty.team", map[string]string{"team_id": "PT1", "name": "Platform"}, "pagerduty.team"},
		{"pagerduty.service", map[string]string{"service_id": "PS1", "status": "active", "escalation_policy_id": "PE1"}, "pagerduty.service"},
		{"pagerduty.schedule", map[string]string{"schedule_id": "PSC1", "name": "Primary"}, "pagerduty.schedule"},
		{"pagerduty.escalation_policy", map[string]string{"escalation_policy_id": "PE1", "name": "Checkout EP"}, "pagerduty.escalation_policy"},
		{"pagerduty.integration", map[string]string{"integration_id": "PI1", "service_id": "PS1", "vendor_id": "PV1"}, "pagerduty.integration"},
		{"pagerduty.vendor", map[string]string{"vendor_id": "PV1", "name": "Datadog"}, "pagerduty.vendor"},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if _, ok := registered[tc.kind]; !ok {
				t.Fatalf("declared PagerDuty kind %q is not routed in the projection registry", tc.kind)
			}
			entities, _, err := BuiltinRegistry().Project(pagerDutyEvent(tc.kind, tc.attrs))
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to projector producing %q; entities=%#v", tc.kind, tc.entityType, entities)
			}
		})
	}
}
