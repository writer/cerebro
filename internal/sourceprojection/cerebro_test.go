package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectCerebroAPIAccessLinksPrincipalAndService(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "cerebro-api-access-audit-request-1",
		TenantId:   "writer",
		SourceId:   "cerebro",
		Kind:       "cerebro.api_access",
		OccurredAt: timestamppb.New(time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"actor_user":          "ci@example.com",
			"auth_mode":           "api_key",
			"client_id":           "ci-client",
			"credential_id":       "cred-api",
			"effective_tenant_id": "writer",
			"method":              "GET",
			"operation_family":    "source",
			"operation_type":      "read",
			"outcome_result":      "allowed",
			"principal":           "ci@example.com",
			"required_scopes":     "cerebro.cosmo.security.read",
			"request_id":          "audit-request-1",
			"route":               "GET /sources",
			"scopes":              "cerebro.cosmo.security.read",
			"sensitive_action":    "false",
			"source_ip":           "198.51.100.7",
			"status_code":         "200",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	serviceURN := "urn:cerebro:writer:service:cerebro"
	accessURN := "urn:cerebro:writer:cerebro_api_access:audit-request-1"
	principalURN := "urn:cerebro:writer:cerebro_principal:ci@example.com"
	identityURN := "urn:cerebro:writer:identity:email:ci@example.com"
	routeURN := "urn:cerebro:writer:cerebro_route:get:/sources"
	operationFamilyURN := "urn:cerebro:writer:cerebro_operation_family:source"
	credentialURN := "urn:cerebro:writer:cerebro_credential:cred-api" // #nosec G101 -- test graph URN, not credential material.
	scopeURN := "urn:cerebro:writer:cerebro_scope:cerebro.cosmo.security.read"
	if entity := state.entities[serviceURN]; entity == nil || entity.EntityType != "service" {
		t.Fatalf("service entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[accessURN]; entity == nil || entity.EntityType != "cerebro.api_access" || entity.Attributes["route"] != "GET /sources" {
		t.Fatalf("access entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, serviceURN, relationHasEvidence, accessURN)
	assertProjectedLink(t, state, accessURN, relationObservedOn, serviceURN)
	assertProjectedLink(t, state, principalURN, relationHasEvidence, accessURN)
	assertProjectedLink(t, state, principalURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, serviceURN, relationSupports, routeURN)
	assertProjectedLink(t, state, routeURN, relationBelongsTo, operationFamilyURN)
	assertProjectedLink(t, state, principalURN, relationCanPerform, routeURN)
	assertProjectedLink(t, state, principalURN, relationCanPerform, operationFamilyURN)
	assertProjectedLink(t, state, principalURN, relationAssignedTo, credentialURN)
	assertProjectedLink(t, state, credentialURN, relationCanPerform, routeURN)
	assertProjectedLink(t, state, principalURN, relationCanPerform, scopeURN)
	assertProjectedLink(t, state, credentialURN, relationCanPerform, scopeURN)
	assertProjectedLink(t, state, scopeURN, relationSupports, routeURN)
}

func TestProjectCerebroAPIAccessDeniedDoesNotGrantRoute(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "cerebro-api-access-denied",
		TenantId:   "writer",
		SourceId:   "cerebro",
		Kind:       "cerebro.api_access",
		OccurredAt: timestamppb.New(time.Date(2026, 6, 9, 12, 1, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"auth_mode":        "api_key",
			"credential_id":    "cred-limited",
			"method":           "POST",
			"missing_scopes":   "cerebro.findings.write",
			"operation_family": "finding",
			"operation_type":   "write",
			"outcome_result":   "denied",
			"principal":        "ci@example.com",
			"required_scopes":  "cerebro.findings.write",
			"request_id":       "denied-request-1",
			"route":            "POST /findings/{findingID}/notes",
			"sensitive_action": "true",
			"status_code":      "403",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	principalURN := "urn:cerebro:writer:cerebro_principal:ci@example.com"
	routeURN := "urn:cerebro:writer:cerebro_route:post:/findings/{findingid}/notes"
	assertProjectedLink(t, state, principalURN, relationActedOn, routeURN)
	assertProjectedLinkMissing(t, state, principalURN, relationCanPerform, routeURN)
}
