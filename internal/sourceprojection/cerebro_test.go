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
			"actor_user":     "ci@example.com",
			"auth_mode":      "api_key",
			"method":         "GET",
			"outcome_result": "allowed",
			"principal":      "ci@example.com",
			"request_id":     "audit-request-1",
			"route":          "GET /sources",
			"source_ip":      "198.51.100.7",
			"status_code":    "200",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	serviceURN := "urn:cerebro:writer:service:cerebro"
	accessURN := "urn:cerebro:writer:cerebro_api_access:audit-request-1"
	principalURN := "urn:cerebro:writer:cerebro_principal:ci@example.com"
	identityURN := "urn:cerebro:writer:identity:email:ci@example.com"
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
}
