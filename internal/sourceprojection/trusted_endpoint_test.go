package sourceprojection

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTrustedEndpointSecurityFindingProjectsEndpointAndFinding(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id:         "evt-1",
		TenantId:   "writer",
		SourceId:   "trusted_endpoint",
		Kind:       "trusted_endpoint.security_finding",
		SchemaRef:  "trusted_endpoint/security_finding/v1",
		OccurredAt: timestamppb.New(time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"agent_id":      "agent-1",
			"device_id":     "dev-1",
			"hardware_key":  "hw-1",
			"hostname":      "laptop-1",
			"serial_number": "serial-1",
			"finding_id":    "finding-1",
			"severity":      "high",
		},
	}
	entities, links, err := trustedEndpointProjections(event)
	if err != nil {
		t.Fatalf("trustedEndpointProjections: %v", err)
	}
	if !hasEntityType(entities, "trusted_endpoint.device") {
		t.Fatalf("missing trusted_endpoint.device entity: %#v", entities)
	}
	if !hasEntityType(entities, "finding") {
		t.Fatalf("missing finding entity: %#v", entities)
	}
	if !hasRelation(links, relationObservedOn) {
		t.Fatalf("missing observed_on link: %#v", links)
	}
}

func hasEntityType(entities []*ports.ProjectedEntity, entityType string) bool {
	for _, entity := range entities {
		if entity.EntityType == entityType {
			return true
		}
	}
	return false
}

func hasRelation(links []*ports.ProjectedLink, relation string) bool {
	for _, link := range links {
		if link.Relation == relation {
			return true
		}
	}
	return false
}
