package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestProjectGRCMonitoredComputerLinksPostureEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-monitored-computer-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.monitored_computer",
		Attributes: map[string]string{
			"provider":                "grc",
			"computer_id":             "computer-1",
			"device_id":               "computer-1",
			"device_uuid":             "udid-1",
			"serial_number":           "serial-1",
			"integration_id":          "kandji",
			"owner_email":             "designer@example.com",
			"owner_id":                "person-1",
			"screenlock_status":       "OK",
			"disk_encryption_status":  "OK",
			"password_manager_status": "NEEDS_ATTENTION",
			"antivirus_status":        "OK",
			"compliance_status":       "needs_attention",
			"os":                      "MACOS",
			"os_version":              "15.5",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	endpointURN := "urn:cerebro:writer:grc_monitored_computer:computer-1"
	identityURN := "urn:cerebro:writer:identity:email:designer@example.com"
	integrationURN := "urn:cerebro:writer:source:grc:integration:kandji"
	evidenceURN := "urn:cerebro:writer:evidence:grc:monitored_computer:computer-1:password_manager"
	if entity := state.entities[endpointURN]; entity == nil || entity.EntityType != "grc.monitored_computer" {
		t.Fatalf("endpoint entity missing: %#v", entity)
	}
	if got := state.entities[endpointURN].Attributes["compliance_status"]; got != "needs_attention" {
		t.Fatalf("endpoint compliance_status = %q, want needs_attention", got)
	}
	if entity := state.entities[evidenceURN]; entity == nil || entity.Attributes["posture_check"] != "password_manager" || entity.Attributes["status"] != "NEEDS_ATTENTION" {
		t.Fatalf("password manager evidence missing or incomplete: %#v", entity)
	}
	assertProjectedLink(t, state, endpointURN, relationOwnedBy, identityURN)
	assertProjectedLink(t, state, endpointURN, relationBelongsTo, integrationURN)
	assertProjectedLink(t, state, endpointURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationObservedOn, endpointURN)
}

func TestProjectGRCMonitoredComputerUsesSerialFallback(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-monitored-computer-serial",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.monitored_computer",
		Attributes: map[string]string{
			"provider":                "grc",
			"serial_number":           "serial-only",
			"password_manager_status": "OK",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	endpointURN := "urn:cerebro:writer:grc_monitored_computer:serial-only"
	evidenceURN := "urn:cerebro:writer:evidence:grc:monitored_computer:serial-only:password_manager"
	if entity := state.entities[endpointURN]; entity == nil || entity.Attributes["source_product"] != "grc" {
		t.Fatalf("endpoint entity missing or source product unset: %#v", entity)
	}
	assertProjectedLink(t, state, endpointURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCMonitoredComputerUsesEndpointIDForPostureEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-monitored-computer-divergent-id",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.monitored_computer",
		Attributes: map[string]string{
			"provider":                "grc",
			"computer_id":             "computer-attr",
			"device_id":               "device-primary",
			"password_manager_status": "OK",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	endpointURN := "urn:cerebro:writer:grc_monitored_computer:device-primary"
	evidenceURN := "urn:cerebro:writer:evidence:grc:monitored_computer:device-primary:password_manager"
	divergentEvidenceURN := "urn:cerebro:writer:evidence:grc:monitored_computer:computer-attr:password_manager"
	assertProjectedLink(t, state, endpointURN, relationHasEvidence, evidenceURN)
	if entity := state.entities[divergentEvidenceURN]; entity != nil {
		t.Fatalf("divergent computer_id evidence was projected: %#v", entity)
	}
}

func TestProjectGRCMonitoredComputerOwnerIDRetractsStaleCanonicalOwnerLinks(t *testing.T) {
	endpointURN := "urn:cerebro:writer:grc_monitored_computer:computer-1"
	identityURN := "urn:cerebro:writer:identity:login:person-1"
	legacyIdentifierURN := "urn:cerebro:writer:identifier:login:person-1"
	staleLinks := []*ports.ProjectedLink{
		projectedLink("writer", "grc", endpointURN, identityURN, relationRepresentsIdentity, nil),
		projectedLink("writer", "grc", endpointURN, identityURN, relationOwnedBy, nil),
		projectedLink("writer", "grc", endpointURN, legacyIdentifierURN, relationHasIdentifier, nil),
	}
	state := &projectionRecorder{links: map[string]*ports.ProjectedLink{}}
	graph := &projectionRecorder{links: map[string]*ports.ProjectedLink{}}
	for _, link := range staleLinks {
		state.links[projectedLinkKey(link)] = cloneProjectedLink(link)
		graph.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	}
	service := New(state, graph)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-monitored-computer-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.monitored_computer",
		Attributes: map[string]string{
			"provider":    "grc",
			"computer_id": "computer-1",
			"owner_id":    "person-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.LinksDeleted != 3 {
		t.Fatalf("LinksDeleted = %d, want 3 stale owner-id links", result.LinksDeleted)
	}
	for _, recorder := range []*projectionRecorder{state, graph} {
		assertProjectedLinkMissing(t, recorder, endpointURN, relationRepresentsIdentity, identityURN)
		assertProjectedLinkMissing(t, recorder, endpointURN, relationOwnedBy, identityURN)
		assertProjectedLinkMissing(t, recorder, endpointURN, relationHasIdentifier, legacyIdentifierURN)
	}
	assertProjectedLink(t, state, endpointURN, relationHasIdentifier, "urn:cerebro:writer:endpoint_identifier:grc_owner_id:person-1")
}
