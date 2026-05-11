package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectGRCVendorWithOwner(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vendor-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":               "vanta",
			"vendor_id":              "vendor-1",
			"name":                   "Acme SaaS",
			"security_owner_user_id": "user-1",
			"inherent_risk_level":    "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	if entity := state.entities[vendorURN]; entity == nil || entity.EntityType != "vendor" {
		t.Fatalf("vendor entity missing: %#v", entity)
	}
	if got := state.entities[vendorURN].Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("vendor inherent_risk_level = %q, want HIGH", got)
	}
	if entity := state.entities[ownerURN]; entity == nil || entity.EntityType != "user" {
		t.Fatalf("owner user entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, vendorURN, relationOwnedBy, ownerURN)
}

func TestProjectGRCControlTestSupportsControlReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":             "vanta",
			"test_id":              "test-1",
			"control_ids":          "control-1,control-2",
			"control_external_ids": "CC6.2,CC7.1",
			"status":               "FAIL",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	testURN := "urn:cerebro:writer:evidence:vanta:control_test:test-1"
	firstControlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:vanta:control:control-2"
	assertProjectedLink(t, state, testURN, relationSupports, firstControlURN)
	assertProjectedLink(t, state, testURN, relationSupports, secondControlURN)
	if got := state.entities[firstControlURN].Attributes["control_external_id"]; got != "CC6.2" {
		t.Fatalf("first control_external_id = %q, want CC6.2", got)
	}
	if got := state.entities[firstControlURN].Label; got != "CC6.2" {
		t.Fatalf("first control label = %q, want CC6.2", got)
	}
}

func TestProjectGRCControlTestKeepsPairedControlReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":             "vanta",
			"test_id":              "test-1",
			"control_ids":          "control-1,control-2",
			"control_external_ids": "CC7.1",
			"control_references":   "control-1=;control-2=CC7.1",
			"status":               "FAIL",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	firstControlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:vanta:control:control-2"
	if got := state.entities[firstControlURN].Attributes["control_external_id"]; got != "" {
		t.Fatalf("first control_external_id = %q, want empty", got)
	}
	if got := state.entities[secondControlURN].Attributes["control_external_id"]; got != "CC7.1" {
		t.Fatalf("second control_external_id = %q, want CC7.1", got)
	}
}

func TestProjectGRCRiskScenarioOwnerDoesNotCreatePersonIdentityBridge(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-risk-risk-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.risk_scenario",
		Attributes: map[string]string{
			"provider":    "vanta",
			"risk_id":     "risk-1",
			"description": "AI vendor risk",
			"owner":       "alice@writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	riskURN := "urn:cerebro:writer:claim:vanta:risk_scenario:risk-1"
	contactURN := "urn:cerebro:writer:contact:vanta:owner:alice@writer.com"
	personURN := "urn:cerebro:writer:person:vanta:owner:alice@writer.com"
	assertProjectedLink(t, state, riskURN, relationAssignedTo, contactURN)
	if _, ok := state.entities[personURN]; ok {
		t.Fatalf("risk owner projected as GRC person: %#v", state.entities[personURN])
	}
	assertProjectedLinkMissing(t, state, contactURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:email:alice@writer.com")
}

func TestProjectGRCPersonIdentifier(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-person-person-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.person",
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	if entity := state.entities[personURN]; entity == nil || entity.EntityType != "person" {
		t.Fatalf("person entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, personURN, relationHasIdentifier, identifierURN)
}

func TestProjectGRCPersonStampsIdentifierLinksWithObservationTime(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	historicalEmploymentDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "grc-person-person-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.person",
		OccurredAt: timestamppb.New(historicalEmploymentDate),
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	link, ok := state.links[personURN+"|"+relationRepresentsIdentity+"|"+identityURN]
	if !ok {
		t.Fatalf("represents_identity link missing for %s -> %s: %#v", personURN, identityURN, state.links)
	}
	stamped, err := time.Parse(time.RFC3339, link.Attributes["at"])
	if err != nil {
		t.Fatalf("represents_identity at = %q is not RFC3339: %v", link.Attributes["at"], err)
	}
	if stamped.Equal(historicalEmploymentDate) {
		t.Fatalf("represents_identity at = %q, want projection observation time", link.Attributes["at"])
	}
	if stamped.Before(before.Add(-time.Second)) || stamped.After(after.Add(time.Second)) {
		t.Fatalf("represents_identity at = %v not within projection window [%v, %v]", stamped, before, after)
	}
}

func TestProjectGRCVulnerabilityUsesCanonicalVulnerability(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":          "vanta",
			"vulnerability_id":  "vuln-1",
			"name":              "CVE-2026-4242",
			"package":           "pkg:golang/example/module@1.2.3",
			"package_purl":      "pkg:golang/example/module@1.2.3",
			"severity":          "HIGH",
			"remediate_by_date": "2026-05-30T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	if entity := state.entities[vulnerabilityURN]; entity == nil || entity.EntityType != "vulnerability" {
		t.Fatalf("vulnerability entity missing: %#v", entity)
	}
	if got := state.entities[vulnerabilityURN].Attributes["remediate_by_date"]; got != "2026-05-30T00:00:00Z" {
		t.Fatalf("remediate_by_date = %q, want deadline", got)
	}
}
