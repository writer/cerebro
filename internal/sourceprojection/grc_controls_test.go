package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

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

func TestProjectGRCControlTestLinksOwnerIntegrationAndCategory(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":     "vanta",
			"test_id":      "test-1",
			"name":         "AWS Config enabled",
			"owner_id":     "user-1",
			"integrations": "aws,gcp",
			"category":     "Infrastructure",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	testURN := "urn:cerebro:writer:evidence:vanta:control_test:test-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	awsSourceURN := "urn:cerebro:writer:source:vanta:integration:aws"
	gcpSourceURN := "urn:cerebro:writer:source:vanta:integration:gcp"
	categoryURN := "urn:cerebro:writer:asset_tag:grc_category:infrastructure"
	assertProjectedLink(t, state, testURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, testURN, relationBelongsTo, awsSourceURN)
	assertProjectedLink(t, state, testURN, relationBelongsTo, gcpSourceURN)
	assertProjectedLink(t, state, testURN, relationTaggedAs, categoryURN)
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
	if state.entities[firstControlURN] != nil {
		t.Fatalf("first control entity = %#v, want no placeholder without external ID", state.entities[firstControlURN])
	}
	if got := state.entities[secondControlURN].Attributes["control_external_id"]; got != "CC7.1" {
		t.Fatalf("second control_external_id = %q, want CC7.1", got)
	}
}

func TestProjectGRCControlLinksOwnerAndDomains(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control",
		Attributes: map[string]string{
			"provider":    "vanta",
			"control_id":  "control-1",
			"name":        "Access Reviews",
			"owner_id":    "user-1",
			"domains":     "COMPLIANCE, SECURITY & PRIVACY GOVERNANCE",
			"description": "Access is reviewed periodically",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	controlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	complianceURN := "urn:cerebro:writer:asset_tag:grc_domain:compliance"
	securityURN := "urn:cerebro:writer:asset_tag:grc_domain:security_privacy_governance"
	assertProjectedLink(t, state, controlURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, controlURN, relationTaggedAs, complianceURN)
	assertProjectedLink(t, state, controlURN, relationTaggedAs, securityURN)
}

func TestProjectGRCControlTestDoesNotRegressControlLabelWhenExternalIDMissingLater(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	first := &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":           "vanta",
			"test_id":            "test-1",
			"control_references": "control-1=CC6.2",
			"status":             "FAIL",
		},
	}
	if _, err := service.Project(context.Background(), first); err != nil {
		t.Fatalf("Project(first) error = %v", err)
	}
	second := &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":           "vanta",
			"test_id":            "test-2",
			"control_references": "control-1=",
			"status":             "FAIL",
		},
	}
	if _, err := service.Project(context.Background(), second); err != nil {
		t.Fatalf("Project(second) error = %v", err)
	}

	controlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	if got := state.entities[controlURN].Label; got != "CC6.2" {
		t.Fatalf("control label = %q, want CC6.2", got)
	}
}
