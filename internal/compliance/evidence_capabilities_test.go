package compliance

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

type evidenceCapabilityCatalogForTest struct {
	Sources []evidenceCapabilitySourceForTest `yaml:"sources"`
}

type evidenceCapabilitySourceForTest struct {
	SourceID   string                               `yaml:"source_id"`
	Dimensions []evidenceCapabilityDimensionForTest `yaml:"dimensions"`
}

type evidenceCapabilityDimensionForTest struct {
	DimensionID    string   `yaml:"dimension_id"`
	DimensionType  string   `yaml:"dimension_type"`
	SupportLevel   string   `yaml:"support_level"`
	Families       []string `yaml:"families"`
	EvidenceTypes  []string `yaml:"evidence_types"`
	ControlDomains []string `yaml:"control_domains"`
}

func TestOktaEvidenceCapabilitiesDeclareComplianceIdentityDepth(t *testing.T) {
	payload, err := os.ReadFile("evidence_capabilities.yaml")
	if err != nil {
		t.Fatalf("read evidence_capabilities.yaml: %v", err)
	}
	var catalog evidenceCapabilityCatalogForTest
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("unmarshal evidence_capabilities.yaml: %v", err)
	}
	dimensions := map[string]evidenceCapabilityDimensionForTest{}
	for _, source := range catalog.Sources {
		if source.SourceID != "okta" {
			continue
		}
		for _, dimension := range source.Dimensions {
			dimensions[dimension.DimensionID] = dimension
		}
	}
	if len(dimensions) == 0 {
		t.Fatal("okta evidence capabilities not found")
	}
	for _, want := range []struct {
		id             string
		dimensionType  string
		support        string
		evidenceType   string
		controlDomain  string
		requiredFamily string
	}{
		{id: "user_lifecycle", dimensionType: "lifecycle_state", support: "supported", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "suspended"},
		{id: "mfa_posture", dimensionType: "app_entitlement", support: "supported", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "mfa"},
		{id: "dormant_users", dimensionType: "lifecycle_state", support: "supported", evidenceType: "access_review", controlDomain: "identity_access", requiredFamily: "stale_login"},
		{id: "deprovisioning", dimensionType: "lifecycle_state", support: "partial", evidenceType: "remediation_state", controlDomain: "remediation", requiredFamily: "terminated_account"},
		{id: "group_memberships", dimensionType: "relationship", support: "supported", evidenceType: "access_review", controlDomain: "identity_access", requiredFamily: "group_membership"},
		{id: "admin_membership", dimensionType: "relationship", support: "partial", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "privileged_role"},
		{id: "app_access", dimensionType: "app_entitlement", support: "partial", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "app_assignment"},
		{id: "external_accounts", dimensionType: "entity_family", support: "partial", evidenceType: "access_review", controlDomain: "identity_access", requiredFamily: "external_user"},
	} {
		dimension, ok := dimensions[want.id]
		if !ok {
			t.Fatalf("okta capability dimension %q not found; got %#v", want.id, dimensions)
		}
		if dimension.DimensionType != want.dimensionType || dimension.SupportLevel != want.support {
			t.Fatalf("dimension %s type/support = %s/%s, want %s/%s", want.id, dimension.DimensionType, dimension.SupportLevel, want.dimensionType, want.support)
		}
		if !stringSliceContains(dimension.EvidenceTypes, want.evidenceType) {
			t.Fatalf("dimension %s evidence types = %#v, want %q", want.id, dimension.EvidenceTypes, want.evidenceType)
		}
		if !stringSliceContains(dimension.ControlDomains, want.controlDomain) {
			t.Fatalf("dimension %s control domains = %#v, want %q", want.id, dimension.ControlDomains, want.controlDomain)
		}
		if !stringSliceContains(dimension.Families, want.requiredFamily) {
			t.Fatalf("dimension %s families = %#v, want %q", want.id, dimension.Families, want.requiredFamily)
		}
	}
}
