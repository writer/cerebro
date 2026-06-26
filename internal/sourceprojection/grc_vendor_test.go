package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
			"website_url":            "https://app.writer.com",
			"security_owner_user_id": "user-1",
			"inherent_risk_level":    "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	aliasURN := "urn:cerebro:writer:vendor_alias:acme-saas"
	if entity := state.entities[vendorURN]; entity == nil || entity.EntityType != "vendor" {
		t.Fatalf("vendor entity missing: %#v", entity)
	}
	if got := state.entities[vendorURN].Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("vendor inherent_risk_level = %q, want HIGH", got)
	}
	if entity := state.entities[ownerURN]; entity == nil || entity.EntityType != "user" {
		t.Fatalf("owner user entity missing: %#v", entity)
	}
	if entity := state.entities[hostURN]; entity == nil || entity.EntityType != "internet.host" {
		t.Fatalf("internet host entity missing: %#v", entity)
	}
	if entity := state.entities[aliasURN]; entity == nil || entity.EntityType != "vendor.alias" {
		t.Fatalf("vendor alias entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, vendorURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, vendorURN, relationHasIdentifier, hostURN)
	assertProjectedLink(t, state, vendorURN, relationHasIdentifier, aliasURN)
}

func TestProjectGRCVendorLinksAccountManagerEmail(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vendor-contact",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":              "vanta",
			"vendor_id":             "vendor-1",
			"name":                  "Acme SaaS",
			"account_manager_email": "manager@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	identityURN := "urn:cerebro:writer:identity:email:manager@example.com"
	assertProjectedLink(t, state, vendorURN, relationAssociatedWith, identityURN)
	link := state.links[vendorURN+"|"+relationAssociatedWith+"|"+identityURN]
	if got := link.Attributes["contact_type"]; got != "account_manager" {
		t.Fatalf("contact_type = %q, want account_manager", got)
	}
}

func TestProjectGRCDiscoveredVendorLinksAliasesCategoryAndReviewer(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-discovered-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.discovered_vendor",
		Attributes: map[string]string{
			"provider":             "grc",
			"discovered_vendor_id": "discovered-vendor-1",
			"name":                 "Acme, Inc.",
			"normalized_name":      "Acme",
			"category":             "AI",
			"ignored_reason":       "duplicate",
			"ignored_by_user_id":   "user-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	discoveryURN := "urn:cerebro:writer:vendor_discovery:grc:discovered-vendor-1"
	aliasURN := "urn:cerebro:writer:vendor_alias:acme-inc"
	normalizedAliasURN := "urn:cerebro:writer:vendor_alias:acme"
	categoryURN := "urn:cerebro:writer:asset_tag:vendor_category:ai"
	userURN := "urn:cerebro:writer:user:grc:user-1"
	if entity := state.entities[discoveryURN]; entity == nil || entity.EntityType != "vendor.discovery" {
		t.Fatalf("discovered vendor entity missing: %#v", entity)
	}
	if got := state.entities[discoveryURN].Attributes["status"]; got != "ignored" {
		t.Fatalf("discovered vendor status = %q, want ignored", got)
	}
	assertProjectedLink(t, state, discoveryURN, relationHasIdentifier, aliasURN)
	assertProjectedLink(t, state, discoveryURN, relationHasIdentifier, normalizedAliasURN)
	assertProjectedLink(t, state, discoveryURN, relationTaggedAs, categoryURN)
	assertProjectedLink(t, state, userURN, relationActedOn, discoveryURN)
}

func TestProjectGRCGroupAndVendorRiskAttribute(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "grc-group-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.group",
			Attributes: map[string]string{
				"provider":   "grc",
				"group_id":   "group-1",
				"group_name": "Security",
			},
		},
		{
			Id:       "grc-vendor-risk-attribute-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.vendor_risk_attribute",
			Attributes: map[string]string{
				"provider":                 "grc",
				"vendor_risk_attribute_id": "risk-attr-1",
				"name":                     "Sensitive data",
				"vendor_categories":        "AI,Infrastructure",
				"risk_level":               "HIGH",
				"enabled":                  "true",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	groupURN := "urn:cerebro:writer:grc_group:grc:group-1"
	attributeURN := "urn:cerebro:writer:vendor_risk_attribute:grc:risk-attr-1"
	categoryURN := "urn:cerebro:writer:asset_tag:vendor_category:ai"
	riskURN := "urn:cerebro:writer:asset_tag:vendor_risk_level:high"
	if entity := state.entities[groupURN]; entity == nil || entity.EntityType != "group" {
		t.Fatalf("group entity missing: %#v", entity)
	}
	if entity := state.entities[attributeURN]; entity == nil || entity.EntityType != "vendor.risk_attribute" {
		t.Fatalf("vendor risk attribute entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, attributeURN, relationTaggedAs, categoryURN)
	assertProjectedLink(t, state, attributeURN, relationTaggedAs, riskURN)
}
