package graph

import (
	"slices"
	"testing"
)

func TestCommonPropertiesUseCompactLiveStorageAndPreserveHeuristics(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "database:customer-records",
		Kind: NodeKindDatabase,
		Name: "Customer Records",
		Properties: map[string]any{
			"internet_exposed":    true,
			"public_ip":           "198.51.100.24",
			"data_classification": "restricted",
			"contains_pii":        true,
			"common_only":         "kept",
		},
	})

	node, ok := g.GetNode("database:customer-records")
	if !ok {
		t.Fatal("expected database node")
	}
	for _, key := range []string{"internet_exposed", "public_ip", "data_classification", "contains_pii"} {
		if _, ok := node.Properties[key]; ok {
			t.Fatalf("expected compact live map without %s, got %#v", key, node.Properties)
		}
	}
	if got := node.Properties["common_only"]; got != "kept" {
		t.Fatalf("common_only = %#v, want kept", got)
	}

	if got, ok := node.PropertyValue("internet_exposed"); !ok || got != true {
		t.Fatalf("PropertyValue(internet_exposed) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("public_ip"); !ok || got != "198.51.100.24" {
		t.Fatalf("PropertyValue(public_ip) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("data_classification"); !ok || got != "restricted" {
		t.Fatalf("PropertyValue(data_classification) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("contains_pii"); !ok || got != true {
		t.Fatalf("PropertyValue(contains_pii) = %#v, %v", got, ok)
	}

	propertyMap := node.PropertyMap()
	if got := propertyMap["internet_exposed"]; got != true {
		t.Fatalf("PropertyMap(internet_exposed) = %#v, want true", got)
	}
	if got := propertyMap["public_ip"]; got != "198.51.100.24" {
		t.Fatalf("PropertyMap(public_ip) = %#v, want 198.51.100.24", got)
	}
	if got := propertyMap["data_classification"]; got != "restricted" {
		t.Fatalf("PropertyMap(data_classification) = %#v, want restricted", got)
	}
	if got := propertyMap["contains_pii"]; got != true {
		t.Fatalf("PropertyMap(contains_pii) = %#v, want true", got)
	}
	if got := propertyMap["common_only"]; got != "kept" {
		t.Fatalf("PropertyMap(common_only) = %#v, want kept", got)
	}

	if !g.isInternetFacing(node) {
		t.Fatal("expected internet-exposed property to keep node internet-facing after promotion")
	}
	if !g.isCrownJewel(node) {
		t.Fatal("expected sensitive data properties to keep node classified as crown jewel after promotion")
	}

	sensitive := detectSensitiveData(node)
	if sensitive == nil {
		t.Fatal("expected sensitive data detection to survive common property promotion")
	}
	if sensitive.DataClassification != "restricted" {
		t.Fatalf("DataClassification = %q, want restricted", sensitive.DataClassification)
	}
	if !slices.Equal(sensitive.DataTypes, []string{"PII"}) {
		t.Fatalf("DataTypes = %#v, want []string{\"PII\"}", sensitive.DataTypes)
	}
}

func TestSetNodePropertyStoresCommonPropertiesOutsideLiveMap(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "user:alice",
		Kind: NodeKindUser,
		Name: "alice",
		Properties: map[string]any{
			"mfa_enabled": false,
			"kept":        "value",
		},
	})

	if !g.SetNodeProperty("user:alice", "mfa_enabled", true) {
		t.Fatal("expected SetNodeProperty(mfa_enabled) to succeed")
	}
	node, ok := g.GetNode("user:alice")
	if !ok {
		t.Fatal("expected updated user node after mfa change")
	}
	if got := node.PreviousProperties["mfa_enabled"]; got != false {
		t.Fatalf("PreviousProperties[mfa_enabled] = %#v, want false", got)
	}

	if !g.SetNodeProperty("user:alice", "service_id", "payments") {
		t.Fatal("expected SetNodeProperty(service_id) to succeed")
	}
	if !g.SetNodeProperty("user:alice", "identity_type", "ManagedIdentity") {
		t.Fatal("expected SetNodeProperty(identity_type) to succeed")
	}

	node, ok = g.GetNode("user:alice")
	if !ok {
		t.Fatal("expected updated user node")
	}
	for _, key := range []string{"mfa_enabled", "service_id", "identity_type"} {
		if _, ok := node.Properties[key]; ok {
			t.Fatalf("expected compact live map without %s, got %#v", key, node.Properties)
		}
	}
	if got := node.Properties["kept"]; got != "value" {
		t.Fatalf("kept = %#v, want value", got)
	}
	if got := node.PreviousProperties["identity_type"]; got != nil {
		t.Fatalf("PreviousProperties[identity_type] = %#v, want nil first-write marker", got)
	}

	if got, ok := node.PropertyValue("mfa_enabled"); !ok || got != true {
		t.Fatalf("PropertyValue(mfa_enabled) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("service_id"); !ok || got != "payments" {
		t.Fatalf("PropertyValue(service_id) = %#v, %v", got, ok)
	}
	if got, ok := node.PropertyValue("identity_type"); !ok || got != "ManagedIdentity" {
		t.Fatalf("PropertyValue(identity_type) = %#v, %v", got, ok)
	}

	contextIDs := eventCorrelationContextIDs(g, node)
	if !slices.Equal(contextIDs, []string{"service:payments"}) {
		t.Fatalf("eventCorrelationContextIDs() = %#v, want []string{\"service:payments\"}", contextIDs)
	}

	ref := eventReferenceFromNode(node)
	if ref.ServiceID != "payments" {
		t.Fatalf("eventReferenceFromNode().ServiceID = %q, want payments", ref.ServiceID)
	}
}
