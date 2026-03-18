package graph

import "testing"

func TestNodeIsBusinessEntity(t *testing.T) {
	businessKinds := []NodeKind{
		NodeKindCustomer,
		NodeKindContact,
		NodeKindCompany,
		NodeKindVendor,
		NodeKindDeal,
		NodeKindOpportunity,
		NodeKindSubscription,
		NodeKindInvoice,
		NodeKindTicket,
		NodeKindLead,
	}

	for _, kind := range businessKinds {
		n := &Node{ID: "n", Kind: kind}
		if !n.IsBusinessEntity() {
			t.Fatalf("expected kind %q to be a business entity", kind)
		}
	}

	infra := &Node{ID: "u", Kind: NodeKindUser}
	if infra.IsBusinessEntity() {
		t.Fatalf("expected kind %q to not be a business entity", infra.Kind)
	}
}

func TestEdgeIsCrossSystem(t *testing.T) {
	cross := &Edge{Properties: map[string]any{"cross_system": true}}
	if !cross.IsCrossSystem() {
		t.Fatal("expected edge to be cross-system")
	}

	nonCross := &Edge{Properties: map[string]any{"cross_system": false}}
	if nonCross.IsCrossSystem() {
		t.Fatal("expected edge to not be cross-system")
	}

	defaultEdge := &Edge{Properties: map[string]any{}}
	if defaultEdge.IsCrossSystem() {
		t.Fatal("expected edge without cross_system flag to not be cross-system")
	}
}

func TestBusinessLineageEdgeKinds(t *testing.T) {
	if EdgeKindOriginatedFrom != "originated_from" {
		t.Fatalf("unexpected originated_from edge kind value: %s", EdgeKindOriginatedFrom)
	}
	if EdgeKindProvisionedAs != "provisioned_as" {
		t.Fatalf("unexpected provisioned_as edge kind value: %s", EdgeKindProvisionedAs)
	}
}
