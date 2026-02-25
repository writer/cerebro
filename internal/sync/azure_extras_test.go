package sync

import "testing"

func TestSerializeAKSAgentPools(t *testing.T) {
	count := int32(3)
	pools := []azureManagedClusterAgentPool{
		{
			Name:                strPtr("nodepool1"),
			Count:               &count,
			VMSize:              strPtr("Standard_D4s_v5"),
			Mode:                strPtr("System"),
			OSType:              strPtr("Linux"),
			OrchestratorVersion: strPtr("1.30.1"),
		},
	}

	serialized := serializeAKSAgentPools(pools)
	if len(serialized) != 1 {
		t.Fatalf("expected 1 serialized pool, got %d", len(serialized))
	}

	pool := serialized[0]
	if pool["name"] != "nodepool1" {
		t.Fatalf("unexpected pool name: %#v", pool["name"])
	}
	if pool["count"] != int32(3) {
		t.Fatalf("unexpected pool count: %#v", pool["count"])
	}
	if pool["vm_size"] != "Standard_D4s_v5" {
		t.Fatalf("unexpected VM size: %#v", pool["vm_size"])
	}
}

func TestSerializeAKSAgentPoolsEmpty(t *testing.T) {
	if got := serializeAKSAgentPools(nil); got != nil {
		t.Fatalf("expected nil for empty pools, got %#v", got)
	}
}

func strPtr(value string) *string {
	return &value
}
