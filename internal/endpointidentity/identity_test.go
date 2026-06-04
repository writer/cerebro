package endpointidentity

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestMemoryStoreResolvesDeviceByHardwareUUID(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	aliases := AliasesFromDevice("writer", "dev-1", "hw-1", "serial-1", "host-1", now)
	if err := store.UpsertEndpointIdentityAliases(context.Background(), aliases); err != nil {
		t.Fatalf("UpsertEndpointIdentityAliases: %v", err)
	}
	resolution, err := store.ResolveEndpointIdentity(context.Background(), ports.EndpointIdentityResolveRequest{
		TenantID: "writer",
		Aliases: []ports.EndpointIdentityAlias{{
			TenantID:   "writer",
			AliasType:  AliasHardwareUUID,
			AliasValue: "HW-1",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEndpointIdentity: %v", err)
	}
	if resolution.CanonicalDeviceID != "dev-1" {
		t.Fatalf("CanonicalDeviceID = %q, want dev-1", resolution.CanonicalDeviceID)
	}
	if resolution.Ambiguous {
		t.Fatal("resolution is ambiguous")
	}
}

func TestMemoryStoreMarksHostnameCollisionAmbiguous(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	_ = store.UpsertEndpointIdentityAliases(context.Background(), AliasesFromDevice("writer", "dev-1", "hw-1", "serial-1", "shared-host", now))
	_ = store.UpsertEndpointIdentityAliases(context.Background(), AliasesFromDevice("writer", "dev-2", "hw-2", "serial-2", "shared-host", now.Add(time.Minute)))
	resolution, err := store.ResolveEndpointIdentity(context.Background(), ports.EndpointIdentityResolveRequest{
		TenantID: "writer",
		Aliases: []ports.EndpointIdentityAlias{{
			TenantID:   "writer",
			AliasType:  AliasHostname,
			AliasValue: "shared-host",
		}},
	})
	if err != nil {
		t.Fatalf("ResolveEndpointIdentity: %v", err)
	}
	if !resolution.Ambiguous {
		t.Fatal("hostname collision should be ambiguous")
	}
	if len(resolution.CandidateDeviceIDs) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(resolution.CandidateDeviceIDs))
	}
}
