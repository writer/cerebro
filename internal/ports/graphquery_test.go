package ports

import (
	"context"
	"testing"
)

type cloudAttackPathStoreStub struct{}

func (*cloudAttackPathStoreStub) Ping(context.Context) error { return nil }
func (*cloudAttackPathStoreStub) ListCloudAttackPaths(context.Context, CloudAttackPathRequest) (*CloudAttackPathResult, error) {
	return &CloudAttackPathResult{}, nil
}

func TestNewGraphReadCapabilitiesIncludesTypedCloudAttackPaths(t *testing.T) {
	store := &cloudAttackPathStoreStub{}
	capabilities := NewGraphReadCapabilities(store)
	if capabilities.CloudAttackPaths != store {
		t.Fatalf("CloudAttackPaths = %#v, want typed store", capabilities.CloudAttackPaths)
	}
	if capabilities.RawCypher != nil {
		t.Fatalf("RawCypher = %#v, want no compatibility capability", capabilities.RawCypher)
	}

	var typedNil *cloudAttackPathStoreStub
	if got := NewGraphReadCapabilities(typedNil).CloudAttackPaths; got != nil {
		t.Fatalf("CloudAttackPaths typed nil = %#v, want nil", got)
	}
}
