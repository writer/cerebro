package graphquery

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type stubStore struct {
	rootURN      string
	limit        int
	neighborhood *ports.EntityNeighborhood
}

func (s *stubStore) Ping(context.Context) error { return nil }

func (s *stubStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	s.rootURN = rootURN
	s.limit = limit
	return s.neighborhood, nil
}

func TestGetEntityNeighborhoodNormalizesLimit(t *testing.T) {
	store := &stubStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:github_user:alice", EntityType: "github.user", Label: "Alice"},
		},
	}
	service := New(store)

	result, err := service.GetEntityNeighborhood(context.Background(), NeighborhoodRequest{
		RootURN: "urn:cerebro:writer:github_user:alice",
		Limit:   99,
	})
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if result.Root == nil || result.Root.URN != "urn:cerebro:writer:github_user:alice" {
		t.Fatalf("Root = %#v, want alice root", result.Root)
	}
	if store.rootURN != "urn:cerebro:writer:github_user:alice" {
		t.Fatalf("store root urn = %q, want alice urn", store.rootURN)
	}
	if store.limit != maxNeighborhoodLimit {
		t.Fatalf("store limit = %d, want %d", store.limit, maxNeighborhoodLimit)
	}
}

func TestGetEntityNeighborhoodRequiresAvailableStore(t *testing.T) {
	service := New(nil)
	if _, err := service.GetEntityNeighborhood(context.Background(), NeighborhoodRequest{RootURN: "urn:cerebro:writer:github_user:alice"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("GetEntityNeighborhood() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}
