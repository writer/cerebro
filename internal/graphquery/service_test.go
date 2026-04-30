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

func TestGetEntityNeighborhoodRejectsMalformedRootURN(t *testing.T) {
	store := &stubStore{}
	service := New(store)
	cases := []string{
		"user:123",
		"urn:other:writer:user:alice",
		"urn:cerebro:writer:user",
		"urn:cerebro::user:alice",
		"urn:cerebro: writer:user:alice",
		"urn:cerebro:writer: user:alice",
		"urn:cerebro:writer:user: alice",
		"urn:cerebro:writer:okta_resource:policyrule: pol-1",
		"urn:cerebro:writer:runtime:writer-jira:ticket: ENG-123",
		"   ",
	}
	for _, raw := range cases {
		_, err := service.GetEntityNeighborhood(context.Background(), NeighborhoodRequest{RootURN: raw})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("GetEntityNeighborhood(%q) error = %v, want %v", raw, err, ErrInvalidRequest)
		}
	}
	if store.rootURN != "" {
		t.Fatalf("store should never see malformed urns; got %q", store.rootURN)
	}
}

func TestGetEntityNeighborhoodAcceptsColonDelimitedRootURN(t *testing.T) {
	store := &stubStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				EntityType: "okta_resource",
				Label:      "pol-1",
			},
		},
	}
	service := New(store)

	result, err := service.GetEntityNeighborhood(context.Background(), NeighborhoodRequest{
		RootURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
	})
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if result.Root == nil || result.Root.URN != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("Root = %#v, want colon-delimited okta_resource root", result.Root)
	}
	if store.rootURN != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("store root urn = %q, want colon-delimited urn", store.rootURN)
	}
}
