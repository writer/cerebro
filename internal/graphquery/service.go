package graphquery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultNeighborhoodLimit = 10
	maxNeighborhoodLimit     = 50
)

// ErrRuntimeUnavailable indicates that the graph query boundary is unavailable.
var ErrRuntimeUnavailable = errors.New("graph query runtime is unavailable")

// ErrInvalidArgument indicates that the graph query request is invalid.
var ErrInvalidArgument = errors.New("graph query invalid argument")

// Service exposes the first bounded graph neighborhood query.
type Service struct {
	store ports.GraphQueryStore
}

// NeighborhoodRequest scopes one bounded root-centered graph query.
type NeighborhoodRequest struct {
	RootURN string
	Limit   uint32
}

// New constructs a bounded graph neighborhood service.
func New(store ports.GraphQueryStore) *Service {
	return &Service{store: store}
}

// GetEntityNeighborhood loads one bounded root-centered graph neighborhood.
func (s *Service) GetEntityNeighborhood(ctx context.Context, request NeighborhoodRequest) (*ports.EntityNeighborhood, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	rootURN := strings.TrimSpace(request.RootURN)
	if rootURN == "" {
		return nil, fmt.Errorf("%w: root urn is required", ErrInvalidArgument)
	}
	return s.store.GetEntityNeighborhood(ctx, rootURN, normalizeNeighborhoodLimit(request.Limit))
}

func normalizeNeighborhoodLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultNeighborhoodLimit
	case limit > maxNeighborhoodLimit:
		return maxNeighborhoodLimit
	default:
		return int(limit)
	}
}
