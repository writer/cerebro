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

var (
	// ErrRuntimeUnavailable indicates that the graph query boundary is unavailable.
	ErrRuntimeUnavailable = errors.New("graph query runtime is unavailable")

	// ErrInvalidRequest indicates that a graph query request failed validation.
	ErrInvalidRequest = errors.New("invalid graph query request")
)

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
		return nil, fmt.Errorf("%w: root urn is required", ErrInvalidRequest)
	}
	if err := validateCerebroURN(rootURN); err != nil {
		return nil, err
	}
	return s.store.GetEntityNeighborhood(ctx, rootURN, normalizeNeighborhoodLimit(request.Limit))
}

// validateCerebroURN rejects malformed root URN inputs so the API can surface
// 400 InvalidArgument instead of 404 NotFound for caller mistakes.
func validateCerebroURN(urn string) error {
	parts := strings.Split(urn, ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return fmt.Errorf("%w: root urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
	}
	for i := 2; i < 5; i++ {
		part := strings.TrimSpace(parts[i])
		if part == "" || part != parts[i] {
			return fmt.Errorf("%w: root urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
		}
	}
	return nil
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
