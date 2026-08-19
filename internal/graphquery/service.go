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
	neighborhoods ports.GraphNeighborhoodStore
	rawCypher     ports.RawCypherQueryStore
	catalog       ports.EntityCatalogStore
	exposure      ports.ExposureCoverageStore
}

// NeighborhoodRequest scopes one bounded root-centered graph query.
type NeighborhoodRequest struct {
	RootURN string
	Limit   uint32
}

// New constructs a bounded graph neighborhood service.
func New(store ports.GraphNeighborhoodStore) *Service {
	return NewWithCapabilities(
		store,
		graphRawCypherCapability(store),
		graphCatalogCapability(store),
		graphExposureCapability(store),
	)
}

func NewWithCapabilities(neighborhoods ports.GraphNeighborhoodStore, rawCypher ports.RawCypherQueryStore, catalog ports.EntityCatalogStore, exposure ports.ExposureCoverageStore) *Service {
	return &Service{
		neighborhoods: neighborhoods,
		rawCypher:     rawCypher,
		catalog:       catalog,
		exposure:      exposure,
	}
}

func graphRawCypherCapability(store ports.GraphNeighborhoodStore) ports.RawCypherQueryStore {
	if rawCypher, ok := store.(ports.RawCypherQueryStore); ok {
		return rawCypher
	}
	return nil
}

func graphCatalogCapability(store ports.GraphNeighborhoodStore) ports.EntityCatalogStore {
	if catalog, ok := store.(ports.EntityCatalogStore); ok {
		return catalog
	}
	return nil
}

func graphExposureCapability(store ports.GraphNeighborhoodStore) ports.ExposureCoverageStore {
	if exposure, ok := store.(ports.ExposureCoverageStore); ok {
		return exposure
	}
	return nil
}

// GetEntityNeighborhood loads one bounded root-centered graph neighborhood.
func (s *Service) GetEntityNeighborhood(ctx context.Context, request NeighborhoodRequest) (*ports.EntityNeighborhood, error) {
	if s == nil || s.neighborhoods == nil {
		return nil, ErrRuntimeUnavailable
	}
	if strings.TrimSpace(request.RootURN) == "" {
		return nil, fmt.Errorf("%w: root urn is required", ErrInvalidRequest)
	}
	rootURN := request.RootURN
	if err := validateCerebroURN(rootURN); err != nil {
		return nil, err
	}
	return s.neighborhoods.GetEntityNeighborhood(ctx, rootURN, normalizeNeighborhoodLimit(request.Limit))
}

// validateCerebroURN rejects malformed root URN inputs so the API can surface
// 400 InvalidArgument instead of 404 NotFound for caller mistakes while still
// allowing colon-delimited IDs such as embedded AWS ARNs.
func validateCerebroURN(urn string) error {
	parts := strings.Split(urn, ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return fmt.Errorf("%w: root urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
	}
	if parts[len(parts)-1] == "" {
		return fmt.Errorf("%w: root urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
	}
	if len(parts) > 3 && parts[3] == "runtime" && (len(parts) < 7 || parts[5] == "") {
		return fmt.Errorf("%w: root urn must be of the form urn:cerebro:<tenant>:runtime:<runtime_id>:<entity_type>:<id>", ErrInvalidRequest)
	}
	for i, part := range parts[2:] {
		if strings.TrimSpace(part) != part || (i < 3 && part == "") {
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
