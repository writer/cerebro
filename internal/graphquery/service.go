package graphquery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
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
	catalog       ports.EntityCatalogStore
	exposure      ports.ExposureCoverageStore
	personAccess  ports.PersonAccessPathStore
	effective     ports.EffectiveAccessPathStore
	attackPaths   ports.CloudAttackPathStore
	crownJewels   ports.CrownJewelPathStore
}

// NeighborhoodRequest scopes one bounded root-centered graph query.
type NeighborhoodRequest struct {
	RootURN                string
	TenantID               string
	ApplicationWorkspaceID string
	Limit                  uint32
}

// New constructs a bounded graph neighborhood service.
func New(store ports.GraphNeighborhoodStore) *Service {
	return NewWithCapabilities(
		store,
		graphCatalogCapability(store),
		graphExposureCapability(store),
		graphPersonAccessCapability(store),
		graphEffectiveAccessCapability(store),
		graphAttackPathCapability(store),
		graphCrownJewelPathCapability(store),
	)
}

func NewWithCapabilities(neighborhoods ports.GraphNeighborhoodStore, catalog ports.EntityCatalogStore, exposure ports.ExposureCoverageStore, extraCapabilities ...any) *Service {
	var personAccessStores []ports.PersonAccessPathStore
	var attackPathStore ports.CloudAttackPathStore
	var crownJewelPathStore ports.CrownJewelPathStore
	var effectiveAccessStore ports.EffectiveAccessPathStore
	for _, capability := range extraCapabilities {
		if typed, ok := capability.(ports.PersonAccessPathStore); ok {
			personAccessStores = append(personAccessStores, typed)
		}
		if typed, ok := capability.(ports.CloudAttackPathStore); ok {
			attackPathStore = typed
		}
		if typed, ok := capability.(ports.CrownJewelPathStore); ok {
			crownJewelPathStore = typed
		}
		if typed, ok := capability.(ports.EffectiveAccessPathStore); ok {
			effectiveAccessStore = typed
		}
	}
	personAccessStore := firstPersonAccessCapability(personAccessStores)
	if personAccessStore == nil {
		personAccessStore = graphPersonAccessCapability(neighborhoods, catalog, exposure)
	}
	if attackPathStore == nil {
		attackPathStore = graphAttackPathCapability(neighborhoods, catalog, exposure, personAccessStore)
	}
	if crownJewelPathStore == nil {
		crownJewelPathStore = graphCrownJewelPathCapability(neighborhoods, catalog, exposure, personAccessStore, attackPathStore)
	}
	if effectiveAccessStore == nil {
		effectiveAccessStore = graphEffectiveAccessCapability(neighborhoods, catalog, exposure, personAccessStore, attackPathStore, crownJewelPathStore)
	}
	return &Service{
		neighborhoods: neighborhoods,
		catalog:       catalog,
		exposure:      exposure,
		personAccess:  personAccessStore,
		effective:     effectiveAccessStore,
		attackPaths:   attackPathStore,
		crownJewels:   crownJewelPathStore,
	}
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

func graphPersonAccessCapability(stores ...any) ports.PersonAccessPathStore {
	for _, store := range stores {
		if personAccess, ok := store.(ports.PersonAccessPathStore); ok {
			return personAccess
		}
	}
	return nil
}

func graphAttackPathCapability(stores ...any) ports.CloudAttackPathStore {
	for _, store := range stores {
		if attackPaths, ok := store.(ports.CloudAttackPathStore); ok {
			return attackPaths
		}
	}
	return nil
}

func graphCrownJewelPathCapability(stores ...any) ports.CrownJewelPathStore {
	for _, store := range stores {
		if crownJewelPaths, ok := store.(ports.CrownJewelPathStore); ok {
			return crownJewelPaths
		}
	}
	return nil
}

func graphEffectiveAccessCapability(stores ...any) ports.EffectiveAccessPathStore {
	for _, store := range stores {
		if effectiveAccess, ok := store.(ports.EffectiveAccessPathStore); ok {
			return effectiveAccess
		}
	}
	return nil
}

func firstPersonAccessCapability(stores []ports.PersonAccessPathStore) ports.PersonAccessPathStore {
	for _, store := range stores {
		if store != nil {
			return store
		}
	}
	return nil
}

// GetEntityNeighborhood loads one bounded root-centered graph neighborhood.
func (s *Service) GetEntityNeighborhood(ctx context.Context, request NeighborhoodRequest) (*ports.EntityNeighborhood, error) {
	if s == nil {
		return nil, ErrRuntimeUnavailable
	}
	if strings.TrimSpace(request.RootURN) == "" {
		return nil, fmt.Errorf("%w: root urn is required", ErrInvalidRequest)
	}
	rootURN := request.RootURN
	if err := validateCerebroURN(rootURN); err != nil {
		return nil, err
	}
	resourceTenantID := cerebrourn.TenantID(rootURN)
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID != "" && tenantID != resourceTenantID {
		return nil, ports.ErrGraphEntityNotFound
	}
	if tenantID == "" {
		tenantID = resourceTenantID
	}
	if workspaceID := strings.TrimSpace(request.ApplicationWorkspaceID); workspaceID != "" {
		return s.QualifyWorkspaceResources(ctx, WorkspaceResourceRequest{
			TenantID:               tenantID,
			ResourceTenantID:       resourceTenantID,
			ApplicationWorkspaceID: workspaceID,
			URNs:                   []string{rootURN},
		})
	}
	if s.neighborhoods == nil {
		return nil, ErrRuntimeUnavailable
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
