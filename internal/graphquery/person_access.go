package graphquery

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultPersonAccessPathLimit = 25
	maxPersonAccessPathLimit     = 100
	defaultPersonAccessPathDepth = 3
	maxPersonAccessPathDepth     = 4
)

type PersonAccessPathRequest struct {
	TenantID    string
	PersonURN   string
	PersonQuery string
	Limit       uint32
	Depth       uint32
}

type PersonAccessPathResult struct {
	TenantID string                  `json:"tenant_id"`
	Filters  PersonAccessPathFilters `json:"filters"`
	Counts   PersonAccessPathCounts  `json:"counts"`
	Paths    []PersonAccessPath      `json:"paths"`
}

type PersonAccessPathFilters struct {
	PersonURN   string `json:"person_urn,omitempty"`
	PersonQuery string `json:"person_query,omitempty"`
	Limit       int    `json:"limit"`
	Depth       int    `json:"depth"`
}

type PersonAccessPathCounts struct {
	Paths int `json:"paths"`
}

type PersonAccessPath struct {
	Person        GraphEntityRef `json:"person"`
	Identity      GraphEntityRef `json:"identity"`
	Principal     GraphEntityRef `json:"principal"`
	AccessTarget  GraphEntityRef `json:"access_target"`
	RelationChain []string       `json:"relation_chain"`
}

func (s *Service) GetPersonAccessPaths(ctx context.Context, request PersonAccessPathRequest) (*PersonAccessPathResult, error) {
	if s == nil || s.personAccess == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	personURN := strings.TrimSpace(request.PersonURN)
	personQuery := strings.ToLower(strings.TrimSpace(request.PersonQuery))
	if personURN == "" && personQuery == "" {
		return nil, fmt.Errorf("%w: person_urn or person_query is required", ErrInvalidRequest)
	}
	if personURN != "" {
		if err := validateCerebroURN(personURN); err != nil {
			return nil, err
		}
		if urnTenant := tenantFromCerebroURN(personURN); urnTenant != "" && urnTenant != tenantID {
			return nil, fmt.Errorf("%w: person_urn tenant must match tenant_id", ErrInvalidRequest)
		}
	}
	limit := normalizePersonAccessPathLimit(request.Limit)
	depth := normalizePersonAccessPathDepth(request.Depth)
	typed, err := s.personAccess.ListPersonAccessPaths(ctx, ports.PersonAccessPathRequest{
		TenantID:    tenantID,
		PersonURN:   personURN,
		PersonQuery: personQuery,
		Limit:       limit,
		Depth:       depth,
	})
	if err != nil {
		return nil, err
	}
	if typed == nil || typed.TenantID != tenantID || len(typed.Paths) > limit {
		return nil, fmt.Errorf("%w: typed person access returned an invalid tenant or bound", ErrRuntimeUnavailable)
	}
	paths := make([]PersonAccessPath, 0, len(typed.Paths))
	for _, path := range typed.Paths {
		converted := PersonAccessPath{
			Person:        catalogGraphRef(path.Person),
			Identity:      catalogGraphRef(path.Identity),
			Principal:     catalogGraphRef(path.Principal),
			AccessTarget:  catalogGraphRef(path.AccessTarget),
			RelationChain: append([]string(nil), path.RelationChain...),
		}
		if converted.Person.URN == "" || converted.Identity.URN == "" || converted.Principal.URN == "" || converted.AccessTarget.URN == "" || len(converted.RelationChain) == 0 {
			return nil, fmt.Errorf("%w: typed person access returned an invalid path", ErrRuntimeUnavailable)
		}
		paths = append(paths, converted)
	}
	return &PersonAccessPathResult{
		TenantID: tenantID,
		Filters: PersonAccessPathFilters{
			PersonURN:   personURN,
			PersonQuery: personQuery,
			Limit:       limit,
			Depth:       depth,
		},
		Counts: PersonAccessPathCounts{Paths: len(paths)},
		Paths:  paths,
	}, nil
}

func normalizePersonAccessPathLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultPersonAccessPathLimit
	case limit > maxPersonAccessPathLimit:
		return maxPersonAccessPathLimit
	default:
		return int(limit)
	}
}

func normalizePersonAccessPathDepth(depth uint32) int {
	switch {
	case depth == 0:
		return defaultPersonAccessPathDepth
	case depth > maxPersonAccessPathDepth:
		return maxPersonAccessPathDepth
	default:
		return int(depth)
	}
}

func tenantFromCerebroURN(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) >= 3 && parts[0] == "urn" && parts[1] == "cerebro" {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func catalogGraphRef(entity ports.CatalogEntity) GraphEntityRef {
	return GraphEntityRef{
		URN:        entity.URN,
		EntityType: entity.EntityType,
		Label:      entity.Label,
	}
}
