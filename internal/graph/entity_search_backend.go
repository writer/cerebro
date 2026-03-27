package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type EntitySearchBackendType string

const (
	EntitySearchBackendGraph      EntitySearchBackendType = "graph"
	EntitySearchBackendOpenSearch EntitySearchBackendType = "opensearch"
)

const (
	currentEntitySubgraphMaxDepth = 4
	currentEntitySubgraphMaxNodes = 512
)

type EntitySearchBackend interface {
	Backend() EntitySearchBackendType
	Search(ctx context.Context, tenantID string, opts EntitySearchOptions) (EntitySearchCollection, error)
	Suggest(ctx context.Context, tenantID string, opts EntitySuggestOptions) (EntitySuggestCollection, error)
}

type EntitySearchBootstrapPendingError struct {
	Backend EntitySearchBackendType
	Reason  string
	Cause   error
}

func ParseEntitySearchBackend(value string) EntitySearchBackendType {
	switch EntitySearchBackendType(strings.ToLower(strings.TrimSpace(value))) {
	case "", EntitySearchBackendGraph:
		return EntitySearchBackendGraph
	case EntitySearchBackendOpenSearch:
		return EntitySearchBackendOpenSearch
	default:
		return EntitySearchBackendType(strings.ToLower(strings.TrimSpace(value)))
	}
}

func (b EntitySearchBackendType) Valid() bool {
	return b == EntitySearchBackendGraph || b == EntitySearchBackendOpenSearch
}

func (e *EntitySearchBootstrapPendingError) Error() string {
	if e == nil {
		return "entity search backend bootstrap pending"
	}
	reason := strings.TrimSpace(e.Reason)
	switch {
	case reason != "" && e.Cause != nil:
		return fmt.Sprintf("entity search backend %q bootstrap pending: %s: %v", e.Backend, reason, e.Cause)
	case reason != "":
		return fmt.Sprintf("entity search backend %q bootstrap pending: %s", e.Backend, reason)
	case e.Cause != nil:
		return fmt.Sprintf("entity search backend %q bootstrap pending: %v", e.Backend, e.Cause)
	default:
		return fmt.Sprintf("entity search backend %q bootstrap pending", e.Backend)
	}
}

func (e *EntitySearchBootstrapPendingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func IsEntitySearchBootstrapPending(err error) bool {
	var target *EntitySearchBootstrapPendingError
	return errors.As(err, &target)
}

func GetCurrentEntityRecordFromStore(ctx context.Context, store GraphStore, id string) (EntityRecord, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return EntityRecord{}, false, nil
	}
	if err := graphStoreContextErr(ctx); err != nil {
		return EntityRecord{}, false, err
	}
	if store == nil {
		return EntityRecord{}, false, ErrStoreUnavailable
	}

	subgraph, err := store.ExtractSubgraph(ctx, id, ExtractSubgraphOptions{
		MaxDepth:  currentEntitySubgraphMaxDepth,
		MaxNodes:  currentEntitySubgraphMaxNodes,
		Direction: ExtractSubgraphDirectionBoth,
	})
	if err != nil {
		return EntityRecord{}, false, err
	}
	if subgraph == nil {
		return EntityRecord{}, false, nil
	}

	now := temporalNowUTC()
	record, ok := GetEntityRecord(subgraph, id, now, now)
	return record, ok, nil
}
