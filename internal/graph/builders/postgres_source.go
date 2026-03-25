package builders

import (
	"context"

	"github.com/writer/cerebro/internal/warehouse"
)

type availableTableClient interface {
	ListAvailableTables(ctx context.Context) ([]string, error)
}

// WarehouseSource adapts a warehouse-backed QueryWarehouse to the DataSource interface.
type WarehouseSource struct {
	client  warehouse.QueryWarehouse
	catalog availableTableClient
}

// PostgresSource is retained as a compatibility alias for older call sites.
type PostgresSource = WarehouseSource

// NewWarehouseSource creates a new warehouse data source.
func NewWarehouseSource(client warehouse.QueryWarehouse) *WarehouseSource {
	source := &WarehouseSource{client: client}
	if catalog, ok := client.(availableTableClient); ok {
		source.catalog = catalog
	}
	return source
}

// NewPostgresSource creates a new warehouse data source.
func NewPostgresSource(client warehouse.QueryWarehouse) *WarehouseSource {
	return NewWarehouseSource(client)
}

func (s *WarehouseSource) ListAvailableTables(ctx context.Context) ([]string, error) {
	if s == nil || s.catalog == nil {
		return nil, nil
	}
	return s.catalog.ListAvailableTables(ctx)
}

// Query executes a query against the warehouse and returns the result
// as a DataQueryResult suitable for graph building.
func (s *WarehouseSource) Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error) {
	result, err := s.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	return &DataQueryResult{
		Columns: result.Columns,
		Rows:    result.Rows,
		Count:   result.Count,
	}, nil
}
