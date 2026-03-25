package builders

import (
	"context"

	"github.com/writer/cerebro/internal/warehouse"
)

// PostgresSource adapts a Postgres-backed QueryWarehouse to the DataSource interface.
type PostgresSource struct {
	client warehouse.QueryWarehouse
}

// NewPostgresSource creates a new Postgres data source.
func NewPostgresSource(client warehouse.QueryWarehouse) *PostgresSource {
	return &PostgresSource{client: client}
}

// Query executes a query against Postgres and returns the result
// as a DataQueryResult suitable for graph building.
func (s *PostgresSource) Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error) {
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
