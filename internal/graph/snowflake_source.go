package graph

import (
	"context"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// SnowflakeSource adapts the Snowflake client to the DataSource interface
type SnowflakeSource struct {
	client *snowflake.Client
}

// NewSnowflakeSource creates a new Snowflake data source
func NewSnowflakeSource(client *snowflake.Client) *SnowflakeSource {
	return &SnowflakeSource{client: client}
}

// Query executes a query against Snowflake
func (s *SnowflakeSource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	result, err := s.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	return &QueryResult{
		Columns: result.Columns,
		Rows:    result.Rows,
		Count:   result.Count,
	}, nil
}
