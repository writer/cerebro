package graph

import (
	"context"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/snowflake"
)

// SnowflakeSource adapts the Snowflake client to the DataSource interface
type SnowflakeSource struct {
	client *snowflake.Client
}

// NewSnowflakeSource creates a new Snowflake data source
func NewSnowflakeSource(client *snowflake.Client) *SnowflakeSource {
	return &SnowflakeSource{client: client}
}

// tableNamePattern matches table names in common clauses (FROM/JOIN/UPDATE/INTO)
var tableNamePattern = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|UPDATE|INTO)\s+([a-z][a-z0-9_\.]+)`)

// normalizeTableNames converts table names to uppercase for Snowflake compatibility
// Our sync engine creates uppercase tables (AWS_IAM_USERS) but queries use lowercase (aws_iam_users)
func normalizeTableNames(query string) string {
	return tableNamePattern.ReplaceAllStringFunc(query, func(match string) string {
		parts := tableNamePattern.FindStringSubmatch(match)
		if len(parts) >= 2 {
			tableName := parts[1]
			// Replace the table name with uppercase version
			return strings.Replace(match, tableName, strings.ToUpper(tableName), 1)
		}
		return match
	})
}

// Query executes a query against Snowflake
func (s *SnowflakeSource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	// Normalize table names to uppercase for Snowflake
	normalizedQuery := normalizeTableNames(query)

	result, err := s.client.Query(ctx, normalizedQuery, args...)
	if err != nil {
		return nil, err
	}

	return &QueryResult{
		Columns: result.Columns,
		Rows:    result.Rows,
		Count:   result.Count,
	}, nil
}
