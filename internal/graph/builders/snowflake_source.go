package builders

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

// SnowflakeSource adapts the Snowflake client to the DataSource interface
type SnowflakeSource struct {
	client              warehouse.QueryWarehouse
	normalizeTableNames bool
	cdcEventsTableRef   string
	useDollarBinds      bool
}

// NewSnowflakeSource creates a new Snowflake data source
func NewSnowflakeSource(client warehouse.QueryWarehouse) *SnowflakeSource {
	_, shouldNormalize := client.(*snowflake.Client)
	source := &SnowflakeSource{client: client, normalizeTableNames: shouldNormalize}

	if dialectSource, ok := client.(interface{ Dialect() string }); ok && strings.EqualFold(strings.TrimSpace(dialectSource.Dialect()), "postgres") {
		source.useDollarBinds = true
		source.cdcEventsTableRef = "cerebro.cdc_events"
		if schemaSource, ok := client.(interface{ AppSchema() string }); ok {
			schema := strings.TrimSpace(schemaSource.AppSchema())
			if schema != "" && snowflake.ValidateTableName(schema) == nil {
				source.cdcEventsTableRef = strings.ToLower(schema) + ".cdc_events"
			}
		}
	}

	return source
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
func (s *SnowflakeSource) Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error) {
	normalizedQuery := query
	if s.normalizeTableNames {
		normalizedQuery = normalizeTableNames(query)
	}

	result, err := s.client.Query(ctx, normalizedQuery, args...)
	if err != nil {
		return nil, err
	}

	return &DataQueryResult{
		Columns: result.Columns,
		Rows:    result.Rows,
		Count:   result.Count,
	}, nil
}

func (s *SnowflakeSource) cdcEventsTable() string {
	if strings.TrimSpace(s.cdcEventsTableRef) != "" {
		return s.cdcEventsTableRef
	}
	return "CDC_EVENTS"
}

func (s *SnowflakeSource) cdcPlaceholder(index int) string {
	if s.useDollarBinds {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}
