package api

import "github.com/evalops/cerebro/internal/snowflake"

var (
	ErrEmptyQuery     = snowflake.ErrEmptyQuery
	ErrNonSelectQuery = snowflake.ErrNonSelectQuery
	ErrSQLInjection   = snowflake.ErrSQLInjection
)

// ValidateReadOnlyQuery validates that a query is a safe read-only statement.
func ValidateReadOnlyQuery(query string) error {
	return snowflake.ValidateReadOnlyQuery(query)
}
