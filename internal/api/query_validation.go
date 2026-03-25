package api

import "github.com/writer/cerebro/internal/warehouse"

var (
	ErrEmptyQuery     = warehouse.ErrEmptyQuery
	ErrNonSelectQuery = warehouse.ErrNonSelectQuery
	ErrSQLInjection   = warehouse.ErrSQLInjection
)

// ValidateReadOnlyQuery validates that a query is a safe read-only statement.
func ValidateReadOnlyQuery(query string) error {
	return warehouse.ValidateReadOnlyQuery(query)
}
