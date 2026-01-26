package api

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrEmptyQuery     = errors.New("query cannot be empty")
	ErrNonSelectQuery = errors.New("only SELECT queries are allowed")
	ErrSQLInjection   = errors.New("potential SQL injection detected")
)

// ValidateReadOnlyQuery validates that a query is a read-only SELECT statement
func ValidateReadOnlyQuery(query string) error {
	query = strings.TrimSpace(query)
	if query == "" {
		return ErrEmptyQuery
	}

	// Normalize to uppercase for comparison
	upper := strings.ToUpper(query)

	// Must start with SELECT
	if !strings.HasPrefix(upper, "SELECT") {
		return ErrNonSelectQuery
	}

	// Check for dangerous keywords
	dangerousPatterns := []string{
		"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
		"ALTER", "CREATE", "GRANT", "REVOKE", "CALL", "EXECUTE",
	}

	for _, pattern := range dangerousPatterns {
		// Look for the pattern as a word boundary
		re := regexp.MustCompile(`\b` + pattern + `\b`)
		if re.MatchString(upper) {
			return ErrSQLInjection
		}
	}

	// Check for multiple statements
	if strings.Contains(query, ";") {
		// Allow trailing semicolon but not multiple statements
		trimmed := strings.TrimSuffix(strings.TrimSpace(query), ";")
		if strings.Contains(trimmed, ";") {
			return ErrSQLInjection
		}
	}

	// Check for SQL comments (injection vector)
	if strings.Contains(query, "--") || strings.Contains(query, "/*") {
		return ErrSQLInjection
	}

	return nil
}
