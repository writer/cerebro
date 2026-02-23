package snowflake

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultReadOnlyQueryLimit   = 100
	MaxReadOnlyQueryLimit       = 1000
	DefaultReadOnlyQueryTimeout = 15 * time.Second
	MaxReadOnlyQueryTimeout     = 60 * time.Second
)

var (
	ErrEmptyQuery     = errors.New("query cannot be empty")
	ErrNonSelectQuery = errors.New("only SELECT and WITH queries are allowed")
	ErrSQLInjection   = errors.New("potential SQL injection detected")
)

var forbiddenReadOnlyKeywords = []string{
	"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
	"CREATE", "ALTER", "GRANT", "REVOKE", "EXECUTE",
	"CALL", "MERGE", "COPY", "PUT", "GET", "EXEC",
}

// ValidateReadOnlyQuery validates that a query is a safe read-only statement.
func ValidateReadOnlyQuery(query string) error {
	if strings.TrimSpace(query) == "" {
		return ErrEmptyQuery
	}

	// Disallow comments to reduce injection surface.
	if strings.Contains(query, "--") || strings.Contains(query, "/*") || strings.Contains(query, "*/") {
		return ErrSQLInjection
	}

	normalized := normalizeQuery(query)
	if normalized == "" {
		return ErrEmptyQuery
	}

	semicolonCount := strings.Count(normalized, ";")
	if semicolonCount > 1 {
		return ErrSQLInjection
	}
	if semicolonCount == 1 {
		if !strings.HasSuffix(normalized, ";") {
			return ErrSQLInjection
		}
		normalized = strings.TrimSpace(strings.TrimSuffix(normalized, ";"))
	}

	upper := strings.ToUpper(normalized)
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
		return ErrNonSelectQuery
	}

	for _, keyword := range forbiddenReadOnlyKeywords {
		if containsKeyword(upper, keyword) {
			return ErrSQLInjection
		}
	}

	return nil
}

// ClampReadOnlyQueryLimit bounds query limits to safe defaults.
func ClampReadOnlyQueryLimit(limit int) int {
	if limit <= 0 {
		return DefaultReadOnlyQueryLimit
	}
	if limit > MaxReadOnlyQueryLimit {
		return MaxReadOnlyQueryLimit
	}
	return limit
}

// ClampReadOnlyQueryTimeout bounds per-request query timeout in seconds.
func ClampReadOnlyQueryTimeout(timeoutSeconds int) time.Duration {
	if timeoutSeconds <= 0 {
		return DefaultReadOnlyQueryTimeout
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout > MaxReadOnlyQueryTimeout {
		return MaxReadOnlyQueryTimeout
	}
	return timeout
}

// BuildReadOnlyLimitedQuery validates read-only SQL and enforces row-limit pushdown.
func BuildReadOnlyLimitedQuery(query string, limit int) (string, int, error) {
	if err := ValidateReadOnlyQuery(query); err != nil {
		return "", 0, err
	}

	boundedLimit := ClampReadOnlyQueryLimit(limit)
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query), ";"))

	boundedQuery := fmt.Sprintf("SELECT * FROM (%s) AS cerebro_readonly_query LIMIT %d", trimmed, boundedLimit)
	return boundedQuery, boundedLimit, nil
}

func normalizeQuery(query string) string {
	fields := strings.Fields(query)
	return strings.Join(fields, " ")
}

func containsKeyword(sql, keyword string) bool {
	idx := 0
	for {
		pos := strings.Index(sql[idx:], keyword)
		if pos == -1 {
			return false
		}
		pos += idx

		validBefore := pos == 0 || !isWordChar(sql[pos-1])
		validAfter := pos+len(keyword) >= len(sql) || !isWordChar(sql[pos+len(keyword)])

		if validBefore && validAfter {
			return true
		}

		idx = pos + 1
		if idx >= len(sql) {
			return false
		}
	}
}

func isWordChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}
