package snowflake

import (
	"errors"
	"strings"
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
