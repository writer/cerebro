package warehouse

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
	sanitizedForKeywords := strings.ToUpper(stripQuotedLiterals(normalized))

	for _, keyword := range forbiddenReadOnlyKeywords {
		if containsKeyword(sanitizedForKeywords, keyword) {
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
	normalizedQuery := normalizeReadOnlyDialect(strings.TrimSpace(query))
	if err := ValidateReadOnlyQuery(normalizedQuery); err != nil {
		return "", 0, err
	}

	boundedLimit := ClampReadOnlyQueryLimit(limit)
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(normalizedQuery), ";"))

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

func stripQuotedLiterals(query string) string {
	if query == "" {
		return ""
	}

	var out strings.Builder
	out.Grow(len(query))

	inSingleQuoted := false
	inDoubleQuoted := false

	for i := 0; i < len(query); i++ {
		ch := query[i]

		if inSingleQuoted {
			if ch == '\'' {
				if i+1 < len(query) && query[i+1] == '\'' {
					i++
					continue
				}
				inSingleQuoted = false
			}
			out.WriteByte(' ')
			continue
		}

		if inDoubleQuoted {
			if ch == '"' {
				if i+1 < len(query) && query[i+1] == '"' {
					i++
					continue
				}
				inDoubleQuoted = false
			}
			out.WriteByte(' ')
			continue
		}

		switch ch {
		case '\'':
			inSingleQuoted = true
			out.WriteByte(' ')
		case '"':
			inDoubleQuoted = true
			out.WriteByte(' ')
		default:
			out.WriteByte(ch)
		}
	}

	return out.String()
}

func normalizeReadOnlyDialect(query string) string {
	if query == "" {
		return ""
	}

	var out strings.Builder
	out.Grow(len(query) + 16)

	inSingleQuoted := false
	inDoubleQuoted := false

	for i := 0; i < len(query); i++ {
		ch := query[i]

		if inSingleQuoted {
			out.WriteByte(ch)
			if ch == '\'' {
				if i+1 < len(query) && query[i+1] == '\'' {
					i++
					out.WriteByte(query[i])
					continue
				}
				inSingleQuoted = false
			}
			continue
		}

		if inDoubleQuoted {
			out.WriteByte(ch)
			if ch == '"' {
				if i+1 < len(query) && query[i+1] == '"' {
					i++
					out.WriteByte(query[i])
					continue
				}
				inDoubleQuoted = false
			}
			continue
		}

		if ch == '\'' {
			inSingleQuoted = true
			out.WriteByte(ch)
			continue
		}
		if ch == '"' {
			inDoubleQuoted = true
			out.WriteByte(ch)
			continue
		}

		if i+2 < len(query) && (query[i] == 'N' || query[i] == 'n') && (query[i+1] == 'O' || query[i+1] == 'o') && (query[i+2] == 'W' || query[i+2] == 'w') {
			prevIsWord := i > 0 && isWordChar(query[i-1])
			nextIndex := i + 3
			if !prevIsWord {
				for nextIndex < len(query) && (query[nextIndex] == ' ' || query[nextIndex] == '\t' || query[nextIndex] == '\n' || query[nextIndex] == '\r') {
					nextIndex++
				}
				if nextIndex+1 < len(query) && query[nextIndex] == '(' {
					close := nextIndex + 1
					for close < len(query) && (query[close] == ' ' || query[close] == '\t' || query[close] == '\n' || query[close] == '\r') {
						close++
					}
					if close < len(query) && query[close] == ')' {
						after := close + 1
						nextIsWord := after < len(query) && isWordChar(query[after])
						if !nextIsWord {
							out.WriteString("CURRENT_TIMESTAMP")
							i = close
							continue
						}
					}
				}
			}
		}

		out.WriteByte(ch)
	}

	return out.String()
}

func isWordChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}
