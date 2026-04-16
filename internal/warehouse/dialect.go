package warehouse

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

const (
	DialectSnowflake = "snowflake"
	DialectPostgres  = "postgres"
	DialectSQLite    = "sqlite"
)

var currentTimestampCallPattern = regexp.MustCompile(`(?i)CURRENT_TIMESTAMP\(\)`)

func DialectFor(schema SchemaWarehouse) string {
	if schema == nil {
		return DialectSnowflake
	}
	return DialectForDB(schema.DB())
}

func DialectForDB(db *sql.DB) string {
	if db == nil {
		return DialectSnowflake
	}
	driverType := strings.ToLower(fmt.Sprintf("%T", db.Driver()))
	switch {
	case strings.Contains(driverType, "sqlite"):
		return DialectSQLite
	case strings.Contains(driverType, "pgx"), strings.Contains(driverType, "postgres"), strings.Contains(driverType, "pq"):
		return DialectPostgres
	default:
		return DialectSnowflake
	}
}

func RewriteQueryForDialect(query, dialect string) string {
	switch dialect {
	case DialectPostgres:
		return rewriteForPostgres(query)
	case DialectSQLite:
		return rewriteForSQLite(query)
	default:
		return query
	}
}

func rewriteForPostgres(query string) string {
	rewritten := currentTimestampCallPattern.ReplaceAllString(query, "CURRENT_TIMESTAMP")
	rewritten = replaceKeyword(rewritten, "TIMESTAMP_TZ", "TIMESTAMPTZ")
	rewritten = replaceKeyword(rewritten, "TIMESTAMP_NTZ", "TIMESTAMP")
	rewritten = replaceKeyword(rewritten, "VARIANT", "JSONB")
	rewritten = replaceKeyword(rewritten, "NUMBER", "NUMERIC")
	rewritten = rewriteJSONFunctions(rewritten, DialectPostgres)
	rewritten = strings.ReplaceAll(rewritten, "::TIMESTAMP_TZ", "::TIMESTAMPTZ")
	return rewriteQuestionPlaceholders(rewritten)
}

func rewriteForSQLite(query string) string {
	rewritten := currentTimestampCallPattern.ReplaceAllString(query, "CURRENT_TIMESTAMP")
	rewritten = replaceKeyword(rewritten, "TIMESTAMP_TZ", "TEXT")
	rewritten = replaceKeyword(rewritten, "TIMESTAMP_NTZ", "TEXT")
	rewritten = replaceKeyword(rewritten, "VARIANT", "JSON")
	rewritten = replaceKeyword(rewritten, "NUMBER", "NUMERIC")
	rewritten = rewriteJSONFunctions(rewritten, DialectSQLite)
	rewritten = strings.ReplaceAll(rewritten, "::TIMESTAMP_TZ", "")
	return rewritten
}

func rewriteQuestionPlaceholders(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	index := maxDollarPlaceholderIndex(query) + 1
	for i := 0; i < len(query); {
		switch query[i] {
		case '\'', '"':
			end := skipSQLQuotedSection(query, i)
			b.WriteString(query[i:end])
			i = end
		case '?':
			_, _ = fmt.Fprintf(&b, "$%d", index)
			index++
			i++
		default:
			b.WriteByte(query[i])
			i++
		}
	}
	return b.String()
}

func replaceKeyword(query, oldWord, newWord string) string {
	pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(oldWord) + `\b`)
	return applyOutsideSQLQuotedSections(query, func(segment string) string {
		return pattern.ReplaceAllString(segment, newWord)
	})
}

func rewriteJSONFunctions(query, dialect string) string {
	var b strings.Builder
	for i := 0; i < len(query); {
		switch query[i] {
		case '\'', '"':
			end := skipSQLQuotedSection(query, i)
			b.WriteString(query[i:end])
			i = end
		default:
			nameLen := matchedJSONFunctionNameLength(query, i)
			if nameLen == 0 {
				b.WriteByte(query[i])
				i++
				continue
			}

			open := i + nameLen
			for open < len(query) && isSQLWhitespace(query[open]) {
				open++
			}
			if open >= len(query) || query[open] != '(' {
				b.WriteByte(query[i])
				i++
				continue
			}

			close, ok := findMatchingSQLParen(query, open)
			if !ok {
				b.WriteByte(query[i])
				i++
				continue
			}

			expr := strings.TrimSpace(rewriteJSONFunctions(query[open+1:close], dialect))
			switch dialect {
			case DialectPostgres:
				b.WriteString("CAST(" + expr + " AS JSONB)")
			case DialectSQLite:
				b.WriteString(expr)
			default:
				b.WriteString(query[i : close+1])
			}
			i = close + 1
		}
	}
	return b.String()
}

func maxDollarPlaceholderIndex(query string) int {
	max := 0
	_ = applyOutsideSQLQuotedSections(query, func(segment string) string {
		if value := maxDollarPlaceholderIndexInSegment(segment); value > max {
			max = value
		}
		return segment
	})
	return max
}

func maxDollarPlaceholderIndexInSegment(segment string) int {
	max := 0
	for i := 0; i < len(segment); i++ {
		if segment[i] != '$' || i+1 >= len(segment) || segment[i+1] < '0' || segment[i+1] > '9' {
			continue
		}
		value := 0
		for j := i + 1; j < len(segment) && segment[j] >= '0' && segment[j] <= '9'; j++ {
			value = value*10 + int(segment[j]-'0')
			i = j
		}
		if value > max {
			max = value
		}
	}
	return max
}

func applyOutsideSQLQuotedSections(query string, rewrite func(string) string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(query); {
		switch query[i] {
		case '\'', '"':
			if last < i {
				b.WriteString(rewrite(query[last:i]))
			}
			end := skipSQLQuotedSection(query, i)
			b.WriteString(query[i:end])
			i = end
			last = end
		default:
			i++
		}
	}
	if last < len(query) {
		b.WriteString(rewrite(query[last:]))
	}
	return b.String()
}

func skipSQLQuotedSection(query string, start int) int {
	if start < 0 || start >= len(query) {
		return len(query)
	}
	quote := query[start]
	for i := start + 1; i < len(query); i++ {
		if query[i] != quote {
			continue
		}
		if i+1 < len(query) && query[i+1] == quote {
			i++
			continue
		}
		return i + 1
	}
	return len(query)
}

func matchedJSONFunctionNameLength(query string, start int) int {
	if start > 0 && isSQLWordCharacter(query[start-1]) {
		return 0
	}
	for _, name := range []string{"TRY_PARSE_JSON", "PARSE_JSON"} {
		if start+len(name) <= len(query) && strings.EqualFold(query[start:start+len(name)], name) {
			return len(name)
		}
	}
	return 0
}

func findMatchingSQLParen(query string, open int) (int, bool) {
	if open < 0 || open >= len(query) || query[open] != '(' {
		return 0, false
	}
	depth := 0
	for i := open; i < len(query); i++ {
		switch query[i] {
		case '\'', '"':
			i = skipSQLQuotedSection(query, i) - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func isSQLWhitespace(ch byte) bool {
	switch ch {
	case ' ', '\n', '\r', '\t', '\f':
		return true
	default:
		return false
	}
}

func isSQLWordCharacter(ch byte) bool {
	return ch == '_' ||
		(ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9')
}
