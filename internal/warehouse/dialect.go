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
	index := 1
	inSingle := false
	inDouble := false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		switch ch {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
			b.WriteByte(ch)
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
			b.WriteByte(ch)
		case '?':
			if inSingle || inDouble {
				b.WriteByte(ch)
				continue
			}
			_, _ = fmt.Fprintf(&b, "$%d", index)
			index++
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func replaceKeyword(query, oldWord, newWord string) string {
	pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(oldWord) + `\b`)
	return pattern.ReplaceAllString(query, newWord)
}

func rewriteJSONFunctions(query, dialect string) string {
	pattern := regexp.MustCompile(`(?i)(TRY_PARSE_JSON|PARSE_JSON)\(([^()]+)\)`)
	return pattern.ReplaceAllStringFunc(query, func(match string) string {
		submatches := pattern.FindStringSubmatch(match)
		if len(submatches) != 3 {
			return match
		}
		expr := strings.TrimSpace(submatches[2])
		switch dialect {
		case DialectPostgres:
			return "CAST(" + expr + " AS JSONB)"
		case DialectSQLite:
			return expr
		default:
			return match
		}
	})
}
