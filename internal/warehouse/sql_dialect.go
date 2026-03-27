package warehouse

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/snowflake"
)

type SQLDialect string

const (
	SQLDialectSnowflake SQLDialect = "snowflake"
	SQLDialectPostgres  SQLDialect = "postgres"
	SQLDialectSQLite    SQLDialect = "sqlite"
)

func (w *PostgresWarehouse) SQLDialect() SQLDialect {
	return SQLDialectPostgres
}

func (w *SQLiteWarehouse) SQLDialect() SQLDialect {
	return SQLDialectSQLite
}

func (m *MemoryWarehouse) SQLDialect() SQLDialect {
	if m == nil || strings.TrimSpace(string(m.DialectValue)) == "" {
		return SQLDialectSnowflake
	}
	return m.DialectValue
}

func Dialect(target any) SQLDialect {
	switch typed := target.(type) {
	case nil:
		return SQLDialectSnowflake
	case interface{ SQLDialect() SQLDialect }:
		if dialect := typed.SQLDialect(); dialect != "" {
			return dialect
		}
	case *snowflake.Client:
		return SQLDialectSnowflake
	}
	return SQLDialectSnowflake
}

func Placeholder(target any, position int) string {
	if position < 1 {
		position = 1
	}
	if Dialect(target) == SQLDialectPostgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}

func Placeholders(target any, start, count int) []string {
	if count <= 0 {
		return nil
	}
	if start < 1 {
		start = 1
	}
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		values = append(values, Placeholder(target, start+i))
	}
	return values
}

func JSONColumnType(target any) string {
	switch Dialect(target) {
	case SQLDialectPostgres:
		return "JSONB"
	case SQLDialectSQLite:
		return "TEXT"
	default:
		return "VARIANT"
	}
}

func TimestampColumnType(target any) string {
	switch Dialect(target) {
	case SQLDialectPostgres:
		return "TIMESTAMPTZ"
	case SQLDialectSQLite:
		return "TEXT"
	default:
		return "TIMESTAMP_TZ"
	}
}

func LocalTimestampColumnType(target any) string {
	switch Dialect(target) {
	case SQLDialectPostgres:
		return "TIMESTAMPTZ"
	case SQLDialectSQLite:
		return "TEXT"
	default:
		return "TIMESTAMP_NTZ"
	}
}

func IntegerColumnType(target any) string {
	switch Dialect(target) {
	case SQLDialectPostgres:
		return "BIGINT"
	case SQLDialectSQLite:
		return "INTEGER"
	default:
		return "NUMBER"
	}
}

func JSONPlaceholder(target any, position int) string {
	placeholder := Placeholder(target, position)
	switch Dialect(target) {
	case SQLDialectPostgres:
		return placeholder + "::jsonb"
	case SQLDialectSnowflake:
		return "PARSE_JSON(" + placeholder + ")"
	default:
		return placeholder
	}
}
