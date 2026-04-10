package sync

import (
	"fmt"

	"github.com/writer/cerebro/internal/warehouse"
)

func syncWarehouseDialect(store warehouse.SyncWarehouse) string {
	return warehouse.DialectFor(store)
}

func syncVariantColumnType(store warehouse.SyncWarehouse) string {
	switch syncWarehouseDialect(store) {
	case warehouse.DialectPostgres:
		return "JSONB"
	case warehouse.DialectSQLite:
		return "JSON"
	default:
		return "VARIANT"
	}
}

func syncTimestampColumnType(store warehouse.SyncWarehouse) string {
	switch syncWarehouseDialect(store) {
	case warehouse.DialectPostgres:
		return "TIMESTAMPTZ"
	case warehouse.DialectSQLite:
		return "TEXT"
	default:
		return "TIMESTAMP_TZ"
	}
}

func syncVariantValueExpr(store warehouse.SyncWarehouse, placeholder string) string {
	switch syncWarehouseDialect(store) {
	case warehouse.DialectPostgres:
		return fmt.Sprintf("CAST(%s AS JSONB)", placeholder)
	case warehouse.DialectSQLite:
		return placeholder
	default:
		return fmt.Sprintf("TRY_PARSE_JSON(%s)", placeholder)
	}
}
