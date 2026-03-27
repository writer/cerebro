package warehouse

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
)

func buildGetAssetsQuery(target any, table string, filter snowflake.AssetFilter) (string, []any, error) {
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return "", nil, err
	}

	query := `WITH deduped_assets AS (
SELECT *, ROW_NUMBER() OVER (
	PARTITION BY ` + quoteSQLiteIdentifier("_cq_id") + `
	ORDER BY ` + quoteSQLiteIdentifier("_cq_sync_time") + ` DESC
) AS ` + quoteSQLiteIdentifier("_cq_latest_rank") + `
FROM ` + quoteSQLiteIdentifier(table)

	conditions := make([]string, 0, 4)
	args := make([]any, 0, 8)

	if account := strings.TrimSpace(filter.Account); account != "" {
		conditions = append(conditions, quoteSQLiteIdentifier("account_id")+" = "+Placeholder(target, len(args)+1))
		args = append(args, account)
	}
	if region := strings.TrimSpace(filter.Region); region != "" {
		conditions = append(conditions, quoteSQLiteIdentifier("region")+" = "+Placeholder(target, len(args)+1))
		args = append(args, region)
	}
	if !filter.Since.IsZero() {
		sinceCondition := quoteSQLiteIdentifier("_cq_sync_time") + " > " + Placeholder(target, len(args)+1)
		args = append(args, warehouseTimeArg(target, filter.Since))
		if filter.SinceID != "" {
			sinceCondition = "(" + sinceCondition + " OR (" +
				quoteSQLiteIdentifier("_cq_sync_time") + " = " + Placeholder(target, len(args)+1) + " AND " +
				quoteSQLiteIdentifier("_cq_id") + " > " + Placeholder(target, len(args)+2) + "))"
			args = append(args, warehouseTimeArg(target, filter.Since), filter.SinceID)
		}
		conditions = append(conditions, sinceCondition)
	}
	if !filter.CursorSyncTime.IsZero() {
		cursorCondition := quoteSQLiteIdentifier("_cq_sync_time") + " > " + Placeholder(target, len(args)+1)
		args = append(args, warehouseTimeArg(target, filter.CursorSyncTime))
		if filter.CursorID != "" {
			cursorCondition = "(" + cursorCondition + " OR (" +
				quoteSQLiteIdentifier("_cq_sync_time") + " = " + Placeholder(target, len(args)+1) + " AND " +
				quoteSQLiteIdentifier("_cq_id") + " > " + Placeholder(target, len(args)+2) + "))"
			args = append(args, warehouseTimeArg(target, filter.CursorSyncTime), filter.CursorID)
		}
		conditions = append(conditions, cursorCondition)
	}

	if len(conditions) > 0 {
		query += `
WHERE ` + strings.Join(conditions, " AND ")
	}

	query += `
)
SELECT ` + assetSelectClause(filter.Columns) + `
FROM deduped_assets
WHERE ` + quoteSQLiteIdentifier("_cq_latest_rank") + ` = 1
ORDER BY ` + quoteSQLiteIdentifier("_cq_sync_time") + ` ASC, ` + quoteSQLiteIdentifier("_cq_id") + ` ASC`

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf("\nLIMIT %d", limit)
	if filter.Offset > 0 && filter.Since.IsZero() && filter.CursorSyncTime.IsZero() {
		query += fmt.Sprintf("\nOFFSET %d", filter.Offset)
	}

	return query, args, nil
}

func assetSelectClause(columns []string) string {
	if len(columns) == 0 {
		return "*"
	}

	validated := make([]string, 0, len(columns))
	for _, column := range columns {
		normalized, err := normalizeSQLiteIdentifier(column)
		if err != nil {
			continue
		}
		validated = append(validated, quoteSQLiteIdentifier(normalized))
	}
	if len(validated) == 0 {
		return "*"
	}
	return strings.Join(validated, ", ")
}

func finalizeAssetRows(table string, rows []map[string]interface{}) []map[string]interface{} {
	for i := range rows {
		delete(rows[i], "_cq_latest_rank")
		rows[i]["_cq_table"] = table
	}
	return rows
}

func warehouseTimeArg(target any, value time.Time) any {
	if Dialect(target) == SQLDialectSQLite {
		return value.UTC().Format(time.RFC3339Nano)
	}
	return value
}
