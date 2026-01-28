package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

const insertBatchSize = 200

func insertRowsBatch(ctx context.Context, sf *snowflake.Client, table string, rows []map[string]interface{}) error {
	if len(rows) == 0 {
		return nil
	}

	columnSet := make(map[string]struct{})
	for _, row := range rows {
		for k := range row {
			if k == "_cq_id" || k == "_cq_hash" {
				continue
			}
			columnSet[strings.ToUpper(k)] = struct{}{}
		}
	}

	columns := make([]string, 0, len(columnSet))
	for col := range columnSet {
		columns = append(columns, col)
	}
	sort.Strings(columns)

	allColumns := append([]string{"_CQ_ID", "_CQ_HASH"}, columns...)

	for start := 0; start < len(rows); start += insertBatchSize {
		end := start + insertBatchSize
		if end > len(rows) {
			end = len(rows)
		}

		batch := rows[start:end]
		selects := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*len(allColumns))

		for _, row := range batch {
			id, _ := row["_cq_id"].(string)
			hash, _ := row["_cq_hash"].(string)
			if id == "" {
				continue
			}

			rowUpper := make(map[string]interface{}, len(row))
			for k, v := range row {
				rowUpper[strings.ToUpper(k)] = v
			}

			selectParts := make([]string, 0, len(allColumns))
			selectParts = append(selectParts, "?", "?")
			args = append(args, id, hash)

			for _, col := range columns {
				jsonVal, _ := json.Marshal(rowUpper[col])
				selectParts = append(selectParts, "PARSE_JSON(?)")
				args = append(args, string(jsonVal))
			}

			selects = append(selects, "SELECT "+strings.Join(selectParts, ", "))
		}

		if len(selects) == 0 {
			continue
		}

		query := fmt.Sprintf("INSERT INTO %s (%s) %s",
			table, strings.Join(allColumns, ", "), strings.Join(selects, " UNION ALL "))

		if _, err := sf.Exec(ctx, query, args...); err != nil {
			return err
		}
	}

	return nil
}
