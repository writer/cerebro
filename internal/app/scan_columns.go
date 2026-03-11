package app

import (
	"context"
	"sort"
	"strings"
)

var scanIdentifierColumns = []string{
	"_cq_id",
	"_cq_sync_time",
	"arn",
	"id",
	"name",
	"resource_id",
	"instance_id",
	"role_id",
	"user_id",
	"bucket_name",
	"function_name",
	"uid",
	"role_name",
	"user_name",
	"display_name",
	"title",
	"self_link",
}

func (a *App) ScanColumnsForTable(ctx context.Context, table string) []string {
	if a == nil || a.Policy == nil {
		return nil
	}

	candidates := make(map[string]struct{})
	for _, col := range a.Policy.ColumnsForTable(table) {
		candidates[strings.ToLower(col)] = struct{}{}
	}
	for _, col := range scanIdentifierColumns {
		candidates[col] = struct{}{}
	}

	if a.Warehouse == nil {
		return sortedColumns(candidates)
	}

	available, err := a.Warehouse.DescribeColumns(ctx, table)
	if err != nil {
		a.Logger.Warn("failed to describe scan columns", "table", table, "error", err)
		return nil
	}

	availableSet := make(map[string]struct{}, len(available))
	for _, col := range available {
		availableSet[strings.ToLower(col)] = struct{}{}
	}

	filtered := make([]string, 0, len(candidates))
	for col := range candidates {
		if _, ok := availableSet[col]; ok {
			filtered = append(filtered, col)
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	sort.Strings(filtered)
	return filtered
}

func sortedColumns(cols map[string]struct{}) []string {
	if len(cols) == 0 {
		return nil
	}

	result := make([]string, 0, len(cols))
	for col := range cols {
		result = append(result, col)
	}
	sort.Strings(result)
	return result
}
