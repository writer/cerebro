package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	apiclient "github.com/writer/cerebro/internal/client"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

var queryCmd = &cobra.Command{
	Use:   "query [sql]",
	Short: "Execute SQL query against the configured warehouse",
	Long: `Execute a SQL query against the configured warehouse.

The query results are displayed in table format by default, with support
for JSON and CSV output. A LIMIT clause is automatically appended if not present.

Examples:
  cerebro query "SELECT * FROM aws_s3_buckets"
  cerebro query "SELECT name, region FROM aws_ec2_instances" --limit 50
  cerebro query "SELECT * FROM aws_iam_users" --format json
  cerebro query "SELECT COUNT(*) FROM aws_s3_buckets"`,
	Args: cobra.MinimumNArgs(1),
	RunE: runQuery,
}

var (
	queryFormat string
	queryLimit  int

	runQueryDirectFn = runQueryDirect
)

var allowedReadOnlyPRAGMAs = map[string]struct{}{
	"TABLE_INFO":       {},
	"TABLE_XINFO":      {},
	"TABLE_LIST":       {},
	"INDEX_LIST":       {},
	"INDEX_INFO":       {},
	"INDEX_XINFO":      {},
	"FOREIGN_KEY_LIST": {},
	"DATABASE_LIST":    {},
	"COMPILE_OPTIONS":  {},
	"FUNCTION_LIST":    {},
	"MODULE_LIST":      {},
	"PRAGMA_LIST":      {},
}

func init() {
	queryCmd.Flags().StringVarP(&queryFormat, "format", "f", "table", "Output format: table, json, csv")
	queryCmd.Flags().IntVarP(&queryLimit, "limit", "l", 100, "Limit results")
}

func runQuery(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			result, err := apiClient.Query(ctx, apiclient.QueryRequest{
				Query:          strings.Join(args, " "),
				Limit:          queryLimit,
				TimeoutSeconds: int((60 * time.Second) / time.Second),
			})
			if err == nil {
				return renderQueryResult(result)
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("query via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runQueryDirectFn(cmd, args)
}

func runQueryDirect(cmd *cobra.Command, args []string) error {
	queryWarehouse, err := app.OpenWarehouse(commandContextOrBackground(cmd), nil, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize warehouse: %w", err)
	}
	if queryWarehouse == nil {
		return fmt.Errorf("warehouse not configured")
	}
	if closer, ok := queryWarehouse.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}

	query := strings.Join(args, " ")
	rawQuery := false
	queryArgs := []any(nil)
	if metadataQuery, metadataArgs, executeRaw, handled, err := prepareDirectMetadataQueryWithArgs(query); err != nil {
		return err
	} else if handled {
		query = metadataQuery
		queryArgs = metadataArgs
		rawQuery = executeRaw
	}
	if !rawQuery {
		if warehouse.HasTopLevelLimit(query) {
			query, err = warehouse.NormalizeReadOnlyQuery(query)
			if err != nil {
				return err
			}
		} else {
			query, _, err = warehouse.BuildReadOnlyLimitedQuery(query, queryLimit)
			if err != nil {
				return err
			}
		}
	}

	ctx, cancel := context.WithTimeout(commandContextOrBackground(cmd), warehouse.ClampReadOnlyQueryTimeout(int((60*time.Second)/time.Second)))
	defer cancel()

	result, err := queryWarehouse.Query(ctx, query, queryArgs...)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	return renderQueryResult(result)
}

func prepareDirectMetadataQuery(query string) (string, bool, bool, error) {
	metadataQuery, _, executeRaw, handled, err := prepareDirectMetadataQueryWithArgs(query)
	return metadataQuery, executeRaw, handled, err
}

func prepareDirectMetadataQueryWithArgs(query string) (string, []any, bool, bool, error) {
	candidate := strings.TrimSpace(query)
	candidateUpper := strings.ToUpper(candidate)
	if !strings.HasPrefix(candidateUpper, "SHOW") &&
		!strings.HasPrefix(candidateUpper, "PRAGMA") &&
		!strings.HasPrefix(candidateUpper, "DESCRIBE") &&
		!strings.HasPrefix(candidateUpper, "DESC") {
		return "", nil, false, false, nil
	}

	trimmed, err := normalizeDirectMetadataQuery(query)
	if err != nil {
		return "", nil, false, false, err
	}

	upper := strings.ToUpper(strings.Join(strings.Fields(trimmed), " "))
	if upper == "SHOW TABLES" {
		return "SELECT table_name FROM information_schema.tables ORDER BY table_name", nil, false, true, nil
	}

	if strings.HasPrefix(upper, "DESCRIBE TABLE ") || strings.HasPrefix(upper, "DESC TABLE ") {
		tableName, err := directMetadataTableName(trimmed)
		if err != nil {
			return "", nil, false, false, err
		}
		return "SELECT column_name FROM information_schema.columns WHERE table_name = ? ORDER BY column_name", []any{tableName}, false, true, nil
	}

	if strings.HasPrefix(strings.ToUpper(trimmed), "PRAGMA ") {
		if !isAllowedReadOnlyPRAGMA(trimmed) {
			return "", nil, false, false, fmt.Errorf("only read-only PRAGMA metadata queries are supported")
		}
		return trimmed, nil, true, true, nil
	}

	return "", nil, false, false, nil
}

func directMetadataTableName(query string) (string, error) {
	fields := strings.Fields(query)
	if len(fields) < 3 || !strings.EqualFold(fields[1], "TABLE") {
		return "", fmt.Errorf("expected DESCRIBE TABLE <table>")
	}
	tableName := strings.TrimSpace(strings.Join(fields[2:], " "))
	if tableName == "" {
		return "", fmt.Errorf("expected DESCRIBE TABLE <table>")
	}
	if idx := strings.LastIndex(tableName, "."); idx >= 0 {
		tableName = tableName[idx+1:]
	}
	tableName = strings.TrimSpace(strings.Trim(tableName, "`\""))
	if tableName == "" {
		return "", fmt.Errorf("expected DESCRIBE TABLE <table>")
	}
	return tableName, nil
}

func normalizeDirectMetadataQuery(query string) (string, error) {
	if strings.TrimSpace(query) == "" {
		return "", warehouse.ErrEmptyQuery
	}
	if strings.Contains(query, "--") || strings.Contains(query, "/*") || strings.Contains(query, "*/") {
		return "", warehouse.ErrSQLInjection
	}

	trimmed := strings.TrimSpace(query)
	semicolonCount := strings.Count(trimmed, ";")
	if semicolonCount > 1 {
		return "", warehouse.ErrSQLInjection
	}
	if semicolonCount == 1 {
		if !strings.HasSuffix(trimmed, ";") {
			return "", warehouse.ErrSQLInjection
		}
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	}

	return trimmed, nil
}

func isAllowedReadOnlyPRAGMA(query string) bool {
	trimmed := strings.TrimSpace(query)
	if strings.Contains(trimmed, "=") {
		return false
	}

	fields := strings.Fields(trimmed)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "PRAGMA") {
		return false
	}

	name := fields[1]
	if idx := strings.IndexAny(name, "(;"); idx >= 0 {
		name = name[:idx]
	}
	if parts := strings.Split(name, "."); len(parts) > 0 {
		name = parts[len(parts)-1]
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	_, ok := allowedReadOnlyPRAGMAs[name]
	return ok
}

func renderQueryResult(result *snowflake.QueryResult) error {
	switch queryFormat {
	case "json":
		return JSONOutput(map[string]interface{}{
			"columns": result.Columns,
			"rows":    result.Rows,
			"count":   result.Count,
		})
	case "csv":
		rows := make([][]string, len(result.Rows))
		for i, row := range result.Rows {
			vals := make([]string, len(result.Columns))
			for j, col := range result.Columns {
				vals[j] = fmt.Sprintf("%v", row[strings.ToLower(col)])
			}
			rows[i] = vals
		}
		return CSVOutput(result.Columns, rows)
	default:
		if len(result.Rows) == 0 {
			Info("No results")
			return nil
		}
		tw := NewTableWriter(os.Stdout, result.Columns...)
		for _, row := range result.Rows {
			vals := make([]string, len(result.Columns))
			for i, col := range result.Columns {
				vals[i] = fmt.Sprintf("%v", row[strings.ToLower(col)])
			}
			tw.AddRow(vals...)
		}
		tw.Render()
	}

	fmt.Printf("\n%d rows returned\n", result.Count)
	return nil
}
