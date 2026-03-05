package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/snowflake"
)

var queryCmd = &cobra.Command{
	Use:   "query [sql]",
	Short: "Execute SQL query against Snowflake",
	Long: `Execute a SQL query against the Snowflake data warehouse.

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
)

func init() {
	queryCmd.Flags().StringVarP(&queryFormat, "format", "f", "table", "Output format: table, json, csv")
	queryCmd.Flags().IntVarP(&queryLimit, "limit", "l", 100, "Limit results")
}

func runQuery(cmd *cobra.Command, args []string) error {
	dsnCfg := snowflake.DSNConfigFromEnv()
	if missing := dsnCfg.MissingFields(); len(missing) > 0 {
		return fmt.Errorf("snowflake not configured: set %s", strings.Join(missing, ", "))
	}

	client, err := snowflake.NewClient(snowflake.ClientConfig{
		Account:    dsnCfg.Account,
		User:       dsnCfg.User,
		PrivateKey: dsnCfg.PrivateKey,
		Database:   dsnCfg.Database,
		Schema:     dsnCfg.Schema,
		Warehouse:  dsnCfg.Warehouse,
		Role:       dsnCfg.Role,
	})
	if err != nil {
		return fmt.Errorf("connect to snowflake: %w", err)
	}
	defer func() { _ = client.Close() }()

	query := strings.Join(args, " ")
	upperQuery := strings.ToUpper(strings.TrimSpace(query))
	// Only add LIMIT to SELECT queries that don't already have one
	if strings.HasPrefix(upperQuery, "SELECT") && !strings.Contains(upperQuery, "LIMIT") && queryLimit > 0 {
		query = fmt.Sprintf("%s LIMIT %d", query, queryLimit)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := client.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

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
