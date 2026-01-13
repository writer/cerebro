package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/config"
	"github.com/writerinternal/cerebro/internal/snowflake"
)

var queryCmd = &cobra.Command{
	Use:   "query [sql]",
	Short: "Execute SQL query against Snowflake",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runQuery,
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
	cfg := config.Load()

	if cfg.SnowflakeConnection == "" {
		return fmt.Errorf("SNOWFLAKE_CONNECTION_STRING not set")
	}

	client, err := snowflake.NewClient(cfg.SnowflakeConnection, cfg.SnowflakeDatabase, cfg.SnowflakeSchema)
	if err != nil {
		return fmt.Errorf("connect to snowflake: %w", err)
	}
	defer client.Close()

	query := strings.Join(args, " ")
	if !strings.Contains(strings.ToUpper(query), "LIMIT") && queryLimit > 0 {
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
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "csv":
		fmt.Println(strings.Join(result.Columns, ","))
		for _, row := range result.Rows {
			vals := make([]string, len(result.Columns))
			for i, col := range result.Columns {
				vals[i] = fmt.Sprintf("%v", row[col])
			}
			fmt.Println(strings.Join(vals, ","))
		}
	default:
		printTable(result)
	}

	fmt.Printf("\n%d rows returned\n", result.Count)
	return nil
}

func printTable(result *snowflake.QueryResult) {
	if len(result.Rows) == 0 {
		fmt.Println("No results")
		return
	}

	widths := make([]int, len(result.Columns))
	for i, col := range result.Columns {
		widths[i] = len(col)
	}
	for _, row := range result.Rows {
		for i, col := range result.Columns {
			val := fmt.Sprintf("%v", row[col])
			if len(val) > widths[i] {
				widths[i] = len(val)
			}
			if widths[i] > 50 {
				widths[i] = 50
			}
		}
	}

	// Header
	for i, col := range result.Columns {
		fmt.Printf("%-*s  ", widths[i], col)
	}
	fmt.Println()

	// Separator
	for i := range result.Columns {
		fmt.Print(strings.Repeat("-", widths[i]) + "  ")
	}
	fmt.Println()

	// Rows
	for _, row := range result.Rows {
		for i, col := range result.Columns {
			val := fmt.Sprintf("%v", row[col])
			if len(val) > 50 {
				val = val[:47] + "..."
			}
			fmt.Printf("%-*s  ", widths[i], val)
		}
		fmt.Println()
	}
}
