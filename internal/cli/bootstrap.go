package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/app"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Initialize Snowflake schema and tables",
	Long: `Bootstrap creates the Cerebro schema and all required tables in Snowflake.

This command should be run once when setting up a new Cerebro installation.
It is safe to run multiple times as it uses CREATE IF NOT EXISTS.`,
	RunE: runBootstrap,
}

var (
	bootstrapDrop bool
)

func init() {
	bootstrapCmd.Flags().BoolVar(&bootstrapDrop, "drop", false, "Drop existing schema before creating (WARNING: destroys all data)")
}

func runBootstrap(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	defer application.Close()

	if application.Snowflake == nil {
		return fmt.Errorf("snowflake not configured - set SNOWFLAKE_CONNECTION_STRING")
	}

	if bootstrapDrop {
		fmt.Println("Dropping existing schema...")
		if err := application.Snowflake.DropSchema(ctx); err != nil {
			return fmt.Errorf("failed to drop schema: %w", err)
		}
		fmt.Println("Schema dropped")
	}

	fmt.Println("Creating schema and tables...")
	if err := application.Snowflake.Bootstrap(ctx); err != nil {
		return fmt.Errorf("failed to bootstrap: %w", err)
	}

	fmt.Println("Bootstrap complete. Created tables:")
	fmt.Println("  - findings")
	fmt.Println("  - tickets")
	fmt.Println("  - access_reviews")
	fmt.Println("  - review_items")
	fmt.Println("  - attack_path_nodes")
	fmt.Println("  - attack_path_edges")
	fmt.Println("  - attack_paths")
	fmt.Println("  - agent_sessions")
	fmt.Println("  - agent_messages")
	fmt.Println("  - provider_syncs")
	fmt.Println("  - audit_log")
	fmt.Println("  - webhooks")
	fmt.Println("  - webhook_deliveries")

	return nil
}
