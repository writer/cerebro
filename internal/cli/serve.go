package cli

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/api"
	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	Long: `Start the Cerebro API server with graceful shutdown support.

The server will handle SIGINT and SIGTERM signals gracefully, allowing
in-flight requests to complete before shutting down.`,
	RunE: runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	// Create a context that cancels on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize application
	application, err := app.New(ctx)
	if err != nil {
		return err
	}

	// Start scheduler in background if configured
	schedulerCtx, schedulerCancel := context.WithCancel(ctx)
	if application.Config.ScanInterval != "" {
		go application.Scheduler.Start(schedulerCtx)
	}

	// Create API server
	apiServer := api.NewServer(application)

	// Define cleanup functions
	cleanups := []server.CleanupFunc{
		func() error {
			schedulerCancel()
			if application.Scheduler != nil {
				application.Scheduler.Stop()
			}
			return nil
		},
		func() error {
			// Sync any dirty findings to Snowflake before shutdown
			if application.SnowflakeFindings != nil {
				application.Logger.Info("syncing findings to snowflake before shutdown")
				syncCtx, syncCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer syncCancel()
				return application.SnowflakeFindings.Sync(syncCtx)
			}
			return nil
		},
		application.Close,
	}

	// Run server with graceful shutdown
	cfg := server.DefaultConfig(application.Config.Port)
	return server.RunWithCleanup(ctx, apiServer, cfg, application.Logger, cleanups...)
}

func init() {
	// Add flags if needed
	serveCmd.Flags().IntP("port", "p", 0, "Override the API port (default from API_PORT env)")
}
