package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/api"
	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/server"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	Long: `Start the Cerebro API server with graceful shutdown support.

The server will handle SIGINT and SIGTERM signals gracefully, allowing
in-flight requests to complete before shutting down.

Examples:
  cerebro serve                 # Start on default port (API_PORT env or 8080)
  cerebro serve --port 9090     # Start on port 9090`,
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

	// Override port if specified via flag
	if servePort > 0 {
		application.Config.Port = servePort
	}

	if !application.Config.APIAuthEnabled {
		allowInsecure := false
		if raw := strings.TrimSpace(os.Getenv("ALLOW_INSECURE_API")); raw != "" {
			allowInsecure, _ = strconv.ParseBool(raw)
		}

		if !allowInsecure {
			return fmt.Errorf("api authentication is disabled; configure API_KEYS/API_AUTH_ENABLED=true or explicitly set ALLOW_INSECURE_API=true")
		}

		application.Logger.Warn("starting API server with authentication disabled")
	}

	// Start scheduler in background if configured
	schedulerCtx, schedulerCancel := context.WithCancel(ctx) // #nosec G118 -- schedulerCancel is invoked via server cleanup on shutdown
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
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 0, "Override the API port (default from API_PORT env or 8080)")
}
