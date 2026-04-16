package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/api"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/server"
)

var servePort int

func validateServeSecurityMode(cfg *app.Config) error {
	if cfg == nil || cfg.APIAuthEnabled || cfg.DevMode {
		return nil
	}
	return fmt.Errorf("api authentication is disabled; configure API_KEYS/API_AUTH_ENABLED=true or explicitly set CEREBRO_DEV_MODE=1 for local development")
}

func serveSecurityWarning(cfg *app.Config) string {
	if cfg == nil || !cfg.DevMode {
		return ""
	}
	return "DEV MODE: API authentication and rate limiting are disabled"
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	Long: `Start the Cerebro API server with graceful shutdown support.

The server will handle SIGINT and SIGTERM signals gracefully, allowing
in-flight requests to complete before shutting down. Send SIGHUP to
reload API keys, provider credentials, and Snowflake credentials without restart.

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

	reloadSigCh := make(chan os.Signal, 1)
	signal.Notify(reloadSigCh, syscall.SIGHUP)
	defer signal.Stop(reloadSigCh)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reloadSigCh:
				if err := application.ReloadSecrets(context.Background()); err != nil {
					application.Logger.Warn("failed to reload secrets on SIGHUP", "error", err)
				}
			}
		}
	}()

	if err := validateServeSecurityMode(application.Config); err != nil {
		return err
	}
	if warning := serveSecurityWarning(application.Config); warning != "" {
		application.Logger.Warn(warning)
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
			if syncer, ok := application.Findings.(interface{ Sync(context.Context) error }); ok {
				application.Logger.Info("syncing findings before shutdown")
				syncCtx, syncCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer syncCancel()
				return syncer.Sync(syncCtx)
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
