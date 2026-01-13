package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/writerinternal/cerebro/internal/api"
	"github.com/writerinternal/cerebro/internal/config"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/snowflake"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	RunE:  runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg := config.Load()

	policyEngine := policy.NewEngine()
	if err := policyEngine.LoadPolicies(cfg.CedarPoliciesPath); err != nil {
		logger.Warn("failed to load policies", "error", err)
	} else {
		logger.Info("loaded policies", "count", len(policyEngine.ListPolicies()))
	}

	var sfClient *snowflake.Client
	if cfg.SnowflakeConnection != "" {
		var err error
		sfClient, err = snowflake.NewClient(cfg.SnowflakeConnection, cfg.SnowflakeDatabase, cfg.SnowflakeSchema)
		if err != nil {
			logger.Warn("failed to connect to snowflake", "error", err)
		} else {
			logger.Info("connected to snowflake")
			defer sfClient.Close()
		}
	}

	server := api.NewServer(cfg, sfClient, policyEngine, logger)
	return server.Run()
}
