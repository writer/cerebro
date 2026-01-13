package cli

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/writerinternal/cerebro/internal/api"
	"github.com/writerinternal/cerebro/internal/app"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	RunE:  runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return err
	}
	defer application.Close()

	// Start scheduler in background if configured
	if application.Config.ScanInterval != "" {
		go application.Scheduler.Start(ctx)
		defer application.Scheduler.Stop()
	}

	server := api.NewServer(application)
	return server.Run()
}
