package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writerinternal/cerebro/internal/agents"
	"github.com/writerinternal/cerebro/internal/app"
	"github.com/writerinternal/cerebro/internal/jobs"
	"github.com/writerinternal/cerebro/internal/scm"
)

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Run the distributed job worker",
	RunE:  runWorker,
}

var (
	workerQueueURL          string
	workerTableName         string
	workerRegion            string
	workerConcurrency       int
	workerVisibilityTimeout string
	workerPollWait          string
)

func init() {
	rootCmd.AddCommand(workerCmd)

	workerCmd.Flags().StringVar(&workerQueueURL, "queue-url", "", "SQS queue URL")
	workerCmd.Flags().StringVar(&workerTableName, "table", "", "DynamoDB table name")
	workerCmd.Flags().StringVar(&workerRegion, "region", "", "AWS region override")
	workerCmd.Flags().IntVar(&workerConcurrency, "concurrency", 0, "Number of concurrent job workers")
	workerCmd.Flags().StringVar(&workerVisibilityTimeout, "visibility-timeout", "", "SQS visibility timeout (e.g. 30s)")
	workerCmd.Flags().StringVar(&workerPollWait, "poll-wait", "", "SQS long poll wait time (e.g. 10s)")
}

func runWorker(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer application.Close()

	queueURL := workerQueueURL
	if queueURL == "" {
		queueURL = application.Config.JobQueueURL
	}
	if queueURL == "" {
		return fmt.Errorf("queue url required")
	}

	tableName := workerTableName
	if tableName == "" {
		tableName = application.Config.JobTableName
	}
	if tableName == "" {
		return fmt.Errorf("table name required")
	}

	region := workerRegion
	if region == "" {
		region = application.Config.JobRegion
	}

	visibilityTimeout := application.Config.JobVisibilityTimeout
	if workerVisibilityTimeout != "" {
		parsed, err := time.ParseDuration(workerVisibilityTimeout)
		if err != nil {
			return err
		}
		visibilityTimeout = parsed
	}

	pollWait := application.Config.JobPollWait
	if workerPollWait != "" {
		parsed, err := time.ParseDuration(workerPollWait)
		if err != nil {
			return err
		}
		pollWait = parsed
	}

	concurrency := workerConcurrency
	if concurrency <= 0 {
		concurrency = application.Config.JobWorkerConcurrency
	}

	awsCfg, err := jobs.LoadAWSConfig(ctx, region)
	if err != nil {
		return err
	}

	queue := jobs.NewSQSQueue(awsCfg, queueURL)
	store := jobs.NewDynamoStore(awsCfg, tableName)
	tools := agents.NewSecurityTools(application.Snowflake, application.Findings, application.Policy, scm.NewGitHubClient(os.Getenv("GITHUB_TOKEN")))
	workerService := jobs.NewWorker(queue, store, tools, jobs.WorkerOptions{
		Concurrency:       concurrency,
		VisibilityTimeout: visibilityTimeout,
		PollWait:          pollWait,
		Logger:            application.Logger,
	})

	Info("Worker started (queue=%s table=%s)", queueURL, tableName)
	return workerService.Start(ctx)
}
