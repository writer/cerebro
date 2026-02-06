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
	workerJobTimeout        string
	workerDrainTimeout      string
	workerPollWait          string
	workerHealthPort        int
)

func init() {
	rootCmd.AddCommand(workerCmd)

	workerCmd.Flags().StringVar(&workerQueueURL, "queue-url", "", "SQS queue URL")
	workerCmd.Flags().StringVar(&workerTableName, "table", "", "DynamoDB table name")
	workerCmd.Flags().StringVar(&workerRegion, "region", "", "AWS region override")
	workerCmd.Flags().IntVar(&workerConcurrency, "concurrency", 0, "Number of concurrent job workers")
	workerCmd.Flags().StringVar(&workerVisibilityTimeout, "visibility-timeout", "", "SQS visibility timeout (e.g. 60s)")
	workerCmd.Flags().StringVar(&workerJobTimeout, "job-timeout", "", "Maximum time per job (e.g. 5m)")
	workerCmd.Flags().StringVar(&workerDrainTimeout, "drain-timeout", "", "Graceful shutdown drain timeout (e.g. 30s)")
	workerCmd.Flags().StringVar(&workerPollWait, "poll-wait", "", "SQS long poll wait time (e.g. 20s)")
	workerCmd.Flags().IntVar(&workerHealthPort, "health-port", 8081, "HTTP port for health check endpoints")
}

func runWorker(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer func() { _ = application.Close() }()

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
		visParsed, viErr := time.ParseDuration(workerVisibilityTimeout)
		if viErr != nil {
			return viErr
		}
		visibilityTimeout = visParsed
	}

	pollWait := application.Config.JobPollWait
	if workerPollWait != "" {
		pollParsed, pollErr := time.ParseDuration(workerPollWait)
		if pollErr != nil {
			return pollErr
		}
		pollWait = pollParsed
	}

	var jobTimeout time.Duration
	if workerJobTimeout != "" {
		jobParsed, jobErr := time.ParseDuration(workerJobTimeout)
		if jobErr != nil {
			return jobErr
		}
		jobTimeout = jobParsed
	}

	var drainTimeout time.Duration
	if workerDrainTimeout != "" {
		drainParsed, drainErr := time.ParseDuration(workerDrainTimeout)
		if drainErr != nil {
			return drainErr
		}
		drainTimeout = drainParsed
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

	// Create security tools for job execution
	tools := agents.NewSecurityTools(
		application.Snowflake,
		application.Findings,
		application.Policy,
		scm.NewConfiguredClient(
			application.Config.GitHubToken,
			application.Config.GitLabToken,
			application.Config.GitLabBaseURL,
		),
	)

	// Create job registry and register handlers
	registry := jobs.NewJobRegistry()
	registry.Register(jobs.JobTypeInspectResource, jobs.NewInspectResourceHandler(tools))

	// Create metrics collector
	metrics := jobs.NewMetrics(application.Logger, jobs.MetricsConfig{
		Namespace: "Cerebro/Worker",
		WorkerID:  fmt.Sprintf("worker-%s", region),
	})

	// Create circuit breaker
	circuit := jobs.NewCircuitBreaker(jobs.CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
	})

	workerService := jobs.NewWorker(queue, store, registry, jobs.WorkerOptions{
		Concurrency:       concurrency,
		VisibilityTimeout: visibilityTimeout,
		JobTimeout:        jobTimeout,
		DrainTimeout:      drainTimeout,
		PollWait:          pollWait,
		Logger:            application.Logger,
		Metrics:           metrics,
		CircuitBreaker:    circuit,
	})

	// Start health check server
	healthServer := jobs.NewHealthServer(workerService, fmt.Sprintf(":%d", workerHealthPort), application.Logger)
	if err := healthServer.Start(); err != nil {
		return fmt.Errorf("failed to start health server: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = healthServer.Shutdown(shutdownCtx)
	}()

	Info("Worker started (queue=%s table=%s concurrency=%d health=:%d)", queueURL, tableName, concurrency, workerHealthPort)
	return workerService.Start(ctx)
}
