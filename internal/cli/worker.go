package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/jobs"
	providerregistry "github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/scm"
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

	runNativeSyncForJobFn           = runNativeSyncForJob
	syncConfiguredProviderSourcesFn = syncConfiguredProviderSources
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
	registry.Register(jobs.JobTypeNativeSync, newNativeSyncJobHandler(application))

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

	workerOpts := jobs.WorkerOptions{
		Concurrency:       concurrency,
		VisibilityTimeout: visibilityTimeout,
		JobTimeout:        jobTimeout,
		DrainTimeout:      drainTimeout,
		PollWait:          pollWait,
		Logger:            application.Logger,
		Metrics:           metrics,
		CircuitBreaker:    circuit,
	}

	idempotencyTable := application.Config.JobIdempotencyTableName
	if idempotencyTable != "" {
		workerOpts.Idempotency = jobs.NewDynamoIdempotencyStore(awsCfg, idempotencyTable)
		application.Logger.Info("idempotency store enabled", "table", idempotencyTable)
	} else {
		application.Logger.Warn("no JOB_IDEMPOTENCY_TABLE_NAME configured; running without idempotency protection")
	}

	workerService := jobs.NewWorker(queue, store, registry, workerOpts)

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

func newNativeSyncJobHandler(application *app.App) jobs.JobHandler {
	return func(ctx context.Context, payload string) (string, error) {
		var logger *slog.Logger
		if application != nil {
			logger = application.Logger
		}

		var req jobs.NativeSyncPayload
		if err := json.Unmarshal([]byte(payload), &req); err != nil {
			return "", fmt.Errorf("decode native sync payload: %w", err)
		}

		provider := strings.ToLower(strings.TrimSpace(req.Provider))
		if !isNativeScheduleProvider(provider) {
			return "", fmt.Errorf("unsupported native sync provider %q", req.Provider)
		}

		schedule := &SyncSchedule{
			Name:     req.ScheduleName,
			Provider: provider,
			Table:    req.Table,
		}

		err := runNativeSyncForJobFn(ctx, provider, schedule)
		if err != nil {
			return "", err
		}

		syncedProviders, failedProviders, err := syncConfiguredProviderSourcesFn(ctx, application, logger)
		if err != nil {
			return "", err
		}

		if logger != nil {
			if len(failedProviders) > 0 {
				logger.Warn(
					"native sync completed with additional provider sync failures",
					"provider", provider,
					"schedule", req.ScheduleName,
					"additional_provider_count", len(syncedProviders),
					"failed_provider_count", len(failedProviders),
				)
			} else {
				logger.Info("native sync job completed", "provider", provider, "schedule", req.ScheduleName, "additional_provider_count", len(syncedProviders))
			}
		}

		result, err := json.Marshal(map[string]interface{}{
			"provider":                    provider,
			"table":                       req.Table,
			"schedule_name":               req.ScheduleName,
			"additional_providers":        syncedProviders,
			"failed_additional_providers": failedProviders,
		})
		if err != nil {
			return "", err
		}

		return string(result), nil
	}
}

func runNativeSyncForJob(ctx context.Context, provider string, schedule *SyncSchedule) error {
	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	switch provider {
	case "aws":
		return executeAWSSync(ctx, client, schedule)
	case "gcp":
		return executeGCPSync(ctx, client, schedule)
	case "azure":
		return executeAzureSync(ctx, client, schedule)
	default:
		return fmt.Errorf("unsupported native sync provider %q", provider)
	}
}

type providerSyncFailure struct {
	Provider string `json:"provider"`
	Error    string `json:"error"`
}

func syncConfiguredProviderSources(ctx context.Context, application *app.App, logger *slog.Logger) ([]string, []providerSyncFailure, error) {
	if application == nil || application.Providers == nil {
		return nil, nil, nil
	}

	providers := application.Providers.List()
	if len(providers) == 0 {
		return nil, nil, nil
	}

	synced := make([]string, 0, len(providers))
	failed := make([]providerSyncFailure, 0)

	for _, provider := range providers {
		if err := ctx.Err(); err != nil {
			return synced, failed, err
		}

		if provider == nil {
			continue
		}

		name := strings.ToLower(strings.TrimSpace(provider.Name()))
		if name == "" || isNativeScheduleProvider(name) {
			continue
		}

		if logger != nil {
			logger.Info("running configured provider sync", "provider", name)
		}

		result, err := provider.Sync(ctx, providerregistry.SyncOptions{FullSync: true})
		if err != nil {
			failed = append(failed, providerSyncFailure{
				Provider: name,
				Error:    fmt.Sprintf("%s sync failed: %v", name, err),
			})
			if logger != nil {
				logger.Warn("configured provider sync failed", "provider", name, "error", err)
			}
			continue
		}

		if result != nil && len(result.Errors) > 0 {
			message := fmt.Sprintf("%s sync reported errors: %s", name, strings.Join(result.Errors, "; "))
			failed = append(failed, providerSyncFailure{
				Provider: name,
				Error:    message,
			})
			if logger != nil {
				logger.Warn("configured provider sync reported errors", "provider", name, "errors", strings.Join(result.Errors, "; "))
			}
			continue
		}

		synced = append(synced, name)
	}

	sort.Strings(synced)
	sort.Slice(failed, func(i, j int) bool {
		return failed[i].Provider < failed[j].Provider
	})

	return synced, failed, nil
}
