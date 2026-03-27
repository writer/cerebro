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

	workerCmd.Flags().IntVar(&workerConcurrency, "concurrency", 0, "Number of concurrent job workers")
	workerCmd.Flags().StringVar(&workerVisibilityTimeout, "visibility-timeout", "", "Queue visibility timeout (e.g. 60s)")
	workerCmd.Flags().StringVar(&workerJobTimeout, "job-timeout", "", "Maximum time per job (e.g. 5m)")
	workerCmd.Flags().StringVar(&workerDrainTimeout, "drain-timeout", "", "Graceful shutdown drain timeout (e.g. 30s)")
	workerCmd.Flags().StringVar(&workerPollWait, "poll-wait", "", "Queue poll wait time (e.g. 20s)")
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
	if !distributedJobsConfigured(application.Config) {
		return fmt.Errorf("JOB_DATABASE_URL is required")
	}

	runtime, err := openJobRuntime(ctx, application.Config)
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()

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
		WorkerID:  fmt.Sprintf("worker-%s", summarizeDatabaseTarget(application.Config.JobDatabaseURL)),
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

	idempStore, err := runtime.newIdempotencyStore(ctx)
	if err != nil {
		return err
	}
	workerOpts.Idempotency = idempStore

	workerService := jobs.NewWorker(runtime.queue, runtime.store, registry, workerOpts)

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

	Info("Worker started (db=%s stream=%s subject=%s concurrency=%d health=:%d)", summarizeDatabaseTarget(application.Config.JobDatabaseURL), application.Config.JobNATSStream, application.Config.JobNATSSubject, concurrency, workerHealthPort)
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

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return nil, nil, err
	}

	var apiClient interface {
		SyncProvider(context.Context, string) (*providerregistry.SyncResult, error)
	}
	apiEnabled := mode != cliExecutionModeDirect
	if apiEnabled {
		client, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return nil, nil, err
			}
			apiEnabled = false
			if logger != nil {
				logger.Warn("api client configuration invalid; using direct provider sync mode", "error", err)
			}
		} else {
			apiClient = client
		}
	}

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

		if apiEnabled && apiClient != nil {
			result, err := apiClient.SyncProvider(ctx, name)
			if err == nil {
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
				continue
			}

			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				failed = append(failed, providerSyncFailure{
					Provider: name,
					Error:    fmt.Sprintf("%s sync via api failed: %v", name, err),
				})
				if logger != nil {
					logger.Warn("configured provider sync via api failed", "provider", name, "error", err)
				}
				continue
			}

			if logger != nil {
				logger.Warn("api unavailable; using direct mode for configured provider sync", "provider", name, "error", err)
			}
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
