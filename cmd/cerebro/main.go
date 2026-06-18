package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/buildinfo"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
)

type usageError string

func (e usageError) Error() string {
	return string(e)
}

var (
	errServeAuthDisabled         = errors.New("api authentication disabled")
	errServeAuthMaterialRequired = errors.New("api authentication material required")
	errServeRateLimitDisabled    = errors.New("api rate limiting disabled")
)

func sanitizeLogValue(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(value)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		log.Print(sanitizeLogValue(fmt.Sprint(err)))
		os.Exit(1)
	}
}

func run(args []string) error {
	telemetry.ConfigureRuntimeMetadata(runtimeTelemetryMetadataFromEnv())
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "serve":
		return serve()
	case "graph":
		return runGraph(args[1:])
	case "orchestrator":
		return runOrchestrator(args[1:])
	case "finding-rule":
		return runFindingRule(args[1:])
	case "source":
		return runSource(args[1:])
	case "source-runtime":
		return runSourceRuntime(args[1:])
	case "vulndb":
		return runVulnDB(args[1:])
	case "closeout":
		return runCloseout(args[1:])
	case "deploy":
		return runDeploy(args[1:])
	case "version":
		fmt.Printf("%s %s\n", buildinfo.ServiceName, buildinfo.Version)
		return nil
	}
	return usageError(fmt.Sprintf("usage: %s [serve|version|deploy|graph|orchestrator|finding-rule|source|source-runtime|vulndb|closeout]", os.Args[0]))
}

func serve() error {
	cfg, err := appconfig.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := validateServeConfig(cfg); err != nil {
		return err
	}
	if cfg.DevMode {
		log.Print("WARN DEV MODE: API authentication and rate limiting are disabled")
	}
	closeTelemetry, err := configureOpenTelemetry(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	defer shutdownTelemetry(context.Background(), closeTelemetry, cfg.ShutdownTimeout)
	deps, closeDeps, err := bootstrap.OpenDependencies(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	sources, err := sourceregistry.Builtin()
	if err != nil {
		return fmt.Errorf("open source registry: %w", err)
	}

	app, err := bootstrap.NewWithError(cfg, deps, sources)
	if err != nil {
		return fmt.Errorf("bootstrap app: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	grcWarmupDone := startGRCReadModelWarmup(ctx, deps.StateStore, log.Printf)
	riskBackfillDone := startFindingRiskBackfill(ctx, app, log.Printf)

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := app.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		if err := <-errCh; err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		waitForStartupJobs(shutdownCtx, grcWarmupDone, riskBackfillDone)
		return nil
	}
}

func validateServeConfig(cfg appconfig.Config) error {
	if cfg.DevMode {
		return nil
	}
	if !cfg.Auth.Enabled {
		return fmt.Errorf("%w; set CEREBRO_DEV_MODE=1 and CEREBRO_DEV_MODE_ACK=1 only for local development", errServeAuthDisabled)
	}
	if !cfg.Auth.HasCredentialMaterial() {
		return fmt.Errorf("%w; configure CEREBRO_API_KEYS, CEREBRO_API_CREDENTIALS_JSON, or CEREBRO_CAPABILITY_TOKEN_SECRETS, or set CEREBRO_DEV_MODE=1 and CEREBRO_DEV_MODE_ACK=1 only for local development", errServeAuthMaterialRequired)
	}
	if !cfg.RateLimit.Enabled {
		return fmt.Errorf("%w; set CEREBRO_DEV_MODE=1 and CEREBRO_DEV_MODE_ACK=1 only for local development", errServeRateLimitDisabled)
	}
	return nil
}

func configureOpenTelemetry(ctx context.Context, cfg appconfig.Config) (telemetry.ShutdownFunc, error) {
	return telemetry.ConfigureOpenTelemetry(ctx, telemetry.OpenTelemetryOptions{
		Enabled:         cfg.OTEL.Enabled,
		ServiceName:     firstNonEmptyString(cfg.OTEL.ServiceName, buildinfo.ServiceName),
		ServiceVersion:  buildinfo.Version,
		Protocol:        cfg.OTEL.Protocol,
		Endpoint:        cfg.OTEL.Endpoint,
		TracesEndpoint:  cfg.OTEL.TracesEndpoint,
		MetricsEndpoint: cfg.OTEL.MetricsEndpoint,
		Headers:         cfg.OTEL.Headers,
		Insecure:        cfg.OTEL.Insecure,
		TraceSampleRate: cfg.OTEL.TraceSampleRate,
		MetricInterval:  cfg.OTEL.MetricInterval,
	})
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func runtimeTelemetryMetadataFromEnv() telemetry.RuntimeMetadata {
	return telemetry.RuntimeMetadata{
		ResourceAttributes: os.Getenv("OTEL_RESOURCE_ATTRIBUTES"),
		ServiceName: firstNonEmptyString(
			os.Getenv("CEREBRO_OTEL_SERVICE_NAME"),
			os.Getenv("OTEL_SERVICE_NAME"),
		),
		DeploymentEnvironment: firstNonEmptyString(
			os.Getenv("CEREBRO_DEPLOYMENT_ENVIRONMENT"),
			os.Getenv("CEREBRO_ENVIRONMENT"),
			os.Getenv("OTEL_ENVIRONMENT_NAME"),
			os.Getenv("ENVIRONMENT"),
			os.Getenv("APP_ENV"),
		),
		CloudRegion: firstNonEmptyString(
			os.Getenv("AWS_REGION"),
			os.Getenv("AWS_DEFAULT_REGION"),
		),
		ContainerID: firstNonEmptyString(
			os.Getenv("ECS_CONTAINER_ID"),
			os.Getenv("HOSTNAME"),
		),
		ECSContainerMetadataURI: firstNonEmptyString(
			os.Getenv("ECS_CONTAINER_METADATA_URI_V4"),
			os.Getenv("ECS_CONTAINER_METADATA_URI"),
		),
		AWSExecutionEnvironment: os.Getenv("AWS_EXECUTION_ENV"),
	}
}

func shutdownTelemetry(ctx context.Context, closeTelemetry telemetry.ShutdownFunc, timeout time.Duration) {
	if closeTelemetry == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := closeTelemetry(ctx); err != nil {
		log.Printf("shutdown telemetry: %v", err)
	}
}

func waitForStartupJobs(ctx context.Context, jobs ...<-chan struct{}) {
	for _, job := range jobs {
		if job == nil {
			continue
		}
		select {
		case <-job:
		case <-ctx.Done():
			return
		}
	}
}

type findingRiskBackfiller interface {
	BackfillFindingRisk(context.Context) error
}

type grcReadModelPreparer interface {
	PrepareGRCReadModels(context.Context) error
}

func prepareGRCReadModels(ctx context.Context, stateStore ports.StateStore) error {
	preparer, ok := stateStore.(grcReadModelPreparer)
	if !ok {
		return nil
	}
	if err := preparer.PrepareGRCReadModels(ctx); err != nil {
		return fmt.Errorf("prepare grc read models: %w", err)
	}
	return nil
}

func startGRCReadModelWarmup(ctx context.Context, stateStore ports.StateStore, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, hasPreparer := stateStore.(grcReadModelPreparer)
		ctx, span := telemetry.StartMain(ctx, "grc.read_model_warmup", telemetry.Attrs(
			telemetry.Field{Key: "preparer_present", Value: hasPreparer},
		))
		status := "completed"
		attrs := telemetry.Attrs(telemetry.Field{Key: "preparer_present", Value: hasPreparer})
		if !hasPreparer {
			status = "skipped"
		}
		defer func() {
			telemetry.End(span, status, attrs)
		}()
		if err := prepareGRCReadModels(ctx, stateStore); err != nil && ctx.Err() == nil {
			status = "failed"
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: "grc_read_model_warmup_failed"})
			logf("%v", err)
		} else if ctx.Err() != nil {
			status = "canceled"
		}
	}()
	return done
}

func startFindingRiskBackfill(ctx context.Context, backfiller findingRiskBackfiller, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	if backfiller == nil {
		_, span := telemetry.StartMain(ctx, "finding.risk_backfill", telemetry.Attrs(
			telemetry.Field{Key: "backfiller_present", Value: false},
		))
		telemetry.End(span, "skipped", telemetry.Attrs(telemetry.Field{Key: "backfiller_present", Value: false}))
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ctx, span := telemetry.StartMain(ctx, "finding.risk_backfill", telemetry.Attrs(
			telemetry.Field{Key: "backfiller_present", Value: true},
		))
		status := "completed"
		attrs := telemetry.Attrs(telemetry.Field{Key: "backfiller_present", Value: true})
		defer func() {
			telemetry.End(span, status, attrs)
		}()
		if err := backfiller.BackfillFindingRisk(ctx); err != nil && ctx.Err() == nil {
			status = "failed"
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: "finding_risk_backfill_failed"})
			logf("backfill finding risk: %v", err)
		} else if ctx.Err() != nil {
			status = "canceled"
		}
	}()
	return done
}

func runSource(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s source [list|check|discover|read] ...", os.Args[0]))
	}
	ctx := context.Background()
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return fmt.Errorf("open source registry: %w", err)
	}
	service := sourceops.New(registry)

	switch args[0] {
	case "list":
		return printProto(service.List())
	case "check":
		sourceID, config, _, err := parseSourceCommandArgs(args[1:])
		if err != nil {
			return err
		}
		config, err = prepareSourceConfig(ctx, sourceID, "check", config)
		if err != nil {
			return err
		}
		config, err = appconfig.ResolveSourceConfigSecretReferences(ctx, sourceID, config)
		if err != nil {
			return err
		}
		response, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
			SourceId: sourceID,
			Config:   config,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	case "discover":
		sourceID, config, _, err := parseSourceCommandArgs(args[1:])
		if err != nil {
			return err
		}
		config, err = prepareSourceConfig(ctx, sourceID, "discover", config)
		if err != nil {
			return err
		}
		config, err = appconfig.ResolveSourceConfigSecretReferences(ctx, sourceID, config)
		if err != nil {
			return err
		}
		response, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
			SourceId: sourceID,
			Config:   config,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	case "read":
		sourceID, config, cursor, err := parseSourceCommandArgs(args[1:])
		if err != nil {
			return err
		}
		config, err = prepareSourceConfig(ctx, sourceID, "read", config)
		if err != nil {
			return err
		}
		config, err = appconfig.ResolveSourceConfigSecretReferences(ctx, sourceID, config)
		if err != nil {
			return err
		}
		response, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
			SourceId: sourceID,
			Config:   config,
			Cursor:   cursor,
		})
		if err != nil {
			return err
		}
		return printProto(response)
	default:
		return usageError(fmt.Sprintf("usage: %s source [list|check|discover|read] ...", os.Args[0]))
	}
}

func runSourceRuntime(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf("usage: %s source-runtime [put|get|list|sync|bootstrap|sdk] ...", os.Args[0]))
	}
	if args[0] == "sdk" {
		return runSourceRuntimeSDK(args[1:])
	}
	cfg, err := appconfig.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	ctx, stop := sourceRuntimeCommandContext()
	defer stop()
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	defer shutdownTelemetry(context.Background(), closeTelemetry, cfg.ShutdownTimeout)
	openDependencies := bootstrap.OpenDependencies
	if args[0] == "bootstrap" {
		openDependencies = bootstrap.OpenSourceRuntimeBootstrapDependencies
	}
	deps, closeDeps, err := openDependencies(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return fmt.Errorf("open source registry: %w", err)
	}
	service := configureSourceRuntimeCommandService(sourceruntime.New(
		registry,
		sourceRuntimeStore(deps.StateStore),
		deps.AppendLog,
		sourceProjector(deps.StateStore, deps.GraphStore),
	))

	switch args[0] {
	case "bootstrap":
		runtimes, err := parseSourceRuntimeBootstrapArgs(args[1:])
		if err != nil {
			return err
		}
		for index, runtime := range runtimes {
			runtime, err = prepareSourceRuntime(ctx, runtime)
			if err != nil {
				return fmt.Errorf("source runtime bootstrap runtimes[%d]: %w", index, err)
			}
			runtimes[index] = runtime
		}
		response, err := service.PutRuntimes(ctx, sourceruntime.PutRuntimesRequest{Runtimes: runtimes})
		if err != nil {
			return err
		}
		payload, err := sourceRuntimeListJSON(response.Runtimes)
		if err != nil {
			return err
		}
		return printJSON(payload)
	case "put":
		runtime, err := parseSourceRuntimePutArgs(args[1:])
		if err != nil {
			return err
		}
		runtime, err = prepareSourceRuntime(ctx, runtime)
		if err != nil {
			return err
		}
		response, err := service.Put(ctx, &cerebrov1.PutSourceRuntimeRequest{Runtime: runtime})
		if err != nil {
			return err
		}
		return printProto(response)
	case "get":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return usageError(fmt.Sprintf("usage: %s source-runtime get <runtime-id>", os.Args[0]))
		}
		response, err := service.Get(ctx, &cerebrov1.GetSourceRuntimeRequest{Id: strings.TrimSpace(args[1])})
		if err != nil {
			return err
		}
		return printProto(response)
	case "list":
		filter, err := parseSourceRuntimeListArgs(args[1:])
		if err != nil {
			return err
		}
		runtimes, err := service.List(ctx, filter)
		if err != nil {
			return err
		}
		payload, err := sourceRuntimeListJSON(runtimes)
		if err != nil {
			return err
		}
		return printJSON(payload)
	case "sync":
		runtimeID, pageLimit, err := parseSourceRuntimeSyncArgs(args[1:])
		if err != nil {
			return err
		}
		response, err := service.SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{
			Id:        runtimeID,
			PageLimit: pageLimit,
		}, sourceruntime.SyncWithLeaseOptions{
			LeaseStore: sourceRuntimeCommandLeaseStore(deps.StateStore),
			LeaseOwner: sourceRuntimeCommandLeaseOwner(),
		})
		if err != nil {
			return err
		}
		return printProto(response)
	default:
		return usageError(fmt.Sprintf("usage: %s source-runtime [put|get|list|sync|bootstrap|sdk] ...", os.Args[0]))
	}
}

func configureSourceRuntimeCommandService(service *sourceruntime.Service) *sourceruntime.Service {
	return service.WithConfigResolver(appconfig.ResolveSourceRuntimeConfigSecretReferences)
}

func sourceRuntimeCommandLeaseStore(store ports.StateStore) ports.SourceRuntimeLeaseStore {
	leaseStore, ok := store.(ports.SourceRuntimeLeaseStore)
	if !ok {
		return nil
	}
	return leaseStore
}

func sourceRuntimeCommandLeaseOwner() string {
	return strings.Replace(sourceruntime.DefaultAPILeaseOwner(), "cerebro-api:", "cerebro-cli:", 1)
}

func sourceRuntimeCommandContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), sourceRuntimeCommandSignals()...)
}

func sourceRuntimeCommandSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func parseSourceCommandArgs(args []string) (string, map[string]string, *cerebrov1.SourceCursor, error) {
	if len(args) == 0 {
		return "", nil, nil, usageError(fmt.Sprintf("usage: %s source <command> <source-id> [key=value ...]", os.Args[0]))
	}
	config := make(map[string]string)
	var cursor *cerebrov1.SourceCursor
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", nil, nil, fmt.Errorf("invalid source argument %q; want key=value", arg)
		}
		if key == "cursor" {
			cursor = &cerebrov1.SourceCursor{Opaque: value}
			continue
		}
		resolved, err := sourceConfigValueFromArg(key, value)
		if err != nil {
			return "", nil, nil, err
		}
		config[key] = resolved
	}
	return args[0], config, cursor, nil
}

func parseSourceRuntimePutArgs(args []string) (*cerebrov1.SourceRuntime, error) {
	if len(args) < 2 {
		return nil, usageError(fmt.Sprintf("usage: %s source-runtime put <runtime-id> <source-id> [tenant_id=<tenant-id>] [key=value ...]", os.Args[0]))
	}
	runtime := &cerebrov1.SourceRuntime{
		Id:       strings.TrimSpace(args[0]),
		SourceId: strings.TrimSpace(args[1]),
		Config:   make(map[string]string),
	}
	if runtime.GetId() == "" || runtime.GetSourceId() == "" {
		return nil, usageError(fmt.Sprintf("usage: %s source-runtime put <runtime-id> <source-id> [tenant_id=<tenant-id>] [key=value ...]", os.Args[0]))
	}
	for _, arg := range args[2:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, fmt.Errorf("invalid source runtime argument %q; want key=value", arg)
		}
		if key == "tenant_id" {
			runtime.TenantId = strings.TrimSpace(value)
			continue
		}
		resolved, err := sourceConfigValueFromArg(key, value)
		if err != nil {
			return nil, err
		}
		runtime.Config[key] = resolved
	}
	return runtime, nil
}

func parseSourceRuntimeBootstrapArgs(args []string) ([]*cerebrov1.SourceRuntime, error) {
	if len(args) != 1 {
		return nil, usageError(fmt.Sprintf("usage: %s source-runtime bootstrap env=<env-var>", os.Args[0]))
	}
	key, value, ok := strings.Cut(args[0], "=")
	envName := strings.TrimSpace(value)
	if !ok || key != "env" || envName == "" {
		return nil, usageError(fmt.Sprintf("usage: %s source-runtime bootstrap env=<env-var>", os.Args[0]))
	}
	payload, ok := os.LookupEnv(envName)
	if !ok {
		return nil, fmt.Errorf("source runtime bootstrap env %q is unset", envName)
	}
	return parseSourceRuntimeBootstrapJSON(payload)
}

func parseSourceRuntimeBootstrapJSON(payload string) ([]*cerebrov1.SourceRuntime, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("source runtime bootstrap payload is empty")
	}
	rawRuntimes, err := sourceRuntimeBootstrapRawMessages(payload)
	if err != nil {
		return nil, err
	}
	if len(rawRuntimes) == 0 {
		return nil, fmt.Errorf("source runtime bootstrap payload must include at least one runtime")
	}
	runtimes := make([]*cerebrov1.SourceRuntime, 0, len(rawRuntimes))
	seenRuntimeIDs := make(map[string]struct{}, len(rawRuntimes))
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: false}
	for index, raw := range rawRuntimes {
		var runtime cerebrov1.SourceRuntime
		if err := unmarshaler.Unmarshal(raw, &runtime); err != nil {
			return nil, fmt.Errorf("parse source runtime bootstrap runtimes[%d]: %w", index, err)
		}
		if err := normalizeBootstrapSourceRuntime(&runtime); err != nil {
			return nil, fmt.Errorf("source runtime bootstrap runtimes[%d]: %w", index, err)
		}
		if _, ok := seenRuntimeIDs[runtime.GetId()]; ok {
			return nil, fmt.Errorf("source runtime bootstrap runtimes[%d]: duplicate runtime id %q", index, runtime.GetId())
		}
		seenRuntimeIDs[runtime.GetId()] = struct{}{}
		runtimes = append(runtimes, &runtime)
	}
	return runtimes, nil
}

func sourceRuntimeBootstrapRawMessages(payload string) ([]json.RawMessage, error) {
	if strings.HasPrefix(payload, "[") {
		var runtimes []json.RawMessage
		if err := json.Unmarshal([]byte(payload), &runtimes); err != nil {
			return nil, fmt.Errorf("parse source runtime bootstrap payload: %w", err)
		}
		return runtimes, nil
	}
	var document struct {
		Runtimes []json.RawMessage `json:"runtimes"`
	}
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		return nil, fmt.Errorf("parse source runtime bootstrap payload: %w", err)
	}
	return document.Runtimes, nil
}

func normalizeBootstrapSourceRuntime(runtime *cerebrov1.SourceRuntime) error {
	runtime.Id = strings.TrimSpace(runtime.GetId())
	runtime.SourceId = strings.TrimSpace(runtime.GetSourceId())
	runtime.TenantId = strings.TrimSpace(runtime.GetTenantId())
	runtime.Checkpoint = nil
	runtime.NextCursor = nil
	runtime.LastSyncedAt = nil
	if runtime.GetId() == "" || runtime.GetSourceId() == "" {
		return usageError(fmt.Sprintf("usage: %s source-runtime bootstrap env=<env-var>", os.Args[0]))
	}
	if runtime.Config == nil {
		runtime.Config = make(map[string]string)
	}
	for key, value := range runtime.GetConfig() {
		normalized, err := sourceConfigValueFromArg(key, value)
		if err != nil {
			return err
		}
		runtime.Config[key] = normalized
	}
	return nil
}

func sourceConfigValueFromArg(key string, value string) (string, error) {
	sensitive := sensitiveCLIConfigKey(key)
	if strings.HasPrefix(value, "env:") && !sourceconfig.LiteralEnvPrefixKey(key) {
		return value, nil
	}
	if sensitive && strings.TrimSpace(value) != "" {
		return "", fmt.Errorf("source config %q is sensitive; pass env:VAR instead of a literal value", strings.TrimSpace(key))
	}
	return value, nil
}

func sensitiveCLIConfigKey(key string) bool {
	return sourceconfig.SensitiveKey(key)
}

func parseSourceRuntimeSyncArgs(args []string) (string, uint32, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", 0, usageError(fmt.Sprintf("usage: %s source-runtime sync <runtime-id> [page_limit=N]", os.Args[0]))
	}
	runtimeID := strings.TrimSpace(args[0])
	var pageLimit uint32
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", 0, fmt.Errorf("invalid source runtime argument %q; want key=value", arg)
		}
		if key != "page_limit" {
			return "", 0, fmt.Errorf("unsupported source runtime argument %q", key)
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return "", 0, fmt.Errorf("parse page_limit: %w", err)
		}
		pageLimit = uint32(parsed)
	}
	return runtimeID, pageLimit, nil
}

func parseSourceRuntimeListArgs(args []string) (ports.SourceRuntimeFilter, error) {
	var filter ports.SourceRuntimeFilter
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return ports.SourceRuntimeFilter{}, fmt.Errorf("invalid source runtime list argument %q; want key=value", arg)
		}
		switch key {
		case "runtime_id":
			filter.RuntimeID = strings.TrimSpace(value)
		case "tenant_id":
			filter.TenantID = strings.TrimSpace(value)
		case "source_id":
			filter.SourceID = strings.TrimSpace(value)
		case "limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return ports.SourceRuntimeFilter{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed == 0 {
				return ports.SourceRuntimeFilter{}, fmt.Errorf("limit must be at least 1")
			}
			filter.Limit = uint32(parsed)
		default:
			return ports.SourceRuntimeFilter{}, fmt.Errorf("unsupported source runtime list argument %q", key)
		}
	}
	return filter, nil
}

func sourceRuntimeListJSON(runtimes []*cerebrov1.SourceRuntime) (map[string][]json.RawMessage, error) {
	items := make([]json.RawMessage, 0, len(runtimes))
	marshaler := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}
	for _, runtime := range runtimes {
		payload, err := marshaler.Marshal(runtime)
		if err != nil {
			return nil, fmt.Errorf("marshal source runtime: %w", err)
		}
		items = append(items, json.RawMessage(payload))
	}
	return map[string][]json.RawMessage{"runtimes": items}, nil
}

func sourceRuntimeStore(store ports.StateStore) ports.SourceRuntimeStore {
	runtimeStore, ok := store.(ports.SourceRuntimeStore)
	if !ok {
		return nil
	}
	return runtimeStore
}

func sourceProjectionStateStore(store ports.StateStore) ports.ProjectionStateStore {
	projectionStore, ok := store.(ports.ProjectionStateStore)
	if !ok {
		return nil
	}
	return projectionStore
}

func sourceProjectionGraphStore(store ports.GraphStore) ports.ProjectionGraphStore {
	projectionStore, ok := store.(ports.ProjectionGraphStore)
	if !ok {
		return nil
	}
	return projectionStore
}

func sourceProjector(stateStore ports.StateStore, graphStore ports.GraphStore) ports.SourceProjector {
	state := sourceProjectionStateStore(stateStore)
	graph := sourceProjectionGraphStore(graphStore)
	if state == nil && graph == nil {
		return nil
	}
	return sourceprojection.New(state, graph)
}

func printProto(message proto.Message) error {
	payload, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	if _, err := os.Stdout.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
