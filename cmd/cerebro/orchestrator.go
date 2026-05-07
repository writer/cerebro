package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
)

const defaultOrchestratorIterations = 1
const defaultSourceRuntimeLeaseTTL = 30 * time.Minute
const sourceRuntimeLeaseReleaseTimeout = 5 * time.Second
const sourceRuntimeLeaseOverscanLimit = 100

type orchestratorOptions struct {
	Filter         ports.SourceRuntimeFilter `json:"filter"`
	PageLimit      uint32                    `json:"page_limit,omitempty"`
	EventLimit     uint32                    `json:"event_limit,omitempty"`
	GraphPageLimit uint32                    `json:"graph_page_limit,omitempty"`
	Interval       time.Duration             `json:"-"`
	Iterations     uint32                    `json:"iterations"`
	RunForever     bool                      `json:"run_forever,omitempty"`
}

type orchestratorResult struct {
	Iterations uint32                         `json:"iterations"`
	RunForever bool                           `json:"run_forever,omitempty"`
	Interval   string                         `json:"interval,omitempty"`
	Runs       []*orchestratorIterationResult `json:"runs"`
}

type orchestratorIterationResult struct {
	Iteration uint32                       `json:"iteration"`
	StartedAt time.Time                    `json:"started_at"`
	Runtimes  []*orchestratorRuntimeResult `json:"runtimes"`
}

type orchestratorRuntimeResult struct {
	RuntimeID          string `json:"runtime_id"`
	SourceID           string `json:"source_id,omitempty"`
	TenantID           string `json:"tenant_id,omitempty"`
	Sync               string `json:"sync"`
	PagesRead          uint32 `json:"pages_read,omitempty"`
	EventsAppended     uint32 `json:"events_appended,omitempty"`
	FindingRules       string `json:"finding_rules"`
	EventsEvaluated    uint32 `json:"events_evaluated,omitempty"`
	FindingEvaluations int    `json:"finding_evaluations,omitempty"`
	GraphIngest        string `json:"graph_ingest"`
	EntitiesProjected  uint32 `json:"entities_projected,omitempty"`
	LinksProjected     uint32 `json:"links_projected,omitempty"`
	Error              string `json:"error,omitempty"`
}

func runOrchestrator(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return usageError(fmt.Sprintf("usage: %s orchestrator run [runtime_id=<runtime-id>] [tenant_id=<tenant-id>] [source_id=<source-id>] [limit=N] [page_limit=N] [event_limit=N] [graph_page_limit=N] [interval=30s] [iterations=N|forever]", os.Args[0]))
	}
	options, err := parseOrchestratorOptions(args[1:])
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), orchestratorShutdownSignals()...)
	defer stop()
	result, runErr := runOrchestratorLoop(ctx, options)
	if !shouldPrintOrchestratorResult(result) {
		return runErr
	}
	if err := printJSON(result); err != nil {
		return err
	}
	return runErr
}

func shouldPrintOrchestratorResult(result *orchestratorResult) bool {
	return result != nil
}

func orchestratorShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func parseOrchestratorOptions(args []string) (orchestratorOptions, error) {
	options := orchestratorOptions{Iterations: defaultOrchestratorIterations}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return orchestratorOptions{}, fmt.Errorf("invalid orchestrator argument %q; want key=value", arg)
		}
		switch key {
		case "runtime_id":
			options.Filter.RuntimeID = strings.TrimSpace(value)
		case "tenant_id":
			options.Filter.TenantID = strings.TrimSpace(value)
		case "source_id":
			options.Filter.SourceID = strings.TrimSpace(value)
		case "limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return orchestratorOptions{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed == 0 {
				return orchestratorOptions{}, fmt.Errorf("limit must be at least 1")
			}
			options.Filter.Limit = uint32(parsed)
		case "page_limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return orchestratorOptions{}, fmt.Errorf("parse page_limit: %w", err)
			}
			options.PageLimit = uint32(parsed)
		case "event_limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return orchestratorOptions{}, fmt.Errorf("parse event_limit: %w", err)
			}
			options.EventLimit = uint32(parsed)
		case "graph_page_limit":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return orchestratorOptions{}, fmt.Errorf("parse graph_page_limit: %w", err)
			}
			options.GraphPageLimit = uint32(parsed)
		case "interval":
			parsed, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				return orchestratorOptions{}, fmt.Errorf("parse interval: %w", err)
			}
			if parsed <= 0 {
				return orchestratorOptions{}, fmt.Errorf("interval must be positive")
			}
			options.Interval = parsed
		case "iterations":
			if strings.TrimSpace(value) == "forever" {
				options.RunForever = true
				options.Iterations = 0
				continue
			}
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return orchestratorOptions{}, fmt.Errorf("parse iterations: %w", err)
			}
			if parsed == 0 {
				return orchestratorOptions{}, fmt.Errorf("iterations must be at least 1 or forever")
			}
			options.RunForever = false
			options.Iterations = uint32(parsed)
		default:
			return orchestratorOptions{}, fmt.Errorf("unsupported orchestrator argument %q", key)
		}
	}
	if (options.RunForever || options.Iterations > 1) && options.Interval <= 0 {
		return orchestratorOptions{}, fmt.Errorf("interval is required when iterations is greater than 1 or forever")
	}
	return options, nil
}

func runOrchestratorLoop(ctx context.Context, options orchestratorOptions) (*orchestratorResult, error) {
	ctx, span := telemetry.Start(ctx, "orchestrator.run", telemetry.Attrs(
		telemetryField("runtime_id", options.Filter.RuntimeID),
		telemetryField("tenant_id", options.Filter.TenantID),
		telemetryField("source_id", options.Filter.SourceID),
		telemetryField("limit", options.Filter.Limit),
		telemetryField("page_limit", options.PageLimit),
		telemetryField("event_limit", options.EventLimit),
		telemetryField("graph_page_limit", options.GraphPageLimit),
		telemetryField("iterations", options.Iterations),
		telemetryField("run_forever", options.RunForever),
	))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		telemetry.End(span, status, spanAttributes)
	}()
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return nil, fmt.Errorf("open source registry: %w", err)
	}
	lister, ok := sourceRuntimeStore(deps.StateStore).(ports.SourceRuntimeListStore)
	if !ok {
		return nil, sourceruntime.ErrRuntimeUnavailable
	}
	leaser, ok := lister.(ports.SourceRuntimeLeaseStore)
	if !ok {
		return nil, sourceruntime.ErrRuntimeUnavailable
	}
	leaseOwner := orchestratorLeaseOwner()
	runtimeService := sourceruntime.New(
		registry,
		lister,
		deps.AppendLog,
		sourceProjector(deps.StateStore, deps.GraphStore),
	).WithConfigResolver(config.ResolveSourceRuntimeConfigSecretReferences)
	findingService := findings.New(
		lister,
		eventReplayer(deps.AppendLog),
		findingStore(deps.StateStore),
		findingEvaluationRunStore(deps.StateStore),
		findingEvidenceStore(deps.StateStore),
		claimStore(deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(deps.GraphStore)).WithGraphQueryStore(findingGraphQueryStore(deps.GraphStore)).WithAppendLog(deps.AppendLog)
	graphService := graphingest.New(
		registry,
		lister,
		sourceProjector(nil, deps.GraphStore),
		deps.GraphStore,
	).WithConfigPreparer(config.ResolveSourceRuntimeConfigSecretReferences)
	result := &orchestratorResult{
		Iterations: options.Iterations,
		RunForever: options.RunForever,
		Runs:       []*orchestratorIterationResult{},
	}
	if options.Interval > 0 {
		result.Interval = options.Interval.String()
	}
	var (
		ticker    *time.Ticker
		iteration uint32
		runErr    error
	)
	if options.RunForever || options.Iterations > 1 {
		ticker = time.NewTicker(options.Interval)
		defer ticker.Stop()
	}
	for {
		iteration++
		iterationResult, err := runOrchestratorIteration(ctx, lister, leaser, leaseOwner, runtimeService, findingService, graphService, options, iteration)
		if err != nil {
			runErr = err
		}
		result.Runs = appendOrchestratorRun(result.Runs, iterationResult, options.RunForever)
		if !options.RunForever && iteration >= options.Iterations {
			break
		}
		if ticker == nil {
			break
		}
		select {
		case <-ctx.Done():
			spanAttributes = withTelemetryField(spanAttributes, "error", ctx.Err().Error())
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
	status = "completed"
	if runErr != nil {
		status = "failed"
		spanAttributes = withTelemetryField(spanAttributes, "error", runErr.Error())
	}
	spanAttributes = withTelemetryField(spanAttributes, "iterations_completed", iteration)
	return result, runErr
}

func appendOrchestratorRun(runs []*orchestratorIterationResult, run *orchestratorIterationResult, runForever bool) []*orchestratorIterationResult {
	if !runForever {
		return append(runs, run)
	}
	return []*orchestratorIterationResult{run}
}

func runOrchestratorIteration(
	ctx context.Context,
	lister ports.SourceRuntimeListStore,
	leaser ports.SourceRuntimeLeaseStore,
	leaseOwner string,
	runtimeService *sourceruntime.Service,
	findingService *findings.Service,
	graphService *graphingest.Service,
	options orchestratorOptions,
	iteration uint32,
) (*orchestratorIterationResult, error) {
	ctx, span := telemetry.Start(ctx, "orchestrator.iteration", telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("runtime_id", options.Filter.RuntimeID),
		telemetryField("tenant_id", options.Filter.TenantID),
		telemetryField("source_id", options.Filter.SourceID),
		telemetryField("limit", options.Filter.Limit),
	))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		telemetry.End(span, status, spanAttributes)
	}()
	targetLimit := options.Filter.Limit
	runtimes, err := lister.ListSourceRuntimes(ctx, orchestratorListFilter(options.Filter))
	result := &orchestratorIterationResult{Iteration: iteration, StartedAt: time.Now().UTC()}
	if err != nil {
		spanAttributes = withTelemetryField(spanAttributes, "error", err.Error())
		return result, err
	}
	telemetry.Event(ctx, "orchestrator.runtimes_listed", telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("runtime_count", len(runtimes)),
	))
	var runErr error
	var acquiredCount uint32
	for _, runtime := range runtimes {
		if targetLimit > 0 && acquiredCount >= targetLimit {
			break
		}
		select {
		case <-ctx.Done():
			spanAttributes = withTelemetryField(spanAttributes, "error", ctx.Err().Error())
			return result, ctx.Err()
		default:
		}
		runtimeCtx, runtimeSpan := telemetry.Start(ctx, "orchestrator.runtime", telemetry.Attrs(
			telemetryField("iteration", iteration),
			telemetryField("runtime_id", runtime.GetId()),
			telemetryField("source_id", runtime.GetSourceId()),
			telemetryField("tenant_id", runtime.GetTenantId()),
		))
		runtimeStatus := "failed"
		runtimeSpanAttrs := telemetry.Attrs()
		runtimeResult := &orchestratorRuntimeResult{
			RuntimeID: strings.TrimSpace(runtime.GetId()),
			SourceID:  strings.TrimSpace(runtime.GetSourceId()),
			TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		}
		acquired, err := acquireOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner)
		if err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "lease", err)
			result.Runtimes = append(result.Runtimes, runtimeResult)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error", err.Error())
			telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
			continue
		}
		if !acquired {
			runtimeResult.Sync = "skipped"
			result.Runtimes = append(result.Runtimes, runtimeResult)
			runtimeStatus = "skipped"
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "reason", "lease_not_acquired")
			telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
			continue
		}
		acquiredCount++
		runtimeCtx, cancelRuntime := context.WithCancel(runtimeCtx)
		stopLeaseRenewal := startOrchestratorRuntimeLeaseRenewal(ctx, leaser, runtime, leaseOwner, cancelRuntime)
		syncResult, err := runtimeService.Sync(runtimeCtx, &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId(), PageLimit: options.PageLimit})
		if err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "sync", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error", err.Error())
			cancelRuntime()
			if renewalErr := stopLeaseRenewal(); renewalErr != nil {
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "renew_lease", renewalErr)
				runErr = renewalErr
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "renew_lease_error", renewalErr.Error())
			}
			if releaseErr := releaseOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner); releaseErr != nil {
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "release_lease", releaseErr)
				runErr = releaseErr
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "release_lease_error", releaseErr.Error())
			}
			result.Runtimes = append(result.Runtimes, runtimeResult)
			telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
			continue
		} else {
			runtimeResult.Sync = "completed"
			runtimeResult.PagesRead = syncResult.GetPagesRead()
			runtimeResult.EventsAppended = syncResult.GetEventsAppended()
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "pages_read", runtimeResult.PagesRead)
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "events_appended", runtimeResult.EventsAppended)
		}
		findingResult, err := findingService.EvaluateSourceRuntimeRules(runtimeCtx, findings.EvaluateRulesRequest{RuntimeID: runtime.GetId(), EventLimit: options.EventLimit})
		if err != nil {
			runtimeResult.FindingRules = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "finding_rules", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "finding_rules_error", err.Error())
		} else {
			runtimeResult.FindingRules = "completed"
			runtimeResult.EventsEvaluated = findingResult.EventsEvaluated
			runtimeResult.FindingEvaluations = len(findingResult.Evaluations)
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "events_evaluated", runtimeResult.EventsEvaluated)
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "finding_evaluations", runtimeResult.FindingEvaluations)
		}
		graphResult, err := graphService.RunRuntime(runtimeCtx, graphingest.RuntimeRequest{RuntimeID: runtime.GetId(), PageLimit: options.GraphPageLimit, Trigger: "orchestrator"})
		if err != nil {
			runtimeResult.GraphIngest = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "graph_ingest", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "graph_ingest_error", err.Error())
		} else {
			runtimeResult.GraphIngest = "completed"
			if graphResult.Ingest != nil {
				runtimeResult.EntitiesProjected = graphResult.Ingest.EntitiesProjected
				runtimeResult.LinksProjected = graphResult.Ingest.LinksProjected
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "entities_projected", runtimeResult.EntitiesProjected)
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "links_projected", runtimeResult.LinksProjected)
			}
		}
		cancelRuntime()
		if err := stopLeaseRenewal(); err != nil {
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "renew_lease", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "renew_lease_error", err.Error())
		}
		if err := releaseOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner); err != nil {
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "release_lease", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "release_lease_error", err.Error())
		}
		result.Runtimes = append(result.Runtimes, runtimeResult)
		if runtimeResult.Error == "" {
			runtimeStatus = "completed"
		}
		if runtimeResult.Error != "" {
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error", runtimeResult.Error)
		}
		telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
	}
	status = "completed"
	if runErr != nil {
		status = "failed"
		spanAttributes = withTelemetryField(spanAttributes, "error", runErr.Error())
	}
	spanAttributes = withTelemetryField(spanAttributes, "runtimes_attempted", len(result.Runtimes))
	spanAttributes = withTelemetryField(spanAttributes, "runtimes_acquired", acquiredCount)
	return result, runErr
}

func orchestratorListFilter(filter ports.SourceRuntimeFilter) ports.SourceRuntimeFilter {
	if filter.Limit == 0 {
		filter.Limit = ^uint32(0)
		return filter
	}
	if ^uint32(0)-filter.Limit < sourceRuntimeLeaseOverscanLimit {
		filter.Limit = ^uint32(0)
		return filter
	}
	filter.Limit += sourceRuntimeLeaseOverscanLimit
	return filter
}

func orchestratorLeaseOwner() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("%s:%d:%d", hostname, os.Getpid(), time.Now().UnixNano())
}

func acquireOrchestratorRuntimeLease(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtime *cerebrov1.SourceRuntime, owner string) (bool, error) {
	if store == nil || runtime == nil {
		return true, nil
	}
	return store.AcquireSourceRuntimeLease(ctx, runtime.GetId(), owner, defaultSourceRuntimeLeaseTTL)
}

func startOrchestratorRuntimeLeaseRenewal(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtime *cerebrov1.SourceRuntime, owner string, cancelWork context.CancelFunc) func() error {
	return startOrchestratorRuntimeLeaseRenewalWithTTL(ctx, store, runtime, owner, cancelWork, defaultSourceRuntimeLeaseTTL)
}

func startOrchestratorRuntimeLeaseRenewalWithTTL(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtime *cerebrov1.SourceRuntime, owner string, cancelWork context.CancelFunc, ttl time.Duration) func() error {
	if store == nil || runtime == nil {
		return func() error { return nil }
	}
	if cancelWork == nil {
		cancelWork = func() {}
	}
	renewCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(sourceRuntimeLeaseRenewalInterval(ttl))
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				renewed, err := store.RenewSourceRuntimeLease(renewCtx, runtime.GetId(), owner, ttl)
				if err != nil {
					cancelWork()
					done <- err
					return
				}
				if !renewed {
					cancelWork()
					done <- fmt.Errorf("source runtime lease lost: %s", runtime.GetId())
					return
				}
			}
		}
	}()
	return func() error {
		cancel()
		return <-done
	}
}

func sourceRuntimeLeaseRenewalInterval(ttl time.Duration) time.Duration {
	interval := ttl / 2
	if interval <= 0 {
		return ttl
	}
	return interval
}

func releaseOrchestratorRuntimeLease(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtime *cerebrov1.SourceRuntime, owner string) error {
	if store == nil || runtime == nil {
		return nil
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sourceRuntimeLeaseReleaseTimeout)
	defer cancel()
	return store.ReleaseSourceRuntimeLease(releaseCtx, runtime.GetId(), owner)
}

func appendRuntimeError(existing string, stage string, err error) string {
	message := fmt.Sprintf("%s: %v", stage, err)
	if strings.TrimSpace(existing) == "" {
		return message
	}
	return existing + "; " + message
}

func telemetryField(key string, value any) telemetry.Field {
	return telemetry.Field{Key: key, Value: value}
}

func withTelemetryField(attributes telemetry.Attributes, key string, value any) telemetry.Attributes {
	return attributes.WithField(telemetryField(key, value))
}

func findingStore(store ports.StateStore) ports.FindingStore {
	typed, _ := store.(ports.FindingStore)
	return typed
}

func findingEvaluationRunStore(store ports.StateStore) ports.FindingEvaluationRunStore {
	typed, _ := store.(ports.FindingEvaluationRunStore)
	return typed
}

func findingEvidenceStore(store ports.StateStore) ports.FindingEvidenceStore {
	typed, _ := store.(ports.FindingEvidenceStore)
	return typed
}

func claimStore(store ports.StateStore) ports.ClaimStore {
	typed, _ := store.(ports.ClaimStore)
	return typed
}

func findingGraphQueryStore(store ports.GraphStore) ports.GraphQueryStore {
	typed, _ := store.(ports.GraphQueryStore)
	return typed
}

func eventReplayer(appendLog ports.AppendLog) ports.EventReplayer {
	typed, _ := appendLog.(ports.EventReplayer)
	return typed
}
