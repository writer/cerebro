package main

import (
	"context"
	"errors"
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
	"github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehealth"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/telemetry"
)

const defaultOrchestratorIterations = 1
const defaultSourceRuntimeLeaseTTL = 30 * time.Minute
const sourceRuntimeLeaseReleaseTimeout = 5 * time.Second
const sourceRuntimeLeaseOverscanLimit = 100

const (
	defaultOrchestratorPhaseTimeout       = 15 * time.Minute
	defaultOrchestratorGraphIngestTimeout = 45 * time.Minute
	// graphRulePhaseTimeoutMargin keeps the derived per-graph-rule Cypher budget
	// strictly under the graph-rule phase timeout so a stuck rule trips an
	// attributable per-rule deadline before the phase context is cancelled out
	// from under the in-flight query (which surfaces as a connectivity error).
	graphRulePhaseTimeoutMargin = time.Minute
)

type orchestratorOptions struct {
	Filter          ports.SourceRuntimeFilter `json:"filter"`
	PageLimit       uint32                    `json:"page_limit,omitempty"`
	EventLimit      uint32                    `json:"event_limit,omitempty"`
	GraphPageLimit  uint32                    `json:"graph_page_limit,omitempty"`
	PhaseTimeout    time.Duration             `json:"-"`
	GraphTimeout    time.Duration             `json:"-"`
	Interval        time.Duration             `json:"-"`
	ShutdownContext context.Context           `json:"-"`
	Iterations      uint32                    `json:"iterations"`
	RunForever      bool                      `json:"run_forever,omitempty"`
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
	RuntimeID            string              `json:"runtime_id"`
	SourceID             string              `json:"source_id,omitempty"`
	TenantID             string              `json:"tenant_id,omitempty"`
	Sync                 string              `json:"sync"`
	PagesRead            uint32              `json:"pages_read,omitempty"`
	EventsAppended       uint32              `json:"events_appended,omitempty"`
	FindingRules         string              `json:"finding_rules"`
	EventsEvaluated      uint32              `json:"events_evaluated,omitempty"`
	FindingEvaluations   int                 `json:"finding_evaluations,omitempty"`
	GraphIngest          string              `json:"graph_ingest"`
	EntitiesProjected    uint32              `json:"entities_projected,omitempty"`
	LinksProjected       uint32              `json:"links_projected,omitempty"`
	GraphRules           string              `json:"graph_rules"`
	GraphRuleEvaluations int                 `json:"graph_rule_evaluations,omitempty"`
	GraphRuleFindings    int                 `json:"graph_rule_findings,omitempty"`
	GraphRuleRowsRead    uint32              `json:"graph_rule_rows_read,omitempty"`
	Error                string              `json:"error,omitempty"`
	Health               sourcehealth.Record `json:"-"`
}

type orchestratorJobMetadataContextKey struct{}

type orchestratorJobMetadata struct {
	ID        string
	Kind      string
	Name      string
	Schedule  string
	StartedAt time.Time
}

func runOrchestrator(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return usageError(fmt.Sprintf("usage: %s orchestrator run [runtime_id=<runtime-id>] [runtime_ids=<runtime-id>,<runtime-id>] [tenant_id=<tenant-id>] [source_id=<source-id>] [limit=N] [page_limit=N] [event_limit=N] [graph_page_limit=N] [phase_timeout=15m] [graph_timeout=45m] [interval=30s] [iterations=N|forever]", os.Args[0]))
	}
	options, err := parseOrchestratorOptions(args[1:])
	if err != nil {
		return err
	}
	options.ShutdownContext = context.Background()
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

func orchestratorScheduleName(options orchestratorOptions) string {
	if options.RunForever {
		return "forever"
	}
	if options.Iterations > 1 {
		return "interval"
	}
	return "single_run"
}

func parseOrchestratorOptions(args []string) (orchestratorOptions, error) {
	options := orchestratorOptions{
		Iterations:   defaultOrchestratorIterations,
		PhaseTimeout: defaultOrchestratorPhaseTimeout,
		GraphTimeout: defaultOrchestratorGraphIngestTimeout,
	}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return orchestratorOptions{}, fmt.Errorf("invalid orchestrator argument %q; want key=value", arg)
		}
		switch key {
		case "runtime_id":
			options.Filter.RuntimeID = strings.TrimSpace(value)
		case "runtime_ids":
			options.Filter.RuntimeIDs = splitCSV(value)
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
		case "phase_timeout":
			parsed, err := parsePositiveDurationArg("phase_timeout", value)
			if err != nil {
				return orchestratorOptions{}, err
			}
			options.PhaseTimeout = parsed
		case "graph_timeout", "graph_ingest_timeout":
			parsed, err := parsePositiveDurationArg(key, value)
			if err != nil {
				return orchestratorOptions{}, err
			}
			options.GraphTimeout = parsed
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

func parsePositiveDurationArg(name string, value string) (time.Duration, error) {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}

func runOrchestratorLoop(ctx context.Context, options orchestratorOptions) (result *orchestratorResult, err error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("configure telemetry: %w", err)
	}
	defer shutdownTelemetry(orchestratorShutdownContext(options, ctx), closeTelemetry, cfg.ShutdownTimeout)
	jobStartedAt := time.Now().UTC()
	jobMeta := orchestratorJobMetadata{
		ID:        orchestratorRunID(orchestratorScheduleName(options), jobStartedAt),
		Kind:      jobs.KindSourceRuntimeOrchestrate,
		Name:      "orchestrator.run",
		Schedule:  orchestratorScheduleName(options),
		StartedAt: jobStartedAt,
	}
	ctx = withOrchestratorJobMetadata(ctx, jobMeta)
	ctx, span := telemetry.StartMain(ctx, "orchestrator.run", telemetry.Attrs(
		telemetryField("operation", "orchestrator.run"),
		telemetryField("operation.type", "background_job"),
		telemetryField("workload.kind", "orchestrator"),
		telemetryField("job.id", jobMeta.ID),
		telemetryField("job.kind", jobMeta.Kind),
		telemetryField("job.name", jobMeta.Name),
		telemetryField("job.schedule", jobMeta.Schedule),
		telemetryField("job.status", "running"),
		telemetryField("job.started_at_unix_ms", jobMeta.StartedAt.UnixMilli()),
		telemetryField("runtime_id", options.Filter.RuntimeID),
		telemetryField("runtime_ids", strings.Join(options.Filter.RuntimeIDs, ",")),
		telemetryField("source_runtime_id", options.Filter.RuntimeID),
		telemetryField("tenant_id", options.Filter.TenantID),
		telemetryField("source_id", options.Filter.SourceID),
		telemetryField("limit", options.Filter.Limit),
		telemetryField("page_limit", options.PageLimit),
		telemetryField("event_limit", options.EventLimit),
		telemetryField("graph_page_limit", options.GraphPageLimit),
		telemetryField("effective_page_limit", options.PageLimit),
		telemetryField("effective_event_limit", options.EventLimit),
		telemetryField("effective_graph_page_limit", options.GraphPageLimit),
		telemetryField("orchestrator.schedule.name", orchestratorScheduleName(options)),
		telemetryField("phase_timeout_ms", options.PhaseTimeout.Milliseconds()),
		telemetryField("graph_timeout_ms", options.GraphTimeout.Milliseconds()),
		telemetryField("iterations", options.Iterations),
		telemetryField("run_forever", options.RunForever),
	))
	telemetry.Event(ctx, "platform.job.started", orchestratorJobAttrs(ctx).With(telemetry.Attrs(
		telemetryField("job.status", "running"),
		telemetryField("job.runner.available", true),
	)))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		if err != nil {
			status = "failed"
			spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(err))
		}
		terminalAttrs := spanAttributes.With(orchestratorJobAttrs(ctx)).With(telemetry.Attrs(
			telemetryField("operation", "orchestrator.run"),
			telemetryField("job.status", status),
			telemetryField("job.status.final", status),
			telemetryField("job_status", status),
			telemetryField("job.run_duration_ms", time.Since(jobMeta.StartedAt).Milliseconds()),
			telemetryField("orchestrator.status", status),
		))
		if status == "completed" {
			telemetry.Event(ctx, "platform.job.completed", terminalAttrs)
		} else {
			if err != nil {
				telemetry.CaptureError(ctx, "platform.job.failed", err, terminalAttrs)
			} else {
				telemetry.Event(ctx, "platform.job.failed", terminalAttrs)
			}
		}
		telemetry.AnnotateMain(ctx, terminalAttrs)
		telemetry.End(span, status, terminalAttrs)
	}()
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		captureOrchestratorError(ctx, "orchestrator.error", 0, nil, "open_dependencies", err)
		return nil, fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	registry, err := sourceregistry.Builtin()
	if err != nil {
		captureOrchestratorError(ctx, "orchestrator.error", 0, nil, "source_registry", err)
		return nil, fmt.Errorf("open source registry: %w", err)
	}
	lister, ok := sourceRuntimeStore(deps.StateStore).(ports.SourceRuntimeListStore)
	if !ok {
		err := sourceruntime.ErrRuntimeUnavailable
		captureOrchestratorError(ctx, "orchestrator.error", 0, nil, "runtime_list_store", err)
		return nil, err
	}
	leaser, ok := lister.(ports.SourceRuntimeLeaseStore)
	if !ok {
		err := sourceruntime.ErrRuntimeUnavailable
		captureOrchestratorError(ctx, "orchestrator.error", 0, nil, "runtime_lease_store", err)
		return nil, err
	}
	leaseOwner := orchestratorLeaseOwner()
	runtimeService := newOrchestratorRuntimeService(registry, lister, deps.AppendLog, deps.StateStore)
	findingService := findings.New(
		lister,
		eventReplayer(deps.AppendLog),
		findingStore(deps.StateStore),
		findingEvaluationRunStore(deps.StateStore),
		findingEvidenceStore(deps.StateStore),
		claimStore(deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(deps.GraphStore)).WithGraphQueryStore(findingGraphQueryStore(deps.GraphStore)).WithAppendLog(deps.AppendLog).WithGraphRuleQueryTimeout(graphRuleQueryBudgetForPhase(options.PhaseTimeout)).WithRuntimeIndexReplayPreparer(cfg.AppendLog.JetStreamRuntimeIndexEnabled, deps.AppendLog, deps.StateStore)
	graphService := graphingest.New(
		registry,
		lister,
		sourceProjector(nil, deps.GraphStore),
		deps.GraphStore,
	).WithConfigPreparer(config.ResolveSourceRuntimeConfigSecretReferences)
	result = &orchestratorResult{
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
		emitOrchestratorJobHeartbeat(ctx, iteration, "iteration_started", telemetry.Attrs(telemetryField("iteration", iteration)))
		iterationResult, err := runOrchestratorIteration(ctx, lister, leaser, leaseOwner, runtimeService, findingService, graphService, options, iteration)
		if err != nil {
			runErr = err
		}
		iterationStatus := "completed"
		if err != nil {
			iterationStatus = "failed"
		}
		emitOrchestratorJobHeartbeat(ctx, iteration, "iteration_"+iterationStatus, telemetry.Attrs(
			telemetryField("iteration", iteration),
			telemetryField("orchestrator.iteration.status", iterationStatus),
		))
		result.Runs = appendOrchestratorRun(result.Runs, iterationResult, options.RunForever)
		if !options.RunForever && iteration >= options.Iterations {
			break
		}
		if ticker == nil {
			break
		}
		select {
		case <-ctx.Done():
			spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(ctx.Err()))
			emitOrchestratorJobHeartbeat(ctx, iteration, "shutdown_requested", telemetry.Attrs(
				telemetryField("iteration", iteration),
				telemetryField("error_kind", telemetry.ErrorKind(ctx.Err())),
			))
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
	status = "completed"
	if runErr != nil {
		status = "failed"
		spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(runErr))
	}
	spanAttributes = withTelemetryField(spanAttributes, "iterations_completed", iteration)
	return result, runErr
}

func newOrchestratorRuntimeService(registry *sourcecdk.Registry, store ports.SourceRuntimeStore, appendLog ports.AppendLog, stateStore ports.StateStore) *sourceruntime.Service {
	return sourceruntime.New(
		registry,
		store,
		appendLog,
		newOrchestratorSyncProjector(stateStore),
	).WithConfigResolver(config.ResolveSourceRuntimeConfigSecretReferences)
}

func newOrchestratorSyncProjector(stateStore ports.StateStore) ports.SourceProjector {
	// Source sync can project current state, but Neo4j writes are handled by
	// the coalescing graph ingest phase below.
	return sourceProjector(stateStore, nil)
}

func orchestratorGraphPageLimit(configured uint32, syncedPages uint32) uint32 {
	if syncedPages > configured {
		return syncedPages
	}
	return configured
}

func graphIngestReadyForGraphRules(result *graphingest.RunResult, syncCursor *cerebrov1.SourceCursor) bool {
	if result == nil || result.Ingest == nil {
		return false
	}
	if !result.Ingest.CheckpointPersisted && !result.Ingest.CheckpointAlreadyFresh {
		return false
	}
	syncCursorOpaque := ""
	if syncCursor != nil {
		syncCursorOpaque = strings.TrimSpace(syncCursor.GetOpaque())
	}
	return strings.TrimSpace(result.Ingest.CheckpointCursor) == syncCursorOpaque
}

func orchestratorRuntimeStartCursorOpaque(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return ""
	}
	if cursor := runtime.GetNextCursor(); cursor != nil {
		return strings.TrimSpace(cursor.GetOpaque())
	}
	return strings.TrimSpace(runtime.GetCheckpoint().GetCursorOpaque())
}

func appendOrchestratorRun(runs []*orchestratorIterationResult, run *orchestratorIterationResult, runForever bool) []*orchestratorIterationResult {
	if !runForever {
		return append(runs, run)
	}
	return []*orchestratorIterationResult{run}
}

func orchestratorShutdownContext(options orchestratorOptions, fallback context.Context) context.Context {
	if options.ShutdownContext != nil {
		return options.ShutdownContext
	}
	return fallback
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
		telemetryField("runtime_ids", strings.Join(options.Filter.RuntimeIDs, ",")),
		telemetryField("tenant_id", options.Filter.TenantID),
		telemetryField("source_id", options.Filter.SourceID),
		telemetryField("limit", options.Filter.Limit),
		telemetryField("phase_timeout_ms", options.PhaseTimeout.Milliseconds()),
		telemetryField("graph_timeout_ms", options.GraphTimeout.Milliseconds()),
	))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		telemetry.AnnotateMainPhase(ctx, "orchestrator.iteration", status, spanAttributes.WithField(telemetryField("iteration", iteration)))
		telemetry.End(span, status, spanAttributes)
	}()
	targetLimit := options.Filter.Limit
	runtimes, err := lister.ListSourceRuntimes(ctx, orchestratorListFilter(options.Filter))
	result := &orchestratorIterationResult{Iteration: iteration, StartedAt: time.Now().UTC()}
	if err != nil {
		spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(err))
		captureOrchestratorError(ctx, "orchestrator.iteration.error", iteration, nil, "list_runtimes", err)
		return result, err
	}
	telemetry.Event(ctx, "orchestrator.runtimes_listed", telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("runtime_count", len(runtimes)),
	))
	var runErr error
	var acquiredCount uint32
	// Graph rules are tenant-scoped: each one queries the whole tenant graph,
	// not just the triggering runtime's slice. Running them once per runtime
	// re-evaluates the identical tenant-wide rule for every runtime in the
	// tenant (hundreds, for large multi-account tenants), which is the dominant
	// load on the graph-rule phase. Track which rules already ran for a tenant
	// this iteration and exclude them so each rule runs at most once per tenant
	// per cycle while still covering rules contributed by other sources.
	graphRulesEvaluatedByTenant := map[string]map[string]struct{}{}
	for _, runtime := range runtimes {
		if targetLimit > 0 && acquiredCount >= targetLimit {
			break
		}
		select {
		case <-ctx.Done():
			spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(ctx.Err()))
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
		runtimeSpanAttrs := telemetry.Attrs(
			telemetryField("iteration", iteration),
			telemetryField("runtime_id", runtime.GetId()),
			telemetryField("source_id", runtime.GetSourceId()),
			telemetryField("tenant_id", runtime.GetTenantId()),
			telemetryField("effective_page_limit", options.PageLimit),
			telemetryField("effective_event_limit", options.EventLimit),
		)
		runtimeResult := &orchestratorRuntimeResult{
			RuntimeID: strings.TrimSpace(runtime.GetId()),
			SourceID:  strings.TrimSpace(runtime.GetSourceId()),
			TenantID:  strings.TrimSpace(runtime.GetTenantId()),
			Health:    sourcehealth.RecordFromRuntime(runtime, time.Now().UTC()),
		}
		emitOrchestratorJobRuntimeEvent(runtimeCtx, "platform.job.runtime.started", "running", iteration, runtime, runtimeResult, runtimeSpanAttrs)
		acquired, err := acquireOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner)
		if err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "lease", err)
			result.Runtimes = append(result.Runtimes, runtimeResult)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_stage", "lease")
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_kind", telemetry.ErrorKind(err))
			captureOrchestratorError(runtimeCtx, "orchestrator.runtime.error", iteration, runtime, "lease", err)
			annotateOrchestratorRuntimeMain(runtimeCtx, runtimeResult, runtimeStatus, runtimeSpanAttrs)
			emitOrchestratorJobRuntimeEvent(runtimeCtx, "platform.job.runtime.failed", runtimeStatus, iteration, runtime, runtimeResult, runtimeSpanAttrs)
			telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
			continue
		}
		if !acquired {
			runtimeResult.Sync = "skipped"
			result.Runtimes = append(result.Runtimes, runtimeResult)
			runtimeStatus = "skipped"
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "reason", "lease_not_acquired")
			annotateOrchestratorRuntimeMain(runtimeCtx, runtimeResult, runtimeStatus, runtimeSpanAttrs)
			emitOrchestratorJobRuntimeEvent(runtimeCtx, "platform.job.runtime.skipped", runtimeStatus, iteration, runtime, runtimeResult, runtimeSpanAttrs)
			telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
			continue
		}
		acquiredCount++
		runtimeCtx, cancelRuntime := context.WithCancel(runtimeCtx)
		stopLeaseRenewal := startOrchestratorRuntimeLeaseRenewal(ctx, leaser, runtime, leaseOwner, cancelRuntime)
		syncStartCursorOpaque := orchestratorRuntimeStartCursorOpaque(runtime)
		syncStarted := time.Now()
		emitOrchestratorJobPhaseStarted(runtimeCtx, "source_runtime.sync", iteration, runtime, 0)
		syncResult, err := runtimeService.Sync(runtimeCtx, &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId(), PageLimit: options.PageLimit})
		if err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "sync", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_stage", "sync")
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_kind", telemetry.ErrorKind(err))
			emitOrchestratorJobPhaseEnded(runtimeCtx, "source_runtime.sync", "failed", iteration, runtime, time.Since(syncStarted), 0, telemetry.Attrs(
				telemetryField("error_kind", telemetry.ErrorKind(err)),
			))
			captureOrchestratorError(runtimeCtx, "orchestrator.runtime.error", iteration, runtime, "sync", err)
			cancelRuntime()
			if renewalErr := stopLeaseRenewal(); renewalErr != nil {
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "renew_lease", renewalErr)
				runErr = renewalErr
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "renew_lease_error_kind", telemetry.ErrorKind(renewalErr))
				captureOrchestratorError(runtimeCtx, "orchestrator.runtime.error", iteration, runtime, "renew_lease", renewalErr)
			}
			if releaseErr := releaseOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner); releaseErr != nil {
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "release_lease", releaseErr)
				runErr = releaseErr
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "release_lease_error_kind", telemetry.ErrorKind(releaseErr))
				captureOrchestratorError(runtimeCtx, "orchestrator.runtime.error", iteration, runtime, "release_lease", releaseErr)
			}
			result.Runtimes = append(result.Runtimes, runtimeResult)
			annotateOrchestratorRuntimeMain(runtimeCtx, runtimeResult, runtimeStatus, runtimeSpanAttrs)
			emitOrchestratorJobRuntimeEvent(runtimeCtx, "platform.job.runtime.failed", runtimeStatus, iteration, runtime, runtimeResult, runtimeSpanAttrs)
			telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
			continue
		} else {
			runtimeResult.Sync = "completed"
			runtimeResult.PagesRead = syncResult.GetPagesRead()
			runtimeResult.EventsAppended = syncResult.GetEventsAppended()
			if syncResult.GetRuntime() != nil {
				runtime = syncResult.GetRuntime()
				runtimeResult.Health = sourcehealth.RecordFromRuntime(runtime, time.Now().UTC())
			}
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "pages_read", runtimeResult.PagesRead)
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "events_appended", runtimeResult.EventsAppended)
			emitOrchestratorJobPhaseEnded(runtimeCtx, "source_runtime.sync", "completed", iteration, runtime, time.Since(syncStarted), 0, telemetry.Attrs(
				telemetryField("pages_read", runtimeResult.PagesRead),
				telemetryField("events_appended", runtimeResult.EventsAppended),
			))
		}
		graphPageLimit := orchestratorGraphPageLimit(options.GraphPageLimit, runtimeResult.PagesRead)
		resetGraphCheckpoint := runtimeResult.EventsAppended > 0 && syncStartCursorOpaque == ""
		resetCompletedGraphCheckpoint := runtimeResult.EventsAppended > 0
		runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "effective_graph_page_limit", graphPageLimit)
		runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "reset_graph_checkpoint", resetGraphCheckpoint)
		runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "reset_completed_graph_checkpoint", resetCompletedGraphCheckpoint)
		graphResult, err := runOrchestratorPhase(runtimeCtx, "orchestrator.graph_ingest", iteration, runtime, options.GraphTimeout, func(phaseCtx context.Context) (*graphingest.RunResult, error) {
			return graphService.RunRuntime(phaseCtx, graphingest.RuntimeRequest{
				RuntimeID:                runtime.GetId(),
				PageLimit:                graphPageLimit,
				ResetCheckpoint:          resetGraphCheckpoint,
				ResetCompletedCheckpoint: resetCompletedGraphCheckpoint,
				Trigger:                  "orchestrator",
			})
		})
		runtimeSpanAttrs = applyGraphIngestCounters(runtimeResult, graphResult, runtimeSpanAttrs)
		if err != nil {
			runtimeResult.GraphIngest = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "graph_ingest", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "graph_ingest_error_kind", telemetry.ErrorKind(err))
		} else {
			runtimeResult.GraphIngest = "completed"
		}
		runtimeResult.Health = withOrchestratorGraphHealth(runtimeResult.Health, graphResult, runtimeResult.GraphIngest, time.Now().UTC())
		findingResult, err := runOrchestratorPhase(runtimeCtx, "orchestrator.finding_rules", iteration, runtime, options.PhaseTimeout, func(phaseCtx context.Context) (*findings.EvaluateRulesResult, error) {
			return findingService.EvaluateSourceRuntimeRules(phaseCtx, findings.EvaluateRulesRequest{RuntimeID: runtime.GetId(), EventLimit: options.EventLimit})
		})
		if err != nil {
			if errors.Is(err, findings.ErrRuleUnavailable) {
				runtimeResult.FindingRules = "skipped"
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "finding_rules_skip_reason", "rule_unavailable")
			} else {
				runtimeResult.FindingRules = "failed"
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "finding_rules", err)
				runErr = err
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "finding_rules_error_kind", telemetry.ErrorKind(err))
			}
		} else {
			runtimeResult.FindingRules = "completed"
			runtimeResult.EventsEvaluated = findingResult.EventsEvaluated
			runtimeResult.FindingEvaluations = len(findingResult.Evaluations)
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "events_evaluated", runtimeResult.EventsEvaluated)
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "finding_evaluations", runtimeResult.FindingEvaluations)
		}
		runtimeResult.Health = withOrchestratorFindingHealth(runtimeResult.Health, runtimeResult.FindingRules)
		// Run graph rules whenever the projection has caught up to the same cursor
		// reached by source sync, even if a trailing PutIngestRun(completed) write
		// failed. The graph is fresh enough for read-only rules at that point.
		if graphIngestReadyForGraphRules(graphResult, syncResult.GetRuntime().GetNextCursor()) {
			excludedGraphRuleIDs := orchestratorEvaluatedGraphRuleIDs(graphRulesEvaluatedByTenant[runtimeResult.TenantID])
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "graph_rules_deduped_count", len(excludedGraphRuleIDs))
			graphRulesResult, err := runOrchestratorPhase(runtimeCtx, "orchestrator.graph_rules", iteration, runtime, options.PhaseTimeout, func(phaseCtx context.Context) (*findings.EvaluateGraphRulesResult, error) {
				return findingService.EvaluateSourceRuntimeGraphRules(phaseCtx, findings.EvaluateGraphRulesRequest{RuntimeID: runtime.GetId(), ExcludeRuleIDs: excludedGraphRuleIDs})
			})
			runtimeSpanAttrs = applyGraphRuleCounters(runtimeResult, graphRulesResult, runtimeSpanAttrs)
			// Mark every rule that was attempted (success or failure) so a slow
			// or failing rule is retried at most once per tenant per cycle
			// rather than re-running for every remaining runtime in the tenant.
			markOrchestratorTenantGraphRulesEvaluated(graphRulesEvaluatedByTenant, runtimeResult.TenantID, graphRulesResult)
			if err != nil {
				if errors.Is(err, findings.ErrGraphRuntimeUnavailable) || errors.Is(err, findings.ErrRuntimeUnavailable) {
					runtimeResult.GraphRules = "skipped"
					runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "graph_rules_skip_reason", "runtime_unavailable")
				} else {
					runtimeResult.GraphRules = "failed"
					runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "graph_rules", err)
					runErr = err
					runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "graph_rules_error_kind", telemetry.ErrorKind(err))
				}
			} else {
				runtimeResult.GraphRules = "completed"
			}
		} else {
			runtimeResult.GraphRules = "skipped"
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "graph_rules_skip_reason", "graph_ingest_not_caught_up")
		}
		cancelRuntime()
		if err := stopLeaseRenewal(); err != nil {
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "renew_lease", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "renew_lease_error_kind", telemetry.ErrorKind(err))
			captureOrchestratorError(runtimeCtx, "orchestrator.runtime.error", iteration, runtime, "renew_lease", err)
		}
		if err := releaseOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner); err != nil {
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "release_lease", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "release_lease_error_kind", telemetry.ErrorKind(err))
			captureOrchestratorError(runtimeCtx, "orchestrator.runtime.error", iteration, runtime, "release_lease", err)
		}
		result.Runtimes = append(result.Runtimes, runtimeResult)
		if runtimeResult.Error == "" {
			runtimeStatus = "completed"
		}
		if runtimeResult.Error != "" {
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "runtime_error_present", true)
		}
		annotateOrchestratorRuntimeMain(runtimeCtx, runtimeResult, runtimeStatus, runtimeSpanAttrs)
		runtimeEventName := "platform.job.runtime.completed"
		if runtimeStatus == "failed" {
			runtimeEventName = "platform.job.runtime.failed"
		}
		emitOrchestratorJobRuntimeEvent(runtimeCtx, runtimeEventName, runtimeStatus, iteration, runtime, runtimeResult, runtimeSpanAttrs)
		telemetry.End(runtimeSpan, runtimeStatus, runtimeSpanAttrs)
	}
	status = "completed"
	if runErr != nil {
		status = "failed"
		spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(runErr))
	}
	spanAttributes = withTelemetryField(spanAttributes, "runtimes_attempted", len(result.Runtimes))
	spanAttributes = withTelemetryField(spanAttributes, "runtimes_acquired", acquiredCount)
	return result, runErr
}

// runOrchestratorPhase wraps a single post-sync orchestrator step
// (`finding_rules`, `graph_ingest`, `graph_rules`) with a named telemetry
// span and a dedicated context timeout. The span surfaces a span_end
// event per phase — without it, a stall between source_runtime.sync and
// orchestrator.runtime is opaque: there's no way to tell which step is
// blocked from logs alone. The timeout decouples per-phase liveness from
// the runtime-level lease TTL, so a single Neo4j tx waiting on a row
// lock or a source.Read() retry storm can't park the iteration
// indefinitely. On context deadline the phase returns
// context.DeadlineExceeded, which the caller treats like any other
// failure (lease releases, next iteration retries).
//
// graphRuleQueryBudgetForPhase derives a per-graph-rule Cypher read budget that
// always trips before the graph-rule phase deadline, so a stuck rule surfaces an
// attributable per-rule timeout instead of a phase-cancellation connectivity
// error. A non-positive phase timeout returns 0 so the finding service keeps its
// own conservative default.
func graphRuleQueryBudgetForPhase(phaseTimeout time.Duration) time.Duration {
	if phaseTimeout <= 0 {
		return 0
	}
	if phaseTimeout > graphRulePhaseTimeoutMargin {
		return phaseTimeout - graphRulePhaseTimeoutMargin
	}
	// Phase budget is at or below the standard margin: keep a 10% headroom so the
	// per-rule deadline still fires first.
	return phaseTimeout - phaseTimeout/10
}

// The phase context is derived from runtimeCtx so it still receives
// lease-renewal cancellation. The generic R parameter lets each phase
// return its own result type without an interface boxing dance.
func runOrchestratorPhase[R any](runtimeCtx context.Context, name string, iteration uint32, runtime *cerebrov1.SourceRuntime, timeout time.Duration, fn func(context.Context) (R, error)) (R, error) {
	phaseCtx, cancel := context.WithTimeout(runtimeCtx, timeout)
	defer cancel()
	phaseCtx, span := telemetry.Start(phaseCtx, name, telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("runtime_id", runtime.GetId()),
		telemetryField("source_id", runtime.GetSourceId()),
		telemetryField("tenant_id", runtime.GetTenantId()),
		telemetryField("timeout_ms", timeout.Milliseconds()),
	))
	started := time.Now()
	emitOrchestratorJobPhaseStarted(phaseCtx, name, iteration, runtime, timeout)
	result, err := fn(phaseCtx)
	durationMs := time.Since(started).Milliseconds()
	status := "completed"
	phaseKey := orchestratorPhaseTelemetryKey(name)
	endAttrs := telemetry.Attrs(
		telemetryField("duration_ms", durationMs),
		telemetryField("phase."+phaseKey+".last_duration_ms", durationMs),
	)
	telemetry.MaxMain(phaseCtx, "phase."+phaseKey+".max_duration_ms", durationMs)
	if err != nil {
		status = "failed"
		endAttrs = withTelemetryField(endAttrs, "error_kind", telemetry.ErrorKind(err))
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(phaseCtx.Err(), context.DeadlineExceeded) {
			endAttrs = withTelemetryField(endAttrs, "timeout_exceeded", true)
		}
		captureOrchestratorError(phaseCtx, name+".error", iteration, runtime, name, err)
	}
	observability.RecordOrchestratorPhase(phaseCtx, observability.OrchestratorPhaseMetrics{
		PhaseKey:        phaseKey,
		SourceID:        runtime.GetSourceId(),
		Status:          status,
		ErrorKind:       errorKindForMetric(err),
		Duration:        time.Since(started),
		TimeoutExceeded: errors.Is(err, context.DeadlineExceeded) || errors.Is(phaseCtx.Err(), context.DeadlineExceeded),
	})
	emitOrchestratorJobPhaseEnded(phaseCtx, name, status, iteration, runtime, time.Since(started), timeout, endAttrs)
	telemetry.AnnotateMainPhase(phaseCtx, name, status, endAttrs.
		WithField(telemetryField("phase.iteration", iteration)).
		WithField(telemetryField("phase.runtime_id", runtime.GetId())).
		WithField(telemetryField("phase.source_id", runtime.GetSourceId())).
		WithField(telemetryField("phase.tenant_id", runtime.GetTenantId())))
	telemetry.End(span, status, endAttrs)
	return result, err
}

func errorKindForMetric(err error) string {
	if err == nil {
		return ""
	}
	return telemetry.ErrorKind(err)
}

func annotateOrchestratorRuntimeMain(ctx context.Context, result *orchestratorRuntimeResult, status string, attrs telemetry.Attributes) {
	if result == nil {
		return
	}
	telemetry.IncrementMain(ctx, "orchestrator.runtime.count", 1)
	switch status {
	case "completed":
		telemetry.IncrementMain(ctx, "orchestrator.runtime.completed.count", 1)
	case "skipped":
		telemetry.IncrementMain(ctx, "orchestrator.runtime.skipped.count", 1)
	case "failed":
		telemetry.IncrementMain(ctx, "orchestrator.runtime.failed.count", 1)
	}
	healthRecord := normalizedOrchestratorRuntimeHealth(result)
	healthState := sourcehealth.Evaluate(healthRecord)
	healthGate := orchestratorRuntimeHealthGate(healthRecord, healthState, status)
	if healthState.FreshnessState != "" {
		telemetry.IncrementMain(ctx, "orchestrator.runtime.freshness."+orchestratorPhaseTelemetryKey(healthState.FreshnessState)+".count", 1)
	}
	if healthState.BackfillEligible {
		telemetry.IncrementMain(ctx, "orchestrator.runtime.backfill_eligible.count", 1)
	}
	annotateOrchestratorHealthGateMain(ctx, healthRecord, healthState, healthGate)
	mainAttrs := attrs.With(telemetry.Attrs(
		telemetryField("runtime_id", result.RuntimeID),
		telemetryField("source_runtime_id", result.RuntimeID),
		telemetryField("source_id", result.SourceID),
		telemetryField("tenant_id", result.TenantID),
		telemetryField("job.runtime.status", status),
		telemetryField("job_runtime_status", status),
		telemetryField("orchestrator.runtime.last_status", status),
		telemetryField("orchestrator.runtime.last_runtime_id", result.RuntimeID),
		telemetryField("orchestrator.runtime.last_source_id", result.SourceID),
		telemetryField("orchestrator.runtime.last_tenant_id", result.TenantID),
		telemetryField("orchestrator.runtime.last_sync_status", result.Sync),
		telemetryField("orchestrator.runtime.last_graph_ingest_status", result.GraphIngest),
		telemetryField("orchestrator.runtime.last_finding_rules_status", result.FindingRules),
		telemetryField("orchestrator.runtime.last_graph_rules_status", result.GraphRules),
		telemetryField("orchestrator.runtime.last_pages_read", result.PagesRead),
		telemetryField("orchestrator.runtime.last_events_appended", result.EventsAppended),
		telemetryField("orchestrator.runtime.last_events_evaluated", result.EventsEvaluated),
		telemetryField("orchestrator.runtime.last_entities_projected", result.EntitiesProjected),
		telemetryField("orchestrator.runtime.last_links_projected", result.LinksProjected),
		telemetryField("orchestrator.runtime.last_finding_evaluations", result.FindingEvaluations),
		telemetryField("orchestrator.runtime.last_graph_rule_evaluations", result.GraphRuleEvaluations),
		telemetryField("orchestrator.runtime.last_graph_rule_findings", result.GraphRuleFindings),
		telemetryField("orchestrator.runtime.last_graph_rule_rows_read", result.GraphRuleRowsRead),
		telemetryField("source_runtime.family", healthRecord.Family),
		telemetryField("source_runtime.enabled_state", healthRecord.EnabledState),
		telemetryField("source_runtime.freshness_state", healthState.FreshnessState),
		telemetryField("source_runtime.source_sync_state", healthState.SourceSyncState),
		telemetryField("source_runtime.graph_ingest_state", healthState.GraphIngestState),
		telemetryField("source_runtime.finding_evaluation_state", healthState.FindingEvaluationState),
		telemetryField("source_runtime.failure_class", healthState.FailureClass),
		telemetryField("source_runtime.next_action", healthState.NextAction),
		telemetryField("source_runtime.backfill_eligible", healthState.BackfillEligible),
		telemetryField("source_runtime.sync_lag_seconds", optionalInt64Value(healthRecord.SyncLagSeconds)),
		telemetryField("source_runtime.watermark_lag_seconds", optionalInt64Value(healthRecord.WatermarkLagSeconds)),
		telemetryField("source_runtime.graph_lag_seconds", optionalInt64Value(healthRecord.GraphLagSeconds)),
		telemetryField("source_runtime.expected_cadence_seconds", optionalInt64Value(healthRecord.ExpectedCadenceSeconds)),
		telemetryField("source_runtime.stale_after_seconds", optionalInt64Value(healthRecord.StaleAfterSeconds)),
		telemetryField("source_runtime.cursor_pending", healthRecord.CursorPending),
		telemetryField("source_runtime.checkpoint_cursor_present", healthRecord.CheckpointCursorPresent),
		telemetryField("source_runtime.contract_probe_state", healthRecord.ContractProbeState),
		telemetryField("source_runtime.contract_probe_status", sourcehealth.ContractProbeStatus(healthRecord.ContractProbeState)),
		telemetryField("orchestrator.runtime_health_gate.status", healthGate.Status),
		telemetryField("orchestrator.runtime_health_gate.blocking_state", healthGate.BlockingState),
		telemetryField("orchestrator.runtime_health_gate.needs_attention", healthGate.NeedsAttention),
	))
	telemetry.AnnotateMainPhase(ctx, "orchestrator.runtime", status, mainAttrs)
}

type orchestratorHealthGate struct {
	Status         string
	BlockingState  string
	NeedsAttention bool
}

func orchestratorRuntimeHealthGate(record sourcehealth.Record, state sourcehealth.State, runtimeStatus string) orchestratorHealthGate {
	if strings.EqualFold(strings.TrimSpace(runtimeStatus), "failed") {
		return orchestratorHealthGate{Status: "blocked", BlockingState: "runtime_failed", NeedsAttention: true}
	}
	if state.FindingEvaluationState == "failed" {
		return orchestratorHealthGate{Status: "blocked", BlockingState: "finding_failed", NeedsAttention: true}
	}
	switch strings.TrimSpace(state.FreshnessState) {
	case "healthy":
		return orchestratorHealthGate{Status: "pass", BlockingState: "none"}
	case "source_failed", "graph_failed":
		return orchestratorHealthGate{Status: "blocked", BlockingState: state.FreshnessState, NeedsAttention: true}
	case "disabled":
		return orchestratorHealthGate{Status: "degraded", BlockingState: "disabled", NeedsAttention: true}
	case "source_stale", "graph_missing", "graph_behind":
		return orchestratorHealthGate{Status: "degraded", BlockingState: state.FreshnessState, NeedsAttention: true}
	}
	if strings.EqualFold(strings.TrimSpace(record.Status), "healthy") {
		return orchestratorHealthGate{Status: "degraded", BlockingState: "graph_missing", NeedsAttention: true}
	}
	return orchestratorHealthGate{Status: "degraded", BlockingState: "unknown", NeedsAttention: true}
}

func annotateOrchestratorHealthGateMain(ctx context.Context, record sourcehealth.Record, state sourcehealth.State, gate orchestratorHealthGate) {
	telemetry.IncrementMain(ctx, "orchestrator.runtime_health_gate.total_count", 1)
	telemetry.IncrementMain(ctx, "orchestrator.runtime_health_gate."+orchestratorPhaseTelemetryKey(gate.Status)+"_count", 1)
	if !gate.NeedsAttention {
		telemetry.IncrementMain(ctx, "orchestrator.runtime_health_gate.healthy_count", 1)
	} else {
		telemetry.IncrementMain(ctx, "orchestrator.runtime_health_gate.needs_attention_count", 1)
	}
	if state.BackfillEligible {
		telemetry.IncrementMain(ctx, "orchestrator.runtime_health_gate.backfill_eligible_count", 1)
	}
	if gate.BlockingState != "" && gate.BlockingState != "none" {
		telemetry.IncrementMain(ctx, "orchestrator.runtime_health_gate."+orchestratorPhaseTelemetryKey(gate.BlockingState)+".count", 1)
	}
	maxOptionalMain(ctx, "orchestrator.runtime_health_gate.max_sync_lag_seconds", record.SyncLagSeconds)
	maxOptionalMain(ctx, "orchestrator.runtime_health_gate.max_watermark_lag_seconds", record.WatermarkLagSeconds)
	maxOptionalMain(ctx, "orchestrator.runtime_health_gate.max_graph_lag_seconds", record.GraphLagSeconds)
}

func maxOptionalMain(ctx context.Context, key string, value *int64) {
	if value == nil {
		return
	}
	telemetry.MaxMain(ctx, key, *value)
}

func normalizedOrchestratorRuntimeHealth(result *orchestratorRuntimeResult) sourcehealth.Record {
	record := result.Health
	if strings.TrimSpace(record.RuntimeID) == "" {
		record.RuntimeID = result.RuntimeID
	}
	if strings.TrimSpace(record.SourceID) == "" {
		record.SourceID = result.SourceID
	}
	if strings.TrimSpace(record.TenantID) == "" {
		record.TenantID = result.TenantID
	}
	if strings.TrimSpace(record.EnabledState) == "" {
		record.EnabledState = "unknown"
	}
	if strings.TrimSpace(record.Status) == "" {
		record.Status = "unknown"
	}
	if strings.TrimSpace(record.ContractProbeState) == "" {
		record.ContractProbeState = "unknown"
	}
	if result.Sync == "failed" {
		record.Status = "failing"
		if strings.TrimSpace(record.LastFailureCategory) == "" {
			record.LastFailureCategory = "source_sync_failed"
		}
	}
	if record.LatestGraphRun == nil {
		switch result.GraphIngest {
		case "completed", "failed", "running", "pending":
			record.LatestGraphRun = &sourcehealth.GraphRun{Status: result.GraphIngest}
		}
	}
	if record.LatestFindingEvaluation == nil {
		switch result.FindingRules {
		case "completed", "failed", "running", "pending":
			record.LatestFindingEvaluation = &sourcehealth.FindingEvaluation{Status: result.FindingRules}
		}
	}
	return record
}

func withOrchestratorGraphHealth(record sourcehealth.Record, graphResult *graphingest.RunResult, graphStatus string, now time.Time) sourcehealth.Record {
	if graphResult == nil {
		if graphStatus != "" && graphStatus != "skipped" {
			record.LatestGraphRun = &sourcehealth.GraphRun{Status: graphStatus}
		}
		return record
	}
	status := strings.TrimSpace(graphResult.Run.Status)
	if status == "" {
		status = graphStatus
	}
	if status == "" {
		status = "unknown"
	}
	record.LatestGraphRun = &sourcehealth.GraphRun{Status: status}
	record.GraphLagSeconds = orchestratorGraphRunLagSeconds(now, graphResult.Run.StartedAt, graphResult.Run.FinishedAt)
	return record
}

func withOrchestratorFindingHealth(record sourcehealth.Record, findingStatus string) sourcehealth.Record {
	switch findingStatus {
	case "completed", "failed", "running", "pending":
		record.LatestFindingEvaluation = &sourcehealth.FindingEvaluation{Status: findingStatus}
	}
	return record
}

func orchestratorGraphRunLagSeconds(now time.Time, startedAt string, finishedAt string) *int64 {
	if finished, ok := parseOrchestratorRFC3339(finishedAt); ok {
		return orchestratorSecondsSince(now, finished)
	}
	if started, ok := parseOrchestratorRFC3339(startedAt); ok {
		return orchestratorSecondsSince(now, started)
	}
	return nil
}

func parseOrchestratorRFC3339(value string) (time.Time, bool) {
	text := strings.TrimSpace(value)
	if text == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func orchestratorSecondsSince(now time.Time, then time.Time) *int64 {
	seconds := int64(now.UTC().Sub(then.UTC()).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	return &seconds
}

func optionalInt64Value(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func captureOrchestratorError(ctx context.Context, name string, iteration uint32, runtime *cerebrov1.SourceRuntime, stage string, err error) {
	if err == nil {
		return
	}
	attrs := telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("stage", stage),
	)
	if runtime != nil {
		attrs = attrs.
			WithField(telemetryField("runtime_id", runtime.GetId())).
			WithField(telemetryField("source_id", runtime.GetSourceId())).
			WithField(telemetryField("tenant_id", runtime.GetTenantId()))
	}
	telemetry.AnnotateMainIfAbsent(ctx, orchestratorFirstFailureAttrs(name, attrs, iteration, runtime, stage, err))
	telemetry.CaptureError(ctx, name, err, attrs)
}

func orchestratorFirstFailureAttrs(name string, attrs telemetry.Attributes, iteration uint32, runtime *cerebrov1.SourceRuntime, stage string, err error) telemetry.Attributes {
	firstFailure := telemetry.Attrs(
		telemetryField("orchestrator.first_failure.present", true),
		telemetryField("orchestrator.first_failure.event_name", strings.TrimSpace(name)),
		telemetryField("orchestrator.first_failure.stage", strings.TrimSpace(stage)),
		telemetryField("orchestrator.first_failure.error_kind", telemetry.ErrorKind(err)),
		telemetryField("orchestrator.first_failure.error_fingerprint", telemetry.ErrorFingerprint(name, err, attrs)),
		telemetryField("orchestrator.first_failure.iteration", iteration),
	)
	if runtime != nil {
		firstFailure = firstFailure.With(telemetry.Attrs(
			telemetryField("orchestrator.first_failure.runtime_id", runtime.GetId()),
			telemetryField("orchestrator.first_failure.source_id", runtime.GetSourceId()),
			telemetryField("orchestrator.first_failure.tenant_id", runtime.GetTenantId()),
		))
	}
	return firstFailure
}

func applyGraphIngestCounters(runtimeResult *orchestratorRuntimeResult, graphResult *graphingest.RunResult, attrs telemetry.Attributes) telemetry.Attributes {
	if runtimeResult == nil || graphResult == nil || graphResult.Ingest == nil {
		return attrs
	}
	runtimeResult.EntitiesProjected = graphResult.Ingest.EntitiesProjected
	runtimeResult.LinksProjected = graphResult.Ingest.LinksProjected
	attrs = withTelemetryField(attrs, "entities_projected", runtimeResult.EntitiesProjected)
	attrs = withTelemetryField(attrs, "links_projected", runtimeResult.LinksProjected)
	return attrs
}

func applyGraphRuleCounters(runtimeResult *orchestratorRuntimeResult, graphRulesResult *findings.EvaluateGraphRulesResult, attrs telemetry.Attributes) telemetry.Attributes {
	if runtimeResult == nil || graphRulesResult == nil {
		return attrs
	}
	runtimeResult.GraphRuleEvaluations = len(graphRulesResult.Evaluations)
	var totalFindings int
	var totalRows uint32
	for _, evaluation := range graphRulesResult.Evaluations {
		if evaluation == nil {
			continue
		}
		totalFindings += len(evaluation.Findings)
		totalRows += evaluation.RowsRead
	}
	runtimeResult.GraphRuleFindings = totalFindings
	runtimeResult.GraphRuleRowsRead = totalRows
	attrs = withTelemetryField(attrs, "graph_rule_evaluations", runtimeResult.GraphRuleEvaluations)
	attrs = withTelemetryField(attrs, "graph_rule_findings", runtimeResult.GraphRuleFindings)
	attrs = withTelemetryField(attrs, "graph_rule_rows_read", runtimeResult.GraphRuleRowsRead)
	return attrs
}

// orchestratorEvaluatedGraphRuleIDs returns the graph-rule IDs already evaluated
// for a tenant this iteration, to be excluded from the next runtime's pass.
func orchestratorEvaluatedGraphRuleIDs(evaluated map[string]struct{}) []string {
	if len(evaluated) == 0 {
		return nil
	}
	ids := make([]string, 0, len(evaluated))
	for id := range evaluated {
		ids = append(ids, id)
	}
	return ids
}

// markOrchestratorTenantGraphRulesEvaluated records every graph rule attempted
// in a pass against the tenant so subsequent runtimes in the same iteration
// exclude it.
func markOrchestratorTenantGraphRulesEvaluated(evaluatedByTenant map[string]map[string]struct{}, tenantID string, result *findings.EvaluateGraphRulesResult) {
	if evaluatedByTenant == nil || result == nil {
		return
	}
	evaluated := evaluatedByTenant[tenantID]
	if evaluated == nil {
		evaluated = map[string]struct{}{}
		evaluatedByTenant[tenantID] = evaluated
	}
	for _, evaluation := range result.Evaluations {
		if evaluation == nil || evaluation.Rule == nil {
			continue
		}
		if id := strings.TrimSpace(evaluation.Rule.GetId()); id != "" {
			evaluated[id] = struct{}{}
		}
	}
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
	return sourceruntime.LeaseRenewalInterval(ttl)
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

func orchestratorRunID(schedule string, startedAt time.Time) string {
	schedule = orchestratorPhaseTelemetryKey(schedule)
	if schedule == "" {
		schedule = "run"
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	return fmt.Sprintf("orchestrator-%s-%d", schedule, startedAt.UTC().UnixNano())
}

func withOrchestratorJobMetadata(ctx context.Context, metadata orchestratorJobMetadata) context.Context {
	return context.WithValue(ctx, orchestratorJobMetadataContextKey{}, metadata)
}

func orchestratorJobMetadataFromContext(ctx context.Context) orchestratorJobMetadata {
	metadata, _ := ctx.Value(orchestratorJobMetadataContextKey{}).(orchestratorJobMetadata)
	if strings.TrimSpace(metadata.Kind) == "" {
		metadata.Kind = jobs.KindSourceRuntimeOrchestrate
	}
	if strings.TrimSpace(metadata.Name) == "" {
		metadata.Name = "orchestrator.run"
	}
	return metadata
}

func orchestratorJobAttrs(ctx context.Context) telemetry.Attributes {
	metadata := orchestratorJobMetadataFromContext(ctx)
	attrs := telemetry.Attrs(
		telemetryField("operation.type", "background_job"),
		telemetryField("workload.kind", "orchestrator"),
		telemetryField("job.id", metadata.ID),
		telemetryField("job.kind", metadata.Kind),
		telemetryField("job.name", metadata.Name),
		telemetryField("job.schedule", metadata.Schedule),
		telemetryField("job_id", metadata.ID),
		telemetryField("job_kind", metadata.Kind),
		telemetryField("job_name", metadata.Name),
		telemetryField("job_schedule", metadata.Schedule),
	)
	if !metadata.StartedAt.IsZero() {
		attrs = attrs.With(telemetry.Attrs(
			telemetryField("job.started_at_unix_ms", metadata.StartedAt.UTC().UnixMilli()),
			telemetryField("job.run_duration_ms", time.Since(metadata.StartedAt).Milliseconds()),
		))
	}
	return attrs
}

func emitOrchestratorJobHeartbeat(ctx context.Context, sequence uint32, stage string, extra telemetry.Attributes) {
	telemetry.IncrementMain(ctx, "job.heartbeat.count", 1)
	telemetry.Event(ctx, "platform.job.heartbeat", orchestratorJobAttrs(ctx).With(extra).With(telemetry.Attrs(
		telemetryField("job.status", "running"),
		telemetryField("job.heartbeat.sequence", sequence),
		telemetryField("job.heartbeat.stage", strings.TrimSpace(stage)),
		telemetryField("job.heartbeat.at_unix_ms", time.Now().UTC().UnixMilli()),
		telemetryField("job_heartbeat_sequence", sequence),
		telemetryField("job_heartbeat_stage", strings.TrimSpace(stage)),
	)))
}

func emitOrchestratorJobPhaseStarted(ctx context.Context, phase string, iteration uint32, runtime *cerebrov1.SourceRuntime, timeout time.Duration) {
	telemetry.IncrementMain(ctx, "job.phase.started.count", 1)
	telemetry.Event(ctx, "platform.job.phase.started", orchestratorJobAttrs(ctx).With(orchestratorPhaseEventAttrs(phase, "running", iteration, runtime, timeout, 0)).With(telemetry.Attrs(
		telemetryField("job.phase.started_at_unix_ms", time.Now().UTC().UnixMilli()),
	)))
}

func emitOrchestratorJobPhaseEnded(ctx context.Context, phase string, status string, iteration uint32, runtime *cerebrov1.SourceRuntime, duration time.Duration, timeout time.Duration, extra telemetry.Attributes) {
	phaseKey := orchestratorPhaseTelemetryKey(phase)
	telemetry.IncrementMain(ctx, "job.phase.finished.count", 1)
	telemetry.IncrementMain(ctx, "job.phase."+phaseKey+".finished.count", 1)
	if status == "failed" {
		telemetry.IncrementMain(ctx, "job.phase.failed.count", 1)
		telemetry.IncrementMain(ctx, "job.phase."+phaseKey+".failed.count", 1)
	}
	eventName := "platform.job.phase.completed"
	if status == "failed" {
		eventName = "platform.job.phase.failed"
	}
	telemetry.Event(ctx, eventName, orchestratorJobAttrs(ctx).With(orchestratorPhaseEventAttrs(phase, status, iteration, runtime, timeout, duration)).With(extra))
}

func orchestratorPhaseEventAttrs(phase string, status string, iteration uint32, runtime *cerebrov1.SourceRuntime, timeout time.Duration, duration time.Duration) telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("job.phase", strings.TrimSpace(phase)),
		telemetryField("job.phase_key", orchestratorPhaseTelemetryKey(phase)),
		telemetryField("job.phase.status", strings.TrimSpace(status)),
		telemetryField("job.phase.timeout_ms", timeout.Milliseconds()),
		telemetryField("job.phase.duration_ms", duration.Milliseconds()),
		telemetryField("job_phase", strings.TrimSpace(phase)),
		telemetryField("job_phase_key", orchestratorPhaseTelemetryKey(phase)),
		telemetryField("job_phase_status", strings.TrimSpace(status)),
		telemetryField("job_phase_timeout_ms", timeout.Milliseconds()),
		telemetryField("job_phase_duration_ms", duration.Milliseconds()),
		telemetryField("duration_ms", duration.Milliseconds()),
	)
	if runtime != nil {
		attrs = attrs.With(telemetry.Attrs(
			telemetryField("runtime_id", runtime.GetId()),
			telemetryField("source_runtime_id", runtime.GetId()),
			telemetryField("source_id", runtime.GetSourceId()),
			telemetryField("tenant_id", runtime.GetTenantId()),
		))
	}
	return attrs
}

func emitOrchestratorJobRuntimeEvent(ctx context.Context, name string, status string, iteration uint32, runtime *cerebrov1.SourceRuntime, result *orchestratorRuntimeResult, extra telemetry.Attributes) {
	telemetry.IncrementMain(ctx, "job.runtime.event.count", 1)
	if status != "" {
		telemetry.IncrementMain(ctx, "job.runtime."+orchestratorPhaseTelemetryKey(status)+".count", 1)
	}
	telemetry.Event(ctx, name, orchestratorJobAttrs(ctx).With(orchestratorRuntimeEventAttrs(status, iteration, runtime, result)).With(extra))
}

func orchestratorRuntimeEventAttrs(status string, iteration uint32, runtime *cerebrov1.SourceRuntime, result *orchestratorRuntimeResult) telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetryField("iteration", iteration),
		telemetryField("job.runtime.status", strings.TrimSpace(status)),
		telemetryField("job_runtime_status", strings.TrimSpace(status)),
	)
	if runtime != nil {
		attrs = attrs.With(telemetry.Attrs(
			telemetryField("runtime_id", runtime.GetId()),
			telemetryField("source_runtime_id", runtime.GetId()),
			telemetryField("source_id", runtime.GetSourceId()),
			telemetryField("tenant_id", runtime.GetTenantId()),
		))
	}
	if result != nil {
		attrs = attrs.With(telemetry.Attrs(
			telemetryField("runtime_id", result.RuntimeID),
			telemetryField("source_runtime_id", result.RuntimeID),
			telemetryField("source_id", result.SourceID),
			telemetryField("tenant_id", result.TenantID),
			telemetryField("sync.status", result.Sync),
			telemetryField("graph_ingest.status", result.GraphIngest),
			telemetryField("finding_rules.status", result.FindingRules),
			telemetryField("graph_rules.status", result.GraphRules),
			telemetryField("pages_read", result.PagesRead),
			telemetryField("events_appended", result.EventsAppended),
			telemetryField("events_evaluated", result.EventsEvaluated),
			telemetryField("entities_projected", result.EntitiesProjected),
			telemetryField("links_projected", result.LinksProjected),
			telemetryField("finding_evaluations", result.FindingEvaluations),
			telemetryField("graph_rule_evaluations", result.GraphRuleEvaluations),
			telemetryField("graph_rule_findings", result.GraphRuleFindings),
			telemetryField("graph_rule_rows_read", result.GraphRuleRowsRead),
			telemetryField("runtime_error_present", strings.TrimSpace(result.Error) != ""),
		))
	}
	return attrs
}

func telemetryField(key string, value any) telemetry.Field {
	return telemetry.Field{Key: key, Value: value}
}

func orchestratorPhaseTelemetryKey(name string) string {
	key := strings.TrimSpace(name)
	key = strings.ReplaceAll(key, ".", "_")
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.Trim(key, "_")
	if key == "" {
		return "unknown"
	}
	return key
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
