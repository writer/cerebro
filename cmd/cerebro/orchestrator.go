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
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
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
	RuntimeID            string `json:"runtime_id"`
	SourceID             string `json:"source_id,omitempty"`
	TenantID             string `json:"tenant_id,omitempty"`
	Sync                 string `json:"sync"`
	PagesRead            uint32 `json:"pages_read,omitempty"`
	EventsAppended       uint32 `json:"events_appended,omitempty"`
	FindingRules         string `json:"finding_rules"`
	EventsEvaluated      uint32 `json:"events_evaluated,omitempty"`
	FindingEvaluations   int    `json:"finding_evaluations,omitempty"`
	GraphIngest          string `json:"graph_ingest"`
	EntitiesProjected    uint32 `json:"entities_projected,omitempty"`
	LinksProjected       uint32 `json:"links_projected,omitempty"`
	GraphRules           string `json:"graph_rules"`
	GraphRuleEvaluations int    `json:"graph_rule_evaluations,omitempty"`
	GraphRuleFindings    int    `json:"graph_rule_findings,omitempty"`
	GraphRuleRowsRead    uint32 `json:"graph_rule_rows_read,omitempty"`
	Error                string `json:"error,omitempty"`
}

func runOrchestrator(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return usageError(fmt.Sprintf("usage: %s orchestrator run [runtime_id=<runtime-id>] [tenant_id=<tenant-id>] [source_id=<source-id>] [limit=N] [page_limit=N] [event_limit=N] [graph_page_limit=N] [phase_timeout=15m] [graph_timeout=45m] [interval=30s] [iterations=N|forever]", os.Args[0]))
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
	ctx, span := telemetry.StartMain(ctx, "orchestrator.run", telemetry.Attrs(
		telemetryField("runtime_id", options.Filter.RuntimeID),
		telemetryField("tenant_id", options.Filter.TenantID),
		telemetryField("source_id", options.Filter.SourceID),
		telemetryField("limit", options.Filter.Limit),
		telemetryField("page_limit", options.PageLimit),
		telemetryField("event_limit", options.EventLimit),
		telemetryField("graph_page_limit", options.GraphPageLimit),
		telemetryField("phase_timeout_ms", options.PhaseTimeout.Milliseconds()),
		telemetryField("graph_timeout_ms", options.GraphTimeout.Milliseconds()),
		telemetryField("iterations", options.Iterations),
		telemetryField("run_forever", options.RunForever),
	))
	status := "failed"
	spanAttributes := telemetry.Attrs()
	defer func() {
		if err != nil {
			status = "failed"
			spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(err))
		}
		telemetry.AnnotateMain(ctx, spanAttributes.WithField(telemetry.Field{Key: "orchestrator.status", Value: status}))
		telemetry.End(span, status, spanAttributes)
	}()
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
	runtimeService := newOrchestratorRuntimeService(registry, lister, deps.AppendLog, deps.StateStore)
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
			spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(ctx.Err()))
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
		telemetryField("tenant_id", options.Filter.TenantID),
		telemetryField("source_id", options.Filter.SourceID),
		telemetryField("limit", options.Filter.Limit),
		telemetryField("phase_timeout_ms", options.PhaseTimeout.Milliseconds()),
		telemetryField("graph_timeout_ms", options.GraphTimeout.Milliseconds()),
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
		spanAttributes = withTelemetryField(spanAttributes, "error_kind", telemetry.ErrorKind(err))
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
		)
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
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_stage", "lease")
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_kind", telemetry.ErrorKind(err))
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
		syncStartCursorOpaque := orchestratorRuntimeStartCursorOpaque(runtime)
		syncResult, err := runtimeService.Sync(runtimeCtx, &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId(), PageLimit: options.PageLimit})
		if err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "sync", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_stage", "sync")
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "error_kind", telemetry.ErrorKind(err))
			cancelRuntime()
			if renewalErr := stopLeaseRenewal(); renewalErr != nil {
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "renew_lease", renewalErr)
				runErr = renewalErr
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "renew_lease_error_kind", telemetry.ErrorKind(renewalErr))
			}
			if releaseErr := releaseOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner); releaseErr != nil {
				runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "release_lease", releaseErr)
				runErr = releaseErr
				runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "release_lease_error_kind", telemetry.ErrorKind(releaseErr))
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
		// Run graph rules whenever the projection has caught up to the same cursor
		// reached by source sync, even if a trailing PutIngestRun(completed) write
		// failed. The graph is fresh enough for read-only rules at that point.
		if graphIngestReadyForGraphRules(graphResult, syncResult.GetRuntime().GetNextCursor()) {
			graphRulesResult, err := runOrchestratorPhase(runtimeCtx, "orchestrator.graph_rules", iteration, runtime, options.PhaseTimeout, func(phaseCtx context.Context) (*findings.EvaluateGraphRulesResult, error) {
				return findingService.EvaluateSourceRuntimeGraphRules(phaseCtx, findings.EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()})
			})
			runtimeSpanAttrs = applyGraphRuleCounters(runtimeResult, graphRulesResult, runtimeSpanAttrs)
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
		}
		if err := releaseOrchestratorRuntimeLease(ctx, leaser, runtime, leaseOwner); err != nil {
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "release_lease", err)
			runErr = err
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "release_lease_error_kind", telemetry.ErrorKind(err))
		}
		result.Runtimes = append(result.Runtimes, runtimeResult)
		if runtimeResult.Error == "" {
			runtimeStatus = "completed"
		}
		if runtimeResult.Error != "" {
			runtimeSpanAttrs = withTelemetryField(runtimeSpanAttrs, "runtime_error_present", true)
		}
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
	result, err := fn(phaseCtx)
	status := "completed"
	endAttrs := telemetry.Attrs()
	if err != nil {
		status = "failed"
		endAttrs = withTelemetryField(endAttrs, "error_kind", telemetry.ErrorKind(err))
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(phaseCtx.Err(), context.DeadlineExceeded) {
			endAttrs = withTelemetryField(endAttrs, "timeout_exceeded", true)
		}
	}
	telemetry.End(span, status, endAttrs)
	return result, err
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
