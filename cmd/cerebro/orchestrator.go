package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const defaultOrchestratorIterations = 1

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
	RuntimeID    string `json:"runtime_id"`
	SourceID     string `json:"source_id,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	Sync         string `json:"sync"`
	FindingRules string `json:"finding_rules"`
	GraphIngest  string `json:"graph_ingest"`
	Error        string `json:"error,omitempty"`
}

func runOrchestrator(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return usageError(fmt.Sprintf("usage: %s orchestrator run [tenant_id=<tenant-id>] [source_id=<source-id>] [limit=N] [page_limit=N] [event_limit=N] [graph_page_limit=N] [interval=30s] [iterations=N|forever]", os.Args[0]))
	}
	options, err := parseOrchestratorOptions(args[1:])
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
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

func parseOrchestratorOptions(args []string) (orchestratorOptions, error) {
	options := orchestratorOptions{Iterations: defaultOrchestratorIterations}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return orchestratorOptions{}, fmt.Errorf("invalid orchestrator argument %q; want key=value", arg)
		}
		switch key {
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
	runtimeService := sourceruntime.New(
		registry,
		lister,
		deps.AppendLog,
		sourceProjector(deps.StateStore, deps.GraphStore),
	).WithConfigResolver(config.ResolveSourceConfigSecretReferences)
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
	).WithConfigPreparer(config.ResolveSourceConfigSecretReferences)
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
		iterationResult, err := runOrchestratorIteration(ctx, lister, runtimeService, findingService, graphService, options, iteration)
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
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
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
	runtimeService *sourceruntime.Service,
	findingService *findings.Service,
	graphService *graphingest.Service,
	options orchestratorOptions,
	iteration uint32,
) (*orchestratorIterationResult, error) {
	runtimes, err := lister.ListSourceRuntimes(ctx, options.Filter)
	result := &orchestratorIterationResult{Iteration: iteration, StartedAt: time.Now().UTC()}
	if err != nil {
		return result, err
	}
	var runErr error
	for _, runtime := range runtimes {
		runtimeResult := &orchestratorRuntimeResult{
			RuntimeID: strings.TrimSpace(runtime.GetId()),
			SourceID:  strings.TrimSpace(runtime.GetSourceId()),
			TenantID:  strings.TrimSpace(runtime.GetTenantId()),
		}
		if err := touchOrchestratorRuntime(ctx, lister, runtime); err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "touch", err)
			result.Runtimes = append(result.Runtimes, runtimeResult)
			runErr = err
			continue
		}
		if _, err := runtimeService.Sync(ctx, &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId(), PageLimit: options.PageLimit}); err != nil {
			runtimeResult.Sync = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "sync", err)
			runErr = err
		} else {
			runtimeResult.Sync = "completed"
		}
		if _, err := findingService.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{RuntimeID: runtime.GetId(), EventLimit: options.EventLimit}); err != nil {
			runtimeResult.FindingRules = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "finding_rules", err)
			runErr = err
		} else {
			runtimeResult.FindingRules = "completed"
		}
		if _, err := graphService.RunRuntime(ctx, graphingest.RuntimeRequest{RuntimeID: runtime.GetId(), PageLimit: options.GraphPageLimit, Trigger: "orchestrator"}); err != nil {
			runtimeResult.GraphIngest = "failed"
			runtimeResult.Error = appendRuntimeError(runtimeResult.Error, "graph_ingest", err)
			runErr = err
		} else {
			runtimeResult.GraphIngest = "completed"
		}
		result.Runtimes = append(result.Runtimes, runtimeResult)
	}
	return result, runErr
}

func touchOrchestratorRuntime(ctx context.Context, store ports.SourceRuntimeStore, runtime *cerebrov1.SourceRuntime) error {
	if store == nil || runtime == nil {
		return nil
	}
	return store.PutSourceRuntime(ctx, runtime)
}

func appendRuntimeError(existing string, stage string, err error) string {
	message := fmt.Sprintf("%s: %v", stage, err)
	if strings.TrimSpace(existing) == "" {
		return message
	}
	return existing + "; " + message
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
