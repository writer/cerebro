package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/graphrebuild"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGraphIngestPageLimit     = 1
	maxGraphIngestPageLimit         = 100
	maxGraphIngestRuntimeIterations = 10000
	defaultGraphPathsTimeout        = 60 * time.Second
	defaultGraphHealthRunningWindow = 60
	graphHealthErrorDetailLimit     = 500
)

var (
	errEndpointOwnerIDCleanupUnsupported = errors.New("endpoint owner-id link cleanup is unsupported by configured stores")
	errEndpointOwnerIDStateCleanupFailed = errors.New("state endpoint owner-id link cleanup failed")
	errEndpointOwnerIDGraphCleanupFailed = errors.New("graph endpoint owner-id link cleanup failed")
)

type graphCountsStore interface {
	Counts(context.Context) (graphstore.Counts, error)
}

type graphRelationCountsStore interface {
	RelationCounts(context.Context, []string) (graphstore.RelationCounts, error)
}

type graphQueryStore interface {
	Ping(context.Context) error
	GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error)
	ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error)
}

type graphPathStore interface {
	PathPatterns(context.Context, int) ([]graphstore.PathPattern, error)
	SampleTraversals(context.Context, int) ([]graphstore.Traversal, error)
	Topology(context.Context) (graphstore.Topology, error)
}

type graphIntegrityStore interface {
	IntegrityChecks(context.Context) ([]graphstore.IntegrityCheck, error)
}

type graphTopologyStore interface {
	Topology(context.Context) (graphstore.Topology, error)
}

type graphOpenFindingPrimaryLinkRepairStore interface {
	RepairOpenFindingPrimaryLinks(context.Context, graphstore.OpenFindingPrimaryLinkRepairRequest) (graphstore.OpenFindingPrimaryLinkRepairResult, error)
}

type graphBackfillEntityTypedPropertiesStore interface {
	BackfillEntityTypedProperties(context.Context, graphstore.BackfillEntityTypedPropertiesRequest) (graphstore.BackfillEntityTypedPropertiesResult, error)
}

type graphIngestRunStore interface {
	ListIngestRuns(context.Context, graphstore.IngestRunFilter) ([]graphstore.IngestRun, error)
}

type graphIngestCheckpointStore interface {
	GetIngestCheckpoint(context.Context, string) (graphstore.IngestCheckpoint, bool, error)
	PutIngestCheckpoint(context.Context, graphstore.IngestCheckpoint) error
}

type graphIngestOptions struct {
	SourceID          string
	SourceConfig      map[string]string
	TenantID          string
	PageLimit         uint32
	Cursor            *cerebrov1.SourceCursor
	CheckpointEnabled bool
	CheckpointID      string
	ResetCheckpoint   bool
}

type graphIngestRuntimeOptions struct {
	RuntimeID       string
	PageLimit       uint32
	CheckpointID    string
	ResetCheckpoint bool
	Interval        time.Duration
	Iterations      uint32
	RunForever      bool
}

type graphIngestResult struct {
	SourceID               string `json:"source_id"`
	TenantID               string `json:"tenant_id,omitempty"`
	PagesRead              uint32 `json:"pages_read"`
	EventsRead             uint32 `json:"events_read"`
	EntitiesProjected      uint32 `json:"entities_projected"`
	LinksProjected         uint32 `json:"links_projected"`
	GraphNodesBefore       int64  `json:"graph_nodes_before,omitempty"`
	GraphLinksBefore       int64  `json:"graph_links_before,omitempty"`
	GraphNodesAfter        int64  `json:"graph_nodes_after,omitempty"`
	GraphLinksAfter        int64  `json:"graph_links_after,omitempty"`
	NextCursor             string `json:"next_cursor,omitempty"`
	CheckpointID           string `json:"checkpoint_id,omitempty"`
	CheckpointCursor       string `json:"checkpoint_cursor,omitempty"`
	CheckpointResumed      bool   `json:"checkpoint_resumed,omitempty"`
	CheckpointPersisted    bool   `json:"checkpoint_persisted,omitempty"`
	CheckpointComplete     bool   `json:"checkpoint_complete,omitempty"`
	CheckpointAlreadyFresh bool   `json:"checkpoint_already_fresh,omitempty"`
}

type graphIngestRuntimeRunnerResult struct {
	RuntimeID  string                   `json:"runtime_id"`
	Iterations uint32                   `json:"iterations"`
	RunForever bool                     `json:"run_forever,omitempty"`
	Interval   string                   `json:"interval,omitempty"`
	Runs       []*graphingest.RunResult `json:"runs"`
}

type graphIngestRunsOptions struct {
	RuntimeID  string
	RuntimeIDs []string
	Status     string
	Limit      int
}

type graphHealthOptions struct {
	IngestLimit                  int
	MaxRunningMinutes            int
	RequiredRelations            []string
	ReportRelations              []string
	MaxIsolatedRatio             float64
	DeclaredRuntimeIDs           []string
	AllowTransientSourceFailures bool
}

type graphHealthResult struct {
	Status                 string                    `json:"status"`
	CheckedAt              time.Time                 `json:"checked_at"`
	Counts                 graphstore.Counts         `json:"counts"`
	Topology               *graphstore.Topology      `json:"topology,omitempty"`
	Integrity              graphIntegrityResult      `json:"integrity"`
	RelationCounts         graphstore.RelationCounts `json:"relation_counts,omitempty"`
	ReportedRelationCounts graphstore.RelationCounts `json:"reported_relation_counts,omitempty"`
	Ingest                 graphHealthIngestResult   `json:"ingest"`
	Failures               []string                  `json:"failures,omitempty"`
	Warnings               []string                  `json:"warnings,omitempty"`
}

type graphHealthIngestResult struct {
	CurrentRuntimeCount        int                    `json:"current_runtime_count"`
	DeclaredRuntimeCount       int                    `json:"declared_runtime_count,omitempty"`
	MissingRuntimeIDs          []string               `json:"missing_runtime_ids,omitempty"`
	FailedRuns                 []graphstore.IngestRun `json:"failed_runs,omitempty"`
	StaleRunningRuns           []graphstore.IngestRun `json:"stale_running_runs,omitempty"`
	ZeroProjectionRuns         []graphstore.IngestRun `json:"zero_projection_runs,omitempty"`
	IgnoredTransientFailedRuns []graphstore.IngestRun `json:"ignored_transient_failed_runs,omitempty"`
}

type graphEndpointOwnerIDCleanupOptions struct {
	TenantID  string
	SourceID  string
	RuntimeID string
	Limit     uint32
	DryRun    bool
}

type graphEndpointOwnerIDCleanupResult struct {
	TenantID   string                            `json:"tenant_id"`
	SourceID   string                            `json:"source_id,omitempty"`
	RuntimeID  string                            `json:"runtime_id,omitempty"`
	Limit      uint32                            `json:"limit,omitempty"`
	DryRun     bool                              `json:"dry_run"`
	StateStore ports.ProjectionLinkCleanupResult `json:"state_store"`
	GraphStore ports.ProjectionLinkCleanupResult `json:"graph_store"`
}

type graphProjectedEntityCleanupOptions struct {
	TenantID     string
	SourceID     string
	RuntimeID    string
	FindingID    string
	EntityTypes  []string
	URNPrefixes  []string
	OnlyIsolated bool
	Limit        uint32
	DryRun       bool
	AllowDetach  bool
}

type graphOpenFindingPrimaryLinkRepairOptions struct {
	Limit  uint32
	DryRun bool
}

type graphBackfillEntityTypedPropertiesOptions struct {
	BatchSize uint32
	DryRun    bool
}

type graphProjectedEntityCleanupResult struct {
	TenantID     string                        `json:"tenant_id"`
	SourceID     string                        `json:"source_id,omitempty"`
	RuntimeID    string                        `json:"runtime_id,omitempty"`
	FindingID    string                        `json:"finding_id,omitempty"`
	EntityTypes  []string                      `json:"entity_types,omitempty"`
	URNPrefixes  []string                      `json:"urn_prefixes,omitempty"`
	OnlyIsolated bool                          `json:"only_isolated"`
	Limit        uint32                        `json:"limit,omitempty"`
	DryRun       bool                          `json:"dry_run"`
	StateStore   ports.ProjectionCleanupResult `json:"state_store"`
	GraphStore   ports.ProjectionCleanupResult `json:"graph_store"`
}

type graphPathsResult struct {
	Patterns   []graphstore.PathPattern `json:"patterns"`
	Traversals []graphstore.Traversal   `json:"traversals"`
	Topology   graphstore.Topology      `json:"topology"`
}

type graphRelationCountsResult struct {
	Relations graphstore.RelationCounts `json:"relations"`
}

type graphIntegrityResult struct {
	Checks []graphstore.IntegrityCheck `json:"checks"`
	Passed uint32                      `json:"passed"`
	Failed uint32                      `json:"failed"`
}

func runGraph(args []string) error {
	if len(args) == 0 {
		return usageError(graphUsage())
	}
	switch args[0] {
	case "ingest":
		options, err := parseGraphIngestArgs(args[1:])
		if err != nil {
			return err
		}
		ctx := context.Background()
		deps, closeDeps, err := openGraphDependencies(ctx)
		if err != nil {
			return err
		}
		defer logClose(closeDeps)
		options.SourceConfig, err = prepareSourceConfig(ctx, options.SourceID, "read", options.SourceConfig)
		if err != nil {
			return err
		}
		options.SourceConfig, err = config.ResolveSourceConfigSecretReferences(ctx, options.SourceID, options.SourceConfig)
		if err != nil {
			return err
		}
		registry, err := sourceregistry.Builtin()
		if err != nil {
			return fmt.Errorf("open source registry: %w", err)
		}
		projector := sourceProjector(nil, deps.GraphStore)
		if projector == nil {
			return fmt.Errorf("projection graph store is required")
		}
		result, err := ingestGraph(ctx, sourceops.New(registry), projector, deps.GraphStore, options)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "ingest-runtime":
		options, err := parseGraphIngestRuntimeArgs(args[1:])
		if err != nil {
			return err
		}
		shutdownCtx := context.Background()
		ctx, stop := signal.NotifyContext(shutdownCtx, os.Interrupt)
		defer stop()
		deps, closeDeps, err := openGraphDependenciesWithShutdown(ctx, shutdownCtx)
		if err != nil {
			return err
		}
		defer logClose(closeDeps)
		result, runErr := runGraphIngestRuntime(ctx, deps, options)
		if err := printJSON(result); err != nil {
			return err
		}
		return runErr
	case "ingest-run":
		return runGraphIngestRun(args[1:])
	case "ingest-runs":
		return runGraphIngestRuns(args[1:])
	case "cleanup-endpoint-owner-id-links":
		options, err := parseGraphEndpointOwnerIDCleanupArgs(args[1:])
		if err != nil {
			return err
		}
		ctx := context.Background()
		deps, closeDeps, err := openGraphCleanupDependencies(ctx)
		if err != nil {
			return err
		}
		defer logClose(closeDeps)
		result, err := cleanupEndpointOwnerIDLinks(ctx, deps, options)
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "cleanup-projected-entities":
		options, err := parseGraphProjectedEntityCleanupArgs(args[1:])
		if err != nil {
			return err
		}
		ctx := context.Background()
		deps, closeDeps, err := openGraphCleanupDependencies(ctx)
		if err != nil {
			return err
		}
		defer logClose(closeDeps)
		result, err := cleanupProjectedEntities(ctx, deps, options)
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "repair-open-finding-primary-links":
		options, err := parseGraphOpenFindingPrimaryLinkRepairArgs(args[1:])
		if err != nil {
			return err
		}
		ctx := context.Background()
		deps, closeDeps, err := openGraphCleanupDependencies(ctx)
		if err != nil {
			return err
		}
		defer logClose(closeDeps)
		result, err := repairOpenFindingPrimaryLinks(ctx, deps, options)
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "backfill-entity-typed-properties":
		options, err := parseGraphBackfillEntityTypedPropertiesArgs(args[1:])
		if err != nil {
			return err
		}
		ctx := context.Background()
		deps, closeDeps, err := openGraphCleanupDependencies(ctx)
		if err != nil {
			return err
		}
		defer logClose(closeDeps)
		result, err := backfillEntityTypedProperties(ctx, deps, options)
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "health":
		return runGraphHealth(args[1:])
	case "counts", "neighborhood", "paths", "relation-counts", "integrity":
		return runGraphInspect(args)
	case "cve-impact", "package-exposure", "asset-vulns":
		return runGraphImpact(args)
	case "inspect":
		if len(args) < 2 {
			return usageError(graphInspectUsage())
		}
		return runGraphInspect(args[1:])
	case "rebuild":
		runtimeID, mode, pageLimit, eventLimit, previewLimit, dryRun, err := parseGraphRebuildArgs(args[1:])
		if err != nil {
			return err
		}
		if !dryRun {
			return fmt.Errorf("graph rebuild currently only supports dry_run=true")
		}
		ctx := context.Background()
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
		if err != nil {
			return fmt.Errorf("configure telemetry: %w", err)
		}
		defer shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
		if err != nil {
			return fmt.Errorf("open dependencies: %w", err)
		}
		defer logClose(closeDeps)
		registry, err := sourceregistry.Builtin()
		if err != nil {
			return fmt.Errorf("open source registry: %w", err)
		}
		var replayer ports.EventReplayer
		if deps.AppendLog != nil {
			if typed, ok := deps.AppendLog.(ports.EventReplayer); ok {
				replayer = typed
			}
		}
		service := graphrebuild.New(registry, sourceRuntimeStore(deps.StateStore), replayer).WithConfigPreparer(config.ResolveSourceRuntimeConfigSecretReferences)
		result, err := service.RebuildDryRun(ctx, graphrebuild.Request{
			Mode:         mode,
			RuntimeID:    runtimeID,
			PageLimit:    pageLimit,
			EventLimit:   eventLimit,
			PreviewLimit: previewLimit,
		})
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return usageError(graphUsage())
	}
}

func graphUsage() string {
	return fmt.Sprintf("usage: %s graph [health|counts|neighborhood|paths|relation-counts|integrity|cve-impact|package-exposure|asset-vulns|ingest|ingest-runtime|ingest-run|ingest-runs|cleanup-endpoint-owner-id-links|cleanup-projected-entities|repair-open-finding-primary-links|backfill-entity-typed-properties|rebuild|inspect] ...", os.Args[0])
}

func graphIngestUsage() string {
	return fmt.Sprintf("usage: %s graph ingest <source-id> [tenant_id=<tenant-id>] [page_limit=N] [cursor=<cursor>] [checkpoint=true] [checkpoint_id=<id>] [reset_checkpoint=true] [key=value ...]", os.Args[0])
}

func graphIngestRuntimeUsage() string {
	return fmt.Sprintf("usage: %s graph ingest-runtime <runtime-id> [page_limit=N] [checkpoint_id=<id>] [reset_checkpoint=true] [interval=30s] [iterations=N|forever]", os.Args[0])
}

func graphIngestRunUsage() string {
	return fmt.Sprintf("usage: %s graph ingest-run <run-id>", os.Args[0])
}

func graphInspectUsage() string {
	return fmt.Sprintf("usage: %s graph [counts|neighborhood <urn>|paths|relation-counts|integrity] [limit=N] [relations=a,b]", os.Args[0])
}

func graphImpactUsage() string {
	return fmt.Sprintf("usage: %s graph [cve-impact <CVE|GHSA>|package-exposure <package|purl>|asset-vulns <urn>] tenant_id=<tenant-id> [limit=N] [depth=N]", os.Args[0])
}

func graphEndpointOwnerIDCleanupUsage() string {
	return fmt.Sprintf("usage: %s graph cleanup-endpoint-owner-id-links tenant_id=<tenant-id> [source_id=kolide|kandji] [runtime_id=<runtime-id>] [limit=N] [dry_run=true|apply=true]", os.Args[0])
}

func graphProjectedEntityCleanupUsage() string {
	return fmt.Sprintf("usage: %s graph cleanup-projected-entities tenant_id=<tenant-id> [source_id=<source-id>] [runtime_id=<runtime-id>] [finding_id=<finding-id>] [entity_type=a,b] [urn_prefix=a,b] [only_isolated=true] [limit=N] [dry_run=true|apply=true] [allow_detach=true]", os.Args[0])
}

func runGraphInspect(args []string) error {
	if len(args) == 0 {
		return usageError(graphInspectUsage())
	}
	ctx := context.Background()
	deps, closeDeps, err := openGraphDependencies(ctx)
	if err != nil {
		return err
	}
	defer logClose(closeDeps)

	switch args[0] {
	case "counts":
		store, ok := deps.GraphStore.(graphCountsStore)
		if !ok {
			return fmt.Errorf("graph store does not support counts")
		}
		counts, err := store.Counts(ctx)
		if err != nil {
			return err
		}
		return printJSON(counts)
	case "neighborhood":
		rootURN, limit, err := parseGraphNeighborhoodArgs(args[1:])
		if err != nil {
			return err
		}
		store, ok := deps.GraphStore.(graphQueryStore)
		if !ok {
			return fmt.Errorf("graph store does not support neighborhoods")
		}
		neighborhood, err := store.GetEntityNeighborhood(ctx, rootURN, limit)
		if err != nil {
			return err
		}
		return printJSON(neighborhood)
	case "paths":
		limit, err := parseGraphLimitArgs(args[1:], 10, "paths")
		if err != nil {
			return err
		}
		store, ok := deps.GraphStore.(graphPathStore)
		if !ok {
			return fmt.Errorf("graph store does not support paths")
		}
		pathCtx, cancel := context.WithTimeout(ctx, defaultGraphPathsTimeout)
		defer cancel()
		patterns, err := store.PathPatterns(pathCtx, limit)
		if err != nil {
			return err
		}
		traversals, err := store.SampleTraversals(pathCtx, limit)
		if err != nil {
			return err
		}
		topology, err := store.Topology(pathCtx)
		if err != nil {
			return err
		}
		return printJSON(graphPathsResult{Patterns: patterns, Traversals: traversals, Topology: topology})
	case "relation-counts":
		relations, err := parseGraphRelationCountsArgs(args[1:])
		if err != nil {
			return err
		}
		store, ok := deps.GraphStore.(graphRelationCountsStore)
		if !ok {
			return fmt.Errorf("graph store does not support relation counts")
		}
		counts, err := store.RelationCounts(ctx, relations)
		if err != nil {
			return err
		}
		return printJSON(graphRelationCountsResult{Relations: counts})
	case "integrity":
		store, ok := deps.GraphStore.(graphIntegrityStore)
		if !ok {
			return fmt.Errorf("graph store does not support integrity checks")
		}
		checks, err := store.IntegrityChecks(ctx)
		if err != nil {
			return err
		}
		result := graphIntegrityResult{Checks: checks}
		for _, check := range checks {
			if check.Passed {
				result.Passed++
			} else {
				result.Failed++
			}
		}
		return printJSON(result)
	default:
		return usageError(graphInspectUsage())
	}
}

func runGraphHealth(args []string) error {
	options, err := parseGraphHealthArgs(args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	deps, closeDeps, err := openGraphDependencies(ctx)
	if err != nil {
		return err
	}
	defer logClose(closeDeps)
	if len(options.DeclaredRuntimeIDs) == 0 {
		declaredRuntimeIDs, err := graphHealthDeclaredRuntimeIDs(ctx, deps)
		if err != nil {
			return err
		}
		options.DeclaredRuntimeIDs = declaredRuntimeIDs
	}
	result, err := checkGraphHealth(ctx, deps.GraphStore, options, time.Now().UTC())
	if printErr := printJSON(result); printErr != nil {
		return printErr
	}
	return err
}

func graphHealthDeclaredRuntimeIDs(ctx context.Context, deps bootstrap.Dependencies) ([]string, error) {
	lister, ok := deps.StateStore.(ports.SourceRuntimeListStore)
	if !ok {
		return nil, nil
	}
	runtimes, err := lister.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{Limit: graphingest.MaxStatusLimit})
	if err != nil {
		return nil, fmt.Errorf("list declared source runtimes: %w", err)
	}
	runtimeIDs := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtimeID := strings.TrimSpace(runtime.GetId()); runtimeID != "" {
			runtimeIDs = append(runtimeIDs, runtimeID)
		}
	}
	sort.Strings(runtimeIDs)
	return runtimeIDs, nil
}

func checkGraphHealth(ctx context.Context, store ports.GraphStore, options graphHealthOptions, now time.Time) (graphHealthResult, error) {
	result := graphHealthResult{
		Status:    "passed",
		CheckedAt: now.UTC(),
		Ingest: graphHealthIngestResult{
			DeclaredRuntimeCount: len(options.DeclaredRuntimeIDs),
		},
	}
	addFailure := func(format string, args ...any) {
		result.Failures = append(result.Failures, fmt.Sprintf(format, args...))
	}
	addWarning := func(format string, args ...any) {
		result.Warnings = append(result.Warnings, fmt.Sprintf(format, args...))
	}

	countsStore, ok := store.(graphCountsStore)
	if !ok {
		addFailure("graph store does not support counts")
	} else {
		counts, err := countsStore.Counts(ctx)
		if err != nil {
			addFailure("count graph records: %v", err)
		} else {
			result.Counts = counts
			if counts.Nodes <= 0 {
				addFailure("graph has zero nodes")
			}
			if counts.Relations <= 0 {
				addFailure("graph has zero relationships")
			}
		}
	}

	if topologyStore, ok := store.(graphTopologyStore); ok {
		topology, err := topologyStore.Topology(ctx)
		if err != nil {
			addWarning("compute graph topology: %v", err)
		} else {
			result.Topology = &topology
			total := topology.Isolated + topology.SourcesOnly + topology.SinksOnly + topology.Intermediates
			if total > 0 && options.MaxIsolatedRatio > 0 {
				ratio := float64(topology.Isolated) / float64(total)
				if ratio > options.MaxIsolatedRatio {
					addWarning("graph isolated-node ratio %.4f exceeds max %.4f (%d isolated of %d nodes)", ratio, options.MaxIsolatedRatio, topology.Isolated, total)
				}
			}
		}
	}

	integrityStore, ok := store.(graphIntegrityStore)
	if !ok {
		addFailure("graph store does not support integrity checks")
	} else {
		checks, err := integrityStore.IntegrityChecks(ctx)
		if err != nil {
			addFailure("run graph integrity checks: %v", err)
		} else {
			result.Integrity.Checks = checks
			for _, check := range checks {
				if check.Passed {
					result.Integrity.Passed++
				} else {
					result.Integrity.Failed++
					addFailure("graph integrity check %q failed: actual=%d expected=%d", check.Name, check.Actual, check.Expected)
				}
			}
		}
	}

	if len(options.RequiredRelations) != 0 {
		relationStore, ok := store.(graphRelationCountsStore)
		if !ok {
			addFailure("graph store does not support relation counts")
		} else {
			counts, err := relationStore.RelationCounts(ctx, options.RequiredRelations)
			if err != nil {
				addFailure("count graph relation records: %v", err)
			} else {
				result.RelationCounts = counts
				for _, relation := range options.RequiredRelations {
					if counts[relation] <= 0 {
						addFailure("graph relation %q has zero relationships", relation)
					}
				}
			}
		}
	}

	if len(options.ReportRelations) != 0 {
		relationStore, ok := store.(graphRelationCountsStore)
		if !ok {
			addWarning("graph store does not support relation counts for reporting")
		} else {
			counts, err := relationStore.RelationCounts(ctx, options.ReportRelations)
			if err != nil {
				addWarning("count reported graph relation records: %v", err)
			} else {
				result.ReportedRelationCounts = counts
				var zeroed []string
				for _, relation := range options.ReportRelations {
					if counts[relation] <= 0 {
						zeroed = append(zeroed, relation)
					}
				}
				if len(zeroed) != 0 {
					sort.Strings(zeroed)
					addWarning("graph has zero edges for %d reported relation(s): %s", len(zeroed), strings.Join(zeroed, ", "))
				}
			}
		}
	}

	runStore, ok := store.(graphIngestRunStore)
	if !ok {
		addFailure("graph store does not support ingest run history")
	} else {
		ingestRunFilter := graphstore.IngestRunFilter{Limit: options.IngestLimit, LatestByRuntime: true}
		if len(options.DeclaredRuntimeIDs) != 0 {
			ingestRunFilter.RuntimeIDs = options.DeclaredRuntimeIDs
			if len(options.DeclaredRuntimeIDs) > ingestRunFilter.Limit {
				ingestRunFilter.Limit = len(options.DeclaredRuntimeIDs)
			}
		}
		runs, err := runStore.ListIngestRuns(ctx, ingestRunFilter)
		if err != nil {
			addFailure("list graph ingest runs: %v", err)
		} else {
			current := latestGraphHealthRunsByRuntime(runs)
			result.Ingest.CurrentRuntimeCount = len(current)
			if len(current) == 0 {
				addFailure("graph ingest run history is empty")
			}
			successfulRuntimeIDs := successfulGraphHealthRuntimeIDs(runs)
			if options.AllowTransientSourceFailures {
				historyFilter := graphstore.IngestRunFilter{Limit: graphingest.MaxStatusLimit}
				if len(options.DeclaredRuntimeIDs) != 0 {
					historyFilter.RuntimeIDs = options.DeclaredRuntimeIDs
				}
				history, err := runStore.ListIngestRuns(ctx, historyFilter)
				if err != nil {
					addWarning("list graph ingest run history for transient failures: %v", err)
				} else {
					successfulRuntimeIDs = successfulGraphHealthRuntimeIDs(history)
				}
			}
			currentRuntimeIDs := make(map[string]struct{}, len(current))
			for runtimeID, run := range current {
				currentRuntimeIDs[runtimeID] = struct{}{}
				switch strings.TrimSpace(run.Status) {
				case graphstore.IngestRunStatusFailed:
					if canIgnoreGraphHealthTransientFailure(run, successfulRuntimeIDs, options.AllowTransientSourceFailures) {
						result.Ingest.IgnoredTransientFailedRuns = append(result.Ingest.IgnoredTransientFailedRuns, run)
						addWarning("ignored transient source failure for runtime %q because prior successful history exists", runtimeID)
					} else {
						result.Ingest.FailedRuns = append(result.Ingest.FailedRuns, run)
					}
				case graphstore.IngestRunStatusRunning:
					if graphHealthRunIsStale(run, now, options.MaxRunningMinutes) {
						result.Ingest.StaleRunningRuns = append(result.Ingest.StaleRunningRuns, run)
					}
				case graphstore.IngestRunStatusCompleted:
					if run.EventsRead > 0 && run.EntitiesProjected == 0 && run.LinksProjected == 0 {
						result.Ingest.ZeroProjectionRuns = append(result.Ingest.ZeroProjectionRuns, run)
					}
				}
			}
			for _, runtimeID := range options.DeclaredRuntimeIDs {
				if _, ok := currentRuntimeIDs[runtimeID]; !ok {
					result.Ingest.MissingRuntimeIDs = append(result.Ingest.MissingRuntimeIDs, runtimeID)
				}
			}
			if len(result.Ingest.MissingRuntimeIDs) != 0 {
				addFailure("missing graph ingest run history for %d declared runtime(s): %s", len(result.Ingest.MissingRuntimeIDs), strings.Join(result.Ingest.MissingRuntimeIDs, ", "))
			}
			if len(result.Ingest.FailedRuns) != 0 {
				addFailure("latest graph ingest run failed for %d runtime(s): %s", len(result.Ingest.FailedRuns), graphHealthRunSummaries(result.Ingest.FailedRuns))
			}
			if len(result.Ingest.StaleRunningRuns) != 0 {
				addFailure("latest graph ingest run is stale-running for %d runtime(s): %s", len(result.Ingest.StaleRunningRuns), graphHealthRunSummaries(result.Ingest.StaleRunningRuns))
			}
			if len(result.Ingest.ZeroProjectionRuns) != 0 {
				addFailure("latest graph ingest projected no graph records for %d runtime(s): %s", len(result.Ingest.ZeroProjectionRuns), graphHealthRunSummaries(result.Ingest.ZeroProjectionRuns))
			}
		}
	}

	if len(result.Failures) != 0 {
		result.Status = "failed"
		return result, fmt.Errorf("graph health failed: %s", strings.Join(result.Failures, "; "))
	}
	return result, nil
}

func runGraphImpact(args []string) error {
	request, err := parseGraphImpactArgs(args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	deps, closeDeps, err := openGraphDependencies(ctx)
	if err != nil {
		return err
	}
	defer logClose(closeDeps)
	store, ok := deps.GraphStore.(graphQueryStore)
	if !ok {
		return fmt.Errorf("graph store does not support impact traversals")
	}
	result, err := graphquery.New(store).GetImpact(ctx, request)
	if err != nil {
		return err
	}
	return printJSON(result)
}

func runGraphIngestRun(args []string) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return usageError(graphIngestRunUsage())
	}
	ctx := context.Background()
	deps, closeDeps, err := openGraphDependencies(ctx)
	if err != nil {
		return err
	}
	defer logClose(closeDeps)
	run, err := graphingest.New(nil, nil, nil, deps.GraphStore).GetRun(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}
	return printJSON(run)
}

func runGraphIngestRuns(args []string) error {
	options, err := parseGraphIngestRunsArgs(args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	deps, closeDeps, err := openGraphDependencies(ctx)
	if err != nil {
		return err
	}
	defer logClose(closeDeps)
	result, err := graphingest.New(nil, nil, nil, deps.GraphStore).ListRuns(ctx, graphstore.IngestRunFilter{
		RuntimeID:  options.RuntimeID,
		RuntimeIDs: options.RuntimeIDs,
		Status:     options.Status,
		Limit:      options.Limit,
	})
	if err != nil {
		return err
	}
	return printJSON(struct {
		Runs        []graphstore.IngestRun `json:"runs"`
		FailedCount uint32                 `json:"failed_count"`
	}{
		Runs:        result.Runs,
		FailedCount: result.FailedCount,
	})
}

func cleanupEndpointOwnerIDLinks(ctx context.Context, deps bootstrap.Dependencies, options graphEndpointOwnerIDCleanupOptions) (result graphEndpointOwnerIDCleanupResult, err error) {
	result = graphEndpointOwnerIDCleanupResult{
		TenantID:  strings.TrimSpace(options.TenantID),
		SourceID:  strings.TrimSpace(options.SourceID),
		RuntimeID: strings.TrimSpace(options.RuntimeID),
		Limit:     options.Limit,
		DryRun:    options.DryRun,
	}
	ctx, span := telemetry.Start(ctx, "projection_cleanup.endpoint_owner_id_links", telemetry.Attrs(
		telemetry.Field{Key: "tenant_id", Value: result.TenantID},
		telemetry.Field{Key: "source_id", Value: result.SourceID},
		telemetry.Field{Key: "runtime_id", Value: result.RuntimeID},
		telemetry.Field{Key: "limit", Value: result.Limit},
		telemetry.Field{Key: "dry_run", Value: result.DryRun},
	))
	defer func() {
		status := "success"
		fields := []telemetry.Field{
			{Key: "state_links_matched", Value: result.StateStore.LinksMatched},
			{Key: "state_links_deleted", Value: result.StateStore.LinksDeleted},
			{Key: "graph_links_matched", Value: result.GraphStore.LinksMatched},
			{Key: "graph_links_deleted", Value: result.GraphStore.LinksDeleted},
		}
		if err != nil {
			status = "error"
			fields = append(fields, telemetry.Field{Key: "error_kind", Value: graphEndpointOwnerIDCleanupErrorKind(err)})
		}
		telemetry.End(span, status, telemetry.Attrs(fields...))
	}()
	request := ports.ProjectionLinkCleanupRequest{
		TenantID:  result.TenantID,
		SourceID:  result.SourceID,
		RuntimeID: result.RuntimeID,
		Limit:     result.Limit,
		DryRun:    result.DryRun,
	}
	cleaned := false
	if cleaner, ok := deps.StateStore.(ports.EndpointOwnerIDLinkCleaner); ok {
		cleaned = true
		result.StateStore, err = cleaner.CleanupEndpointOwnerIDLinks(ctx, request)
		if err != nil {
			return result, fmt.Errorf("%w: %w", errEndpointOwnerIDStateCleanupFailed, err)
		}
	}
	if cleaner, ok := deps.GraphStore.(ports.EndpointOwnerIDLinkCleaner); ok {
		cleaned = true
		result.GraphStore, err = cleaner.CleanupEndpointOwnerIDLinks(ctx, request)
		if err != nil {
			return result, fmt.Errorf("%w: %w", errEndpointOwnerIDGraphCleanupFailed, err)
		}
	}
	if !cleaned {
		return result, errEndpointOwnerIDCleanupUnsupported
	}
	return result, nil
}

func graphEndpointOwnerIDCleanupErrorKind(err error) string {
	switch {
	case errors.Is(err, errEndpointOwnerIDCleanupUnsupported):
		return "cleanup_unsupported"
	case errors.Is(err, errEndpointOwnerIDStateCleanupFailed):
		return "state_cleanup_failed"
	case errors.Is(err, errEndpointOwnerIDGraphCleanupFailed):
		return "graph_cleanup_failed"
	default:
		return "cleanup_failed"
	}
}

func cleanupProjectedEntities(ctx context.Context, deps bootstrap.Dependencies, options graphProjectedEntityCleanupOptions) (result graphProjectedEntityCleanupResult, err error) {
	result = graphProjectedEntityCleanupResult{
		TenantID:     strings.TrimSpace(options.TenantID),
		SourceID:     strings.TrimSpace(options.SourceID),
		RuntimeID:    strings.TrimSpace(options.RuntimeID),
		FindingID:    strings.TrimSpace(options.FindingID),
		EntityTypes:  append([]string(nil), options.EntityTypes...),
		URNPrefixes:  append([]string(nil), options.URNPrefixes...),
		OnlyIsolated: options.OnlyIsolated,
		Limit:        options.Limit,
		DryRun:       options.DryRun,
	}
	request := ports.ProjectionCleanupRequest{
		TenantID:     result.TenantID,
		SourceID:     result.SourceID,
		RuntimeID:    result.RuntimeID,
		FindingID:    result.FindingID,
		EntityTypes:  result.EntityTypes,
		URNPrefixes:  result.URNPrefixes,
		OnlyIsolated: result.OnlyIsolated,
		Limit:        result.Limit,
		DryRun:       result.DryRun,
	}
	cleaned := false
	if cleaner, ok := deps.StateStore.(ports.ProjectionCleaner); ok {
		cleaned = true
		result.StateStore, err = cleaner.CleanupProjectedEntities(ctx, request)
		if err != nil {
			return result, fmt.Errorf("cleanup state projected entities: %w", err)
		}
	}
	if cleaner, ok := deps.GraphStore.(ports.ProjectionCleaner); ok {
		cleaned = true
		result.GraphStore, err = cleaner.CleanupProjectedEntities(ctx, request)
		if err != nil {
			return result, fmt.Errorf("cleanup graph projected entities: %w", err)
		}
	}
	if !cleaned {
		return result, fmt.Errorf("projected entity cleanup is unsupported by configured stores")
	}
	return result, nil
}

func repairOpenFindingPrimaryLinks(ctx context.Context, deps bootstrap.Dependencies, options graphOpenFindingPrimaryLinkRepairOptions) (graphstore.OpenFindingPrimaryLinkRepairResult, error) {
	repairer, ok := deps.GraphStore.(graphOpenFindingPrimaryLinkRepairStore)
	if !ok {
		return graphstore.OpenFindingPrimaryLinkRepairResult{DryRun: options.DryRun}, fmt.Errorf("open finding primary link repair is unsupported by configured graph store")
	}
	return repairer.RepairOpenFindingPrimaryLinks(ctx, graphstore.OpenFindingPrimaryLinkRepairRequest{
		Limit:  options.Limit,
		DryRun: options.DryRun,
	})
}

func backfillEntityTypedProperties(ctx context.Context, deps bootstrap.Dependencies, options graphBackfillEntityTypedPropertiesOptions) (graphstore.BackfillEntityTypedPropertiesResult, error) {
	backfiller, ok := deps.GraphStore.(graphBackfillEntityTypedPropertiesStore)
	if !ok {
		return graphstore.BackfillEntityTypedPropertiesResult{DryRun: options.DryRun}, fmt.Errorf("entity typed-property backfill is unsupported by configured graph store")
	}
	return backfiller.BackfillEntityTypedProperties(ctx, graphstore.BackfillEntityTypedPropertiesRequest{
		BatchSize: options.BatchSize,
		DryRun:    options.DryRun,
	})
}

func parseGraphNeighborhoodArgs(args []string) (string, int, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", 0, usageError(graphInspectUsage())
	}
	rootURN := strings.TrimSpace(args[0])
	remaining := args[1:]
	if strings.Contains(rootURN, "=") {
		key, value, _ := strings.Cut(rootURN, "=")
		if strings.TrimSpace(key) != "root_urn" {
			return "", 0, usageError(graphInspectUsage())
		}
		rootURN = strings.TrimSpace(value)
		remaining = args[1:]
	}
	limit, err := parseGraphLimitArgs(remaining, 25, "neighborhood")
	if err != nil {
		return "", 0, err
	}
	return rootURN, limit, nil
}

func parseGraphRelationCountsArgs(args []string) ([]string, error) {
	var relations []string
	seen := map[string]struct{}{}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "relations":
			for _, relation := range strings.Split(value, ",") {
				relation = strings.TrimSpace(relation)
				if relation == "" {
					continue
				}
				if _, ok := seen[relation]; ok {
					continue
				}
				seen[relation] = struct{}{}
				relations = append(relations, relation)
			}
		default:
			return nil, usageError(fmt.Sprintf("unsupported graph relation-counts argument %q", key))
		}
	}
	if len(relations) == 0 {
		return nil, usageError(graphInspectUsage())
	}
	if len(relations) > 50 {
		return nil, fmt.Errorf("relations must include at most 50 values")
	}
	return relations, nil
}

func parseGraphHealthArgs(args []string) (graphHealthOptions, error) {
	options := graphHealthOptions{
		IngestLimit:       graphingest.MaxStatusLimit,
		MaxRunningMinutes: defaultGraphHealthRunningWindow,
	}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphHealthOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "ingest_limit", "limit":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return graphHealthOptions{}, fmt.Errorf("parse ingest_limit: %w", err)
			}
			if parsed < 1 || parsed > graphingest.MaxStatusLimit {
				return graphHealthOptions{}, fmt.Errorf("ingest_limit must be between 1 and %d", graphingest.MaxStatusLimit)
			}
			options.IngestLimit = parsed
		case "max_running_minutes":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return graphHealthOptions{}, fmt.Errorf("parse max_running_minutes: %w", err)
			}
			if parsed < 1 {
				return graphHealthOptions{}, fmt.Errorf("max_running_minutes must be greater than zero")
			}
			options.MaxRunningMinutes = parsed
		case "relations", "required_relations":
			options.RequiredRelations = appendUniqueGraphHealthValues(options.RequiredRelations, splitCleanupValues(value))
			if len(options.RequiredRelations) > 50 {
				return graphHealthOptions{}, fmt.Errorf("relations must include at most 50 values")
			}
		case "report_relations":
			options.ReportRelations = appendUniqueGraphHealthValues(options.ReportRelations, splitCleanupValues(value))
			if len(options.ReportRelations) > 50 {
				return graphHealthOptions{}, fmt.Errorf("report_relations must include at most 50 values")
			}
		case "max_isolated_ratio":
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return graphHealthOptions{}, fmt.Errorf("parse max_isolated_ratio: %w", err)
			}
			if parsed < 0 || parsed > 1 {
				return graphHealthOptions{}, fmt.Errorf("max_isolated_ratio must be between 0 and 1")
			}
			options.MaxIsolatedRatio = parsed
		case "declared_runtime_ids", "runtime_ids":
			options.DeclaredRuntimeIDs = appendUniqueGraphHealthValues(options.DeclaredRuntimeIDs, splitCleanupValues(value))
		case "allow_transient_source_failures":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphHealthOptions{}, fmt.Errorf("parse allow_transient_source_failures: %w", err)
			}
			options.AllowTransientSourceFailures = parsed
		default:
			return graphHealthOptions{}, usageError(fmt.Sprintf("unsupported graph health argument %q", key))
		}
	}
	return options, nil
}

func parseGraphImpactArgs(args []string) (graphquery.ImpactRequest, error) {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return graphquery.ImpactRequest{}, usageError(graphImpactUsage())
	}
	request := graphquery.ImpactRequest{
		Identifier: strings.TrimSpace(args[1]),
	}
	switch strings.TrimSpace(args[0]) {
	case "cve-impact":
		request.Kind = graphquery.ImpactKindVulnerability
	case "package-exposure":
		request.Kind = graphquery.ImpactKindPackage
	case "asset-vulns":
		request.Kind = graphquery.ImpactKindAsset
		request.RootURN = request.Identifier
	default:
		return graphquery.ImpactRequest{}, usageError(graphImpactUsage())
	}
	for _, arg := range args[2:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphquery.ImpactRequest{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "tenant_id":
			request.TenantID = strings.TrimSpace(value)
		case "limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphquery.ImpactRequest{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed == 0 {
				return graphquery.ImpactRequest{}, fmt.Errorf("limit must be at least 1")
			}
			request.Limit = uint32(parsed)
		case "depth":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphquery.ImpactRequest{}, fmt.Errorf("parse depth: %w", err)
			}
			if parsed == 0 {
				return graphquery.ImpactRequest{}, fmt.Errorf("depth must be at least 1")
			}
			request.Depth = uint32(parsed)
		default:
			return graphquery.ImpactRequest{}, usageError(fmt.Sprintf("unsupported graph impact argument %q", key))
		}
	}
	if request.Kind != graphquery.ImpactKindAsset && strings.TrimSpace(request.TenantID) == "" {
		return graphquery.ImpactRequest{}, usageError(graphImpactUsage())
	}
	return request, nil
}

func parseGraphLimitArgs(args []string, defaultLimit int, command string) (int, error) {
	limit := defaultLimit
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return 0, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "limit":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return 0, fmt.Errorf("parse limit: %w", err)
			}
			if parsed < 1 || parsed > 500 {
				return 0, fmt.Errorf("limit must be between 1 and 500")
			}
			limit = parsed
		default:
			return 0, usageError(fmt.Sprintf("unsupported graph %s argument %q", command, key))
		}
	}
	return limit, nil
}

func openGraphDependencies(ctx context.Context) (bootstrap.Dependencies, func() error, error) {
	return openGraphDependenciesWithShutdown(ctx, ctx)
}

func openGraphDependenciesWithShutdown(ctx context.Context, shutdownCtx context.Context) (bootstrap.Dependencies, func() error, error) {
	cfg, err := config.Load()
	if err != nil {
		return bootstrap.Dependencies{}, nil, fmt.Errorf("load config: %w", err)
	}
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return bootstrap.Dependencies{}, nil, fmt.Errorf("configure telemetry: %w", err)
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		shutdownTelemetry(shutdownCtx, closeTelemetry, cfg.ShutdownTimeout)
		return bootstrap.Dependencies{}, nil, fmt.Errorf("open dependencies: %w", err)
	}
	if deps.GraphStore == nil {
		_ = closeDeps()
		shutdownTelemetry(shutdownCtx, closeTelemetry, cfg.ShutdownTimeout)
		return bootstrap.Dependencies{}, nil, fmt.Errorf("graph store is required")
	}
	return deps, func() error {
		err := closeDeps()
		shutdownTelemetry(shutdownCtx, closeTelemetry, cfg.ShutdownTimeout)
		return err
	}, nil
}

func openGraphCleanupDependencies(ctx context.Context) (bootstrap.Dependencies, func() error, error) {
	cfg, err := config.Load()
	if err != nil {
		return bootstrap.Dependencies{}, nil, fmt.Errorf("load config: %w", err)
	}
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return bootstrap.Dependencies{}, nil, fmt.Errorf("configure telemetry: %w", err)
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		return bootstrap.Dependencies{}, nil, fmt.Errorf("open dependencies: %w", err)
	}
	return deps, func() error {
		err := closeDeps()
		shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
		return err
	}, nil
}

func logClose(closeFn func() error) {
	if closeFn == nil {
		return
	}
	if err := closeFn(); err != nil {
		log.Printf("close dependencies: %v", err)
	}
}

func parseGraphIngestArgs(args []string) (graphIngestOptions, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return graphIngestOptions{}, usageError(graphIngestUsage())
	}
	options := graphIngestOptions{
		SourceID:     strings.TrimSpace(args[0]),
		SourceConfig: make(map[string]string),
		PageLimit:    defaultGraphIngestPageLimit,
	}
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphIngestOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "cursor":
			if strings.TrimSpace(value) != "" {
				options.Cursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(value)}
			}
		case "page_limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphIngestOptions{}, fmt.Errorf("parse page_limit: %w", err)
			}
			if parsed == 0 || parsed > maxGraphIngestPageLimit {
				return graphIngestOptions{}, fmt.Errorf("page_limit must be between 1 and %d", maxGraphIngestPageLimit)
			}
			options.PageLimit = uint32(parsed)
		case "tenant_id":
			options.TenantID = strings.TrimSpace(value)
		case "checkpoint":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphIngestOptions{}, fmt.Errorf("parse checkpoint: %w", err)
			}
			options.CheckpointEnabled = parsed
		case "checkpoint_id":
			options.CheckpointID = strings.TrimSpace(value)
			if options.CheckpointID != "" {
				options.CheckpointEnabled = true
			}
		case "reset_checkpoint":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphIngestOptions{}, fmt.Errorf("parse reset_checkpoint: %w", err)
			}
			options.ResetCheckpoint = parsed
		default:
			options.SourceConfig[strings.TrimSpace(key)] = value
		}
	}
	return options, nil
}

func parseGraphIngestRuntimeArgs(args []string) (graphIngestRuntimeOptions, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return graphIngestRuntimeOptions{}, usageError(graphIngestRuntimeUsage())
	}
	options := graphIngestRuntimeOptions{
		RuntimeID:  strings.TrimSpace(args[0]),
		PageLimit:  defaultGraphIngestPageLimit,
		Iterations: 1,
	}
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphIngestRuntimeOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "page_limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphIngestRuntimeOptions{}, fmt.Errorf("parse page_limit: %w", err)
			}
			if parsed == 0 || parsed > maxGraphIngestPageLimit {
				return graphIngestRuntimeOptions{}, fmt.Errorf("page_limit must be between 1 and %d", maxGraphIngestPageLimit)
			}
			options.PageLimit = uint32(parsed)
		case "checkpoint_id":
			options.CheckpointID = strings.TrimSpace(value)
		case "reset_checkpoint":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphIngestRuntimeOptions{}, fmt.Errorf("parse reset_checkpoint: %w", err)
			}
			options.ResetCheckpoint = parsed
		case "interval":
			parsed, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				return graphIngestRuntimeOptions{}, fmt.Errorf("parse interval: %w", err)
			}
			if parsed <= 0 {
				return graphIngestRuntimeOptions{}, fmt.Errorf("interval must be positive")
			}
			options.Interval = parsed
		case "iterations":
			normalized := strings.TrimSpace(value)
			if normalized == "forever" {
				options.Iterations = 0
				options.RunForever = true
				continue
			}
			parsed, err := strconv.ParseUint(normalized, 10, 32)
			if err != nil {
				return graphIngestRuntimeOptions{}, fmt.Errorf("parse iterations: %w", err)
			}
			if parsed == 0 {
				options.Iterations = 0
				options.RunForever = true
				continue
			}
			if parsed > maxGraphIngestRuntimeIterations {
				return graphIngestRuntimeOptions{}, fmt.Errorf("iterations must be between 1 and %d or forever", maxGraphIngestRuntimeIterations)
			}
			options.Iterations = uint32(parsed)
			options.RunForever = false
		default:
			return graphIngestRuntimeOptions{}, usageError(fmt.Sprintf("unsupported graph ingest-runtime argument %q", key))
		}
	}
	if (options.RunForever || options.Iterations > 1) && options.Interval <= 0 {
		return graphIngestRuntimeOptions{}, fmt.Errorf("interval is required when iterations is greater than 1 or forever")
	}
	return options, nil
}

func parseGraphIngestRunsArgs(args []string) (graphIngestRunsOptions, error) {
	options := graphIngestRunsOptions{Limit: graphingest.DefaultStatusLimit}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphIngestRunsOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "runtime_id":
			options.RuntimeID = strings.TrimSpace(value)
		case "runtime_ids":
			options.RuntimeIDs = appendUniqueGraphHealthValues(options.RuntimeIDs, splitCleanupValues(value))
		case "status":
			options.Status = strings.TrimSpace(value)
			if !validGraphIngestRunStatus(options.Status) {
				return graphIngestRunsOptions{}, fmt.Errorf("unsupported ingest run status %q", options.Status)
			}
		case "limit":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return graphIngestRunsOptions{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed < 1 || parsed > graphingest.MaxStatusLimit {
				return graphIngestRunsOptions{}, fmt.Errorf("limit must be between 1 and %d", graphingest.MaxStatusLimit)
			}
			options.Limit = parsed
		default:
			return graphIngestRunsOptions{}, usageError(fmt.Sprintf("unsupported graph ingest-runs argument %q", key))
		}
	}
	return options, nil
}

func parseGraphEndpointOwnerIDCleanupArgs(args []string) (graphEndpointOwnerIDCleanupOptions, error) {
	options := graphEndpointOwnerIDCleanupOptions{DryRun: true}
	apply := false
	dryRunSet := false
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphEndpointOwnerIDCleanupOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "tenant_id":
			options.TenantID = strings.TrimSpace(value)
		case "source_id":
			options.SourceID = strings.ToLower(strings.TrimSpace(value))
			if options.SourceID != "" && options.SourceID != "kolide" && options.SourceID != "kandji" {
				return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("source_id must be kolide or kandji")
			}
		case "runtime_id":
			options.RuntimeID = strings.TrimSpace(value)
		case "limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed == 0 {
				return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("limit must be positive")
			}
			options.Limit = uint32(parsed)
		case "dry_run":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("parse dry_run: %w", err)
			}
			options.DryRun = parsed
			dryRunSet = true
		case "apply":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("parse apply: %w", err)
			}
			apply = parsed
		default:
			return graphEndpointOwnerIDCleanupOptions{}, usageError(fmt.Sprintf("unsupported graph cleanup-endpoint-owner-id-links argument %q", key))
		}
	}
	if strings.TrimSpace(options.TenantID) == "" {
		return graphEndpointOwnerIDCleanupOptions{}, usageError(graphEndpointOwnerIDCleanupUsage())
	}
	if apply {
		if dryRunSet && options.DryRun {
			return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("apply=true conflicts with dry_run=true")
		}
		options.DryRun = false
	}
	if !options.DryRun && !apply {
		return graphEndpointOwnerIDCleanupOptions{}, fmt.Errorf("apply=true is required before deleting endpoint owner-id links")
	}
	return options, nil
}

func parseGraphProjectedEntityCleanupArgs(args []string) (graphProjectedEntityCleanupOptions, error) {
	options := graphProjectedEntityCleanupOptions{DryRun: true, OnlyIsolated: true}
	apply := false
	dryRunSet := false
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphProjectedEntityCleanupOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "tenant_id":
			options.TenantID = strings.TrimSpace(value)
		case "source_id":
			options.SourceID = strings.TrimSpace(value)
		case "runtime_id":
			options.RuntimeID = strings.TrimSpace(value)
		case "finding_id":
			options.FindingID = strings.TrimSpace(value)
		case "entity_type", "entity_types":
			options.EntityTypes = append(options.EntityTypes, splitCleanupValues(value)...)
		case "urn_prefix", "urn_prefixes":
			options.URNPrefixes = append(options.URNPrefixes, splitCleanupValues(value)...)
		case "only_isolated":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphProjectedEntityCleanupOptions{}, fmt.Errorf("parse only_isolated: %w", err)
			}
			options.OnlyIsolated = parsed
		case "allow_detach":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphProjectedEntityCleanupOptions{}, fmt.Errorf("parse allow_detach: %w", err)
			}
			options.AllowDetach = parsed
		case "limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphProjectedEntityCleanupOptions{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed == 0 {
				return graphProjectedEntityCleanupOptions{}, fmt.Errorf("limit must be positive")
			}
			options.Limit = uint32(parsed)
		case "dry_run":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphProjectedEntityCleanupOptions{}, fmt.Errorf("parse dry_run: %w", err)
			}
			options.DryRun = parsed
			dryRunSet = true
		case "apply":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphProjectedEntityCleanupOptions{}, fmt.Errorf("parse apply: %w", err)
			}
			apply = parsed
		default:
			return graphProjectedEntityCleanupOptions{}, usageError(fmt.Sprintf("unsupported graph cleanup-projected-entities argument %q", key))
		}
	}
	if strings.TrimSpace(options.TenantID) == "" {
		return graphProjectedEntityCleanupOptions{}, usageError(graphProjectedEntityCleanupUsage())
	}
	if strings.TrimSpace(options.SourceID) == "" &&
		strings.TrimSpace(options.RuntimeID) == "" &&
		strings.TrimSpace(options.FindingID) == "" &&
		len(options.EntityTypes) == 0 &&
		len(options.URNPrefixes) == 0 {
		return graphProjectedEntityCleanupOptions{}, usageError(graphProjectedEntityCleanupUsage())
	}
	if !options.OnlyIsolated && strings.TrimSpace(options.FindingID) == "" && !options.AllowDetach {
		return graphProjectedEntityCleanupOptions{}, fmt.Errorf("allow_detach=true is required when only_isolated=false without finding_id")
	}
	if apply {
		if dryRunSet && options.DryRun {
			return graphProjectedEntityCleanupOptions{}, fmt.Errorf("apply=true conflicts with dry_run=true")
		}
		options.DryRun = false
	}
	if !options.DryRun && !apply {
		return graphProjectedEntityCleanupOptions{}, fmt.Errorf("apply=true is required before deleting projected entities")
	}
	if !options.DryRun && strings.TrimSpace(options.FindingID) != "" && !options.AllowDetach {
		return graphProjectedEntityCleanupOptions{}, fmt.Errorf("allow_detach=true is required before deleting finding-scoped projected entities")
	}
	return options, nil
}

func parseGraphOpenFindingPrimaryLinkRepairArgs(args []string) (graphOpenFindingPrimaryLinkRepairOptions, error) {
	options := graphOpenFindingPrimaryLinkRepairOptions{DryRun: true}
	apply := false
	dryRunSet := false
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphOpenFindingPrimaryLinkRepairOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphOpenFindingPrimaryLinkRepairOptions{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed == 0 {
				return graphOpenFindingPrimaryLinkRepairOptions{}, fmt.Errorf("limit must be positive")
			}
			options.Limit = uint32(parsed)
		case "dry_run":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphOpenFindingPrimaryLinkRepairOptions{}, fmt.Errorf("parse dry_run: %w", err)
			}
			options.DryRun = parsed
			dryRunSet = true
		case "apply":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphOpenFindingPrimaryLinkRepairOptions{}, fmt.Errorf("parse apply: %w", err)
			}
			apply = parsed
		default:
			return graphOpenFindingPrimaryLinkRepairOptions{}, usageError(fmt.Sprintf("unsupported graph repair-open-finding-primary-links argument %q", key))
		}
	}
	if apply {
		if dryRunSet && options.DryRun {
			return graphOpenFindingPrimaryLinkRepairOptions{}, fmt.Errorf("apply=true conflicts with dry_run=true")
		}
		options.DryRun = false
	}
	if !options.DryRun && !apply {
		return graphOpenFindingPrimaryLinkRepairOptions{}, fmt.Errorf("apply=true is required before repairing open finding primary links")
	}
	return options, nil
}

func parseGraphBackfillEntityTypedPropertiesArgs(args []string) (graphBackfillEntityTypedPropertiesOptions, error) {
	options := graphBackfillEntityTypedPropertiesOptions{DryRun: true}
	apply := false
	dryRunSet := false
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return graphBackfillEntityTypedPropertiesOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "batch_size":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return graphBackfillEntityTypedPropertiesOptions{}, fmt.Errorf("parse batch_size: %w", err)
			}
			if parsed == 0 {
				return graphBackfillEntityTypedPropertiesOptions{}, fmt.Errorf("batch_size must be positive")
			}
			options.BatchSize = uint32(parsed)
		case "dry_run":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphBackfillEntityTypedPropertiesOptions{}, fmt.Errorf("parse dry_run: %w", err)
			}
			options.DryRun = parsed
			dryRunSet = true
		case "apply":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return graphBackfillEntityTypedPropertiesOptions{}, fmt.Errorf("parse apply: %w", err)
			}
			apply = parsed
		default:
			return graphBackfillEntityTypedPropertiesOptions{}, usageError(fmt.Sprintf("unsupported graph backfill-entity-typed-properties argument %q", key))
		}
	}
	if apply {
		if dryRunSet && options.DryRun {
			return graphBackfillEntityTypedPropertiesOptions{}, fmt.Errorf("apply=true conflicts with dry_run=true")
		}
		options.DryRun = false
	}
	if !options.DryRun && !apply {
		return graphBackfillEntityTypedPropertiesOptions{}, fmt.Errorf("apply=true is required before backfilling entity typed properties")
	}
	return options, nil
}

func splitCleanupValues(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		values = append(values, part)
	}
	return values
}

func appendUniqueGraphHealthValues(values []string, additions []string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func latestGraphHealthRunsByRuntime(runs []graphstore.IngestRun) map[string]graphstore.IngestRun {
	latest := map[string]graphstore.IngestRun{}
	for _, run := range runs {
		runtimeID := graphHealthRunRuntimeID(run)
		if runtimeID == "" {
			continue
		}
		if current, ok := latest[runtimeID]; !ok || graphHealthRunStartedAfter(run, current) {
			latest[runtimeID] = run
		}
	}
	return latest
}

func successfulGraphHealthRuntimeIDs(runs []graphstore.IngestRun) map[string]struct{} {
	successful := map[string]struct{}{}
	for _, run := range runs {
		if strings.TrimSpace(run.Status) != graphstore.IngestRunStatusCompleted {
			continue
		}
		if runtimeID := graphHealthRunRuntimeID(run); runtimeID != "" {
			successful[runtimeID] = struct{}{}
		}
	}
	return successful
}

func graphHealthRunRuntimeID(run graphstore.IngestRun) string {
	if runtimeID := strings.TrimSpace(run.RuntimeID); runtimeID != "" {
		return runtimeID
	}
	return strings.TrimSpace(run.ID)
}

func graphHealthRunStartedAfter(left, right graphstore.IngestRun) bool {
	leftStarted, leftOK := parseGraphHealthRunTime(left.StartedAt)
	rightStarted, rightOK := parseGraphHealthRunTime(right.StartedAt)
	switch {
	case leftOK && rightOK:
		if leftStarted.Equal(rightStarted) {
			return strings.TrimSpace(left.ID) > strings.TrimSpace(right.ID)
		}
		return leftStarted.After(rightStarted)
	case leftOK:
		return true
	case rightOK:
		return false
	default:
		return strings.TrimSpace(left.ID) > strings.TrimSpace(right.ID)
	}
}

func graphHealthRunIsStale(run graphstore.IngestRun, now time.Time, maxRunningMinutes int) bool {
	startedAt, ok := parseGraphHealthRunTime(run.StartedAt)
	const maxDurationMinutes = int64(1<<63-1) / int64(time.Minute)
	if !ok || maxRunningMinutes <= 0 || int64(maxRunningMinutes) > maxDurationMinutes {
		return false
	}
	return now.UTC().Sub(startedAt) > time.Duration(maxRunningMinutes)*time.Minute
}

func parseGraphHealthRunTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func canIgnoreGraphHealthTransientFailure(run graphstore.IngestRun, successfulRuntimeIDs map[string]struct{}, enabled bool) bool {
	if !enabled {
		return false
	}
	if _, ok := successfulRuntimeIDs[graphHealthRunRuntimeID(run)]; !ok {
		return false
	}
	errorText := strings.ToLower(strings.TrimSpace(run.Error))
	if errorText == "" {
		return false
	}
	for _, token := range []string{
		"client.timeout exceeded",
		"context deadline exceeded",
		"i/o timeout",
		"request canceled",
		"temporary failure",
		"tls handshake timeout",
	} {
		if strings.Contains(errorText, token) {
			return true
		}
	}
	return false
}

func graphHealthRunSummaries(runs []graphstore.IngestRun) string {
	summaries := make([]string, 0, len(runs))
	for _, run := range runs {
		summaries = append(summaries, graphHealthRunSummary(run))
	}
	sort.Strings(summaries)
	return strings.Join(summaries, ", ")
}

func graphHealthRunSummary(run graphstore.IngestRun) string {
	runtimeID := strings.TrimSpace(run.RuntimeID)
	runID := strings.TrimSpace(run.ID)
	summary := "<unknown-runtime>"
	if runtimeID != "" && runID != "" {
		summary = runtimeID + ":" + runID
	} else if runtimeID != "" {
		summary = runtimeID
	} else if runID != "" {
		summary = runID
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "status", value: run.Status},
		{name: "started_at", value: run.StartedAt},
		{name: "finished_at", value: run.FinishedAt},
		{name: "events_read", value: strconv.FormatInt(run.EventsRead, 10)},
		{name: "entities_projected", value: strconv.FormatInt(run.EntitiesProjected, 10)},
		{name: "links_projected", value: strconv.FormatInt(run.LinksProjected, 10)},
	} {
		if strings.TrimSpace(field.value) != "" {
			summary += ":" + field.name + "=" + field.value
		}
	}
	if errorText := strings.TrimSpace(run.Error); errorText != "" {
		summary += ":error=" + truncateGraphHealthDetail(errorText, graphHealthErrorDetailLimit)
	}
	return summary
}

func truncateGraphHealthDetail(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

func ingestGraph(
	ctx context.Context,
	sourceService *sourceops.Service,
	projector ports.SourceProjector,
	graphStore ports.GraphStore,
	options graphIngestOptions,
) (*graphIngestResult, error) {
	result := &graphIngestResult{
		SourceID: strings.TrimSpace(options.SourceID),
		TenantID: strings.TrimSpace(options.TenantID),
	}
	cursor := options.Cursor
	checkpointStore, err := prepareGraphIngestCheckpoint(ctx, graphStore, options, result, &cursor)
	if err != nil {
		return nil, err
	}
	if result.CheckpointAlreadyFresh {
		return result, nil
	}
	countsStore, hasCounts := graphStore.(graphCountsStore)
	if hasCounts {
		counts, err := countsStore.Counts(ctx)
		if err != nil {
			return nil, err
		}
		result.GraphNodesBefore = counts.Nodes
		result.GraphLinksBefore = counts.Relations
	}
	for i := uint32(0); i < options.PageLimit; i++ {
		response, err := sourceService.Read(ctx, &cerebrov1.ReadSourceRequest{
			SourceId: options.SourceID,
			Config:   options.SourceConfig,
			Cursor:   cursor,
		})
		if err != nil {
			return nil, err
		}
		result.PagesRead++
		for _, event := range response.GetEvents() {
			projected, err := projector.Project(ctx, graphIngestEvent(event, options.TenantID))
			if err != nil {
				return nil, fmt.Errorf("project source event %q: %w", event.GetId(), err)
			}
			result.EventsRead++
			result.EntitiesProjected += projected.EntitiesProjected
			result.LinksProjected += projected.LinksProjected
		}
		cursor = response.GetNextCursor()
		if checkpointStore != nil {
			if err := persistGraphIngestCheckpoint(ctx, checkpointStore, options, result, response, cursor); err != nil {
				return nil, err
			}
		}
		if cursor == nil {
			break
		}
	}
	if cursor != nil {
		result.NextCursor = strings.TrimSpace(cursor.GetOpaque())
	}
	if hasCounts {
		counts, err := countsStore.Counts(ctx)
		if err != nil {
			return nil, err
		}
		result.GraphNodesAfter = counts.Nodes
		result.GraphLinksAfter = counts.Relations
	}
	return result, nil
}

func runGraphIngestRuntime(ctx context.Context, deps bootstrap.Dependencies, options graphIngestRuntimeOptions) (*graphIngestRuntimeRunnerResult, error) {
	runtimeStore := sourceRuntimeStore(deps.StateStore)
	if runtimeStore == nil {
		return nil, fmt.Errorf("source runtime store is required")
	}
	registry, err := sourceregistry.Builtin()
	if err != nil {
		return nil, fmt.Errorf("open source registry: %w", err)
	}
	projector := sourceProjector(nil, deps.GraphStore)
	if projector == nil {
		return nil, fmt.Errorf("projection graph store is required")
	}
	service := graphingest.New(registry, runtimeStore, projector, deps.GraphStore).WithConfigPreparer(prepareGraphRuntimeSourceConfig)
	result := &graphIngestRuntimeRunnerResult{
		RuntimeID:  strings.TrimSpace(options.RuntimeID),
		Iterations: options.Iterations,
		RunForever: options.RunForever,
		Runs:       make([]*graphingest.RunResult, 0, graphIngestRuntimeResultCapacity(options)),
	}
	if options.Interval > 0 {
		result.Interval = options.Interval.String()
	}
	var (
		ticker    *time.Ticker
		joined    error
		iteration uint32
	)
	if options.RunForever || options.Iterations > 1 {
		ticker = time.NewTicker(options.Interval)
		defer ticker.Stop()
	}
	for {
		runResult, err := service.RunRuntime(ctx, graphingest.RuntimeRequest{
			RuntimeID:       options.RuntimeID,
			PageLimit:       options.PageLimit,
			CheckpointID:    options.CheckpointID,
			ResetCheckpoint: options.ResetCheckpoint,
			Trigger:         graphIngestTrigger(options),
		})
		if runResult != nil {
			result.Runs = append(result.Runs, runResult)
		}
		joined = errors.Join(joined, err)
		iteration++
		if !options.RunForever && iteration >= options.Iterations {
			break
		}
		if ticker == nil {
			break
		}
		select {
		case <-ctx.Done():
			joined = errors.Join(joined, ctx.Err())
			return result, joined
		case <-ticker.C:
		}
	}
	return result, joined
}

func prepareGraphIngestCheckpoint(
	ctx context.Context,
	graphStore ports.GraphStore,
	options graphIngestOptions,
	result *graphIngestResult,
	cursor **cerebrov1.SourceCursor,
) (graphIngestCheckpointStore, error) {
	if !options.CheckpointEnabled {
		return nil, nil
	}
	checkpointStore, ok := graphStore.(graphIngestCheckpointStore)
	if !ok {
		return nil, fmt.Errorf("graph store does not support ingest checkpoints")
	}
	checkpointID := graphIngestCheckpointID(options)
	result.CheckpointID = checkpointID
	if options.ResetCheckpoint || *cursor != nil {
		return checkpointStore, nil
	}
	checkpoint, found, err := checkpointStore.GetIngestCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, err
	}
	if !found {
		return checkpointStore, nil
	}
	result.CheckpointResumed = true
	result.CheckpointCursor = strings.TrimSpace(checkpoint.CursorOpaque)
	if checkpoint.Completed && checkpoint.CursorOpaque == "" {
		result.CheckpointComplete = true
		result.CheckpointAlreadyFresh = true
		return checkpointStore, nil
	}
	if checkpoint.CursorOpaque != "" {
		*cursor = &cerebrov1.SourceCursor{Opaque: checkpoint.CursorOpaque}
	}
	return checkpointStore, nil
}

func persistGraphIngestCheckpoint(
	ctx context.Context,
	checkpointStore graphIngestCheckpointStore,
	options graphIngestOptions,
	result *graphIngestResult,
	response *cerebrov1.ReadSourceResponse,
	nextCursor *cerebrov1.SourceCursor,
) error {
	cursorOpaque := ""
	completed := true
	if nextCursor != nil {
		cursorOpaque = strings.TrimSpace(nextCursor.GetOpaque())
		completed = cursorOpaque == ""
	}
	checkpointOpaque := strings.TrimSpace(response.GetCheckpoint().GetCursorOpaque())
	checkpoint := graphstore.IngestCheckpoint{
		ID:               graphIngestCheckpointID(options),
		SourceID:         strings.TrimSpace(options.SourceID),
		TenantID:         strings.TrimSpace(options.TenantID),
		ConfigHash:       graphIngestConfigHash(options.SourceConfig),
		CursorOpaque:     cursorOpaque,
		CheckpointOpaque: checkpointOpaque,
		Completed:        completed,
		PagesRead:        int64(result.PagesRead),
		EventsRead:       int64(result.EventsRead),
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := checkpointStore.PutIngestCheckpoint(ctx, checkpoint); err != nil {
		return err
	}
	result.CheckpointID = checkpoint.ID
	result.CheckpointCursor = cursorOpaque
	result.CheckpointPersisted = true
	result.CheckpointComplete = completed
	return nil
}

func graphIngestCheckpointID(options graphIngestOptions) string {
	if normalized := strings.TrimSpace(options.CheckpointID); normalized != "" {
		return normalized
	}
	tenantID := strings.TrimSpace(options.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	hash := graphIngestConfigHash(options.SourceConfig)
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return strings.TrimSpace(options.SourceID) + ":" + tenantID + ":" + hash
}

func prepareGraphRuntimeSourceConfig(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
	return config.ResolveSourceRuntimeConfigSecretReferences(ctx, sourceID, values)
}

func graphIngestRuntimeResultCapacity(options graphIngestRuntimeOptions) int {
	if options.RunForever {
		return 1
	}
	if options.Iterations == 0 {
		return 1
	}
	return int(options.Iterations)
}

func graphIngestTrigger(options graphIngestRuntimeOptions) string {
	if options.RunForever || options.Iterations > 1 {
		return "scheduled"
	}
	return "manual"
}

func validGraphIngestRunStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case graphstore.IngestRunStatusRunning, graphstore.IngestRunStatusCompleted, graphstore.IngestRunStatusFailed:
		return true
	default:
		return false
	}
}

func graphIngestConfigHash(config map[string]string) string {
	keys := make([]string, 0, len(config))
	for key := range config {
		if !sensitiveGraphIngestConfigKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(strings.TrimSpace(key)))
		hash.Write([]byte{0})
		hash.Write([]byte(config[key]))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func sensitiveGraphIngestConfigKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"token", "secret", "password", "access_key", "session"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func graphIngestEvent(event *cerebrov1.EventEnvelope, tenantID string) *cerebrov1.EventEnvelope {
	if event == nil {
		return nil
	}
	cloned := proto.Clone(event).(*cerebrov1.EventEnvelope)
	if normalized := strings.TrimSpace(tenantID); normalized != "" {
		cloned.TenantId = normalized
	}
	return cloned
}

func parseGraphRebuildArgs(args []string) (string, string, uint32, uint32, int, bool, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", "", 0, 0, 0, false, usageError(fmt.Sprintf("usage: %s graph rebuild <runtime-id> [dry_run=true] [mode=source|replay] [page_limit=N] [event_limit=N] [preview_limit=N]", os.Args[0]))
	}
	runtimeID := strings.TrimSpace(args[0])
	dryRun := true
	var (
		mode         string
		pageLimit    uint32
		eventLimit   uint32
		previewLimit int
	)
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", "", 0, 0, 0, false, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "dry_run":
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return "", "", 0, 0, 0, false, fmt.Errorf("parse dry_run: %w", err)
			}
			dryRun = parsed
		case "mode":
			mode = strings.TrimSpace(value)
		case "page_limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return "", "", 0, 0, 0, false, fmt.Errorf("parse page_limit: %w", err)
			}
			pageLimit = uint32(parsed)
		case "event_limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return "", "", 0, 0, 0, false, fmt.Errorf("parse event_limit: %w", err)
			}
			eventLimit = uint32(parsed)
		case "preview_limit":
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return "", "", 0, 0, 0, false, fmt.Errorf("parse preview_limit: %w", err)
			}
			previewLimit = parsed
		default:
			return "", "", 0, 0, 0, false, usageError(fmt.Sprintf("unsupported graph rebuild argument %q", key))
		}
	}
	return runtimeID, mode, pageLimit, eventLimit, previewLimit, dryRun, nil
}

func printJSON(value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	if _, err := os.Stdout.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
