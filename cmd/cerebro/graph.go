package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphrebuild"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceregistry"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGraphIngestPageLimit = 1
	maxGraphIngestPageLimit     = 100
)

type graphCountsStore interface {
	Counts(context.Context) (graphstore.Counts, error)
}

type graphQueryStore interface {
	GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error)
}

type graphPathStore interface {
	PathPatterns(context.Context, int) ([]graphstore.PathPattern, error)
	SampleTraversals(context.Context, int) ([]graphstore.Traversal, error)
	Topology(context.Context) (graphstore.Topology, error)
}

type graphIntegrityStore interface {
	IntegrityChecks(context.Context) ([]graphstore.IntegrityCheck, error)
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

type graphPathsResult struct {
	Patterns   []graphstore.PathPattern `json:"patterns"`
	Traversals []graphstore.Traversal   `json:"traversals"`
	Topology   graphstore.Topology      `json:"topology"`
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
	case "counts", "neighborhood", "paths", "integrity":
		return runGraphInspect(args)
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
		service := graphrebuild.New(registry, sourceRuntimeStore(deps.StateStore), replayer)
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
	return fmt.Sprintf("usage: %s graph [counts|neighborhood|paths|integrity|ingest|rebuild|inspect] ...", os.Args[0])
}

func graphIngestUsage() string {
	return fmt.Sprintf("usage: %s graph ingest <source-id> [tenant_id=<tenant-id>] [page_limit=N] [cursor=<cursor>] [checkpoint=true] [checkpoint_id=<id>] [reset_checkpoint=true] [key=value ...]", os.Args[0])
}

func graphInspectUsage() string {
	return fmt.Sprintf("usage: %s graph [counts|neighborhood <urn>|paths|integrity] [limit=N]", os.Args[0])
}

func runGraphInspect(args []string) error {
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
		patterns, err := store.PathPatterns(ctx, limit)
		if err != nil {
			return err
		}
		traversals, err := store.SampleTraversals(ctx, limit)
		if err != nil {
			return err
		}
		topology, err := store.Topology(ctx)
		if err != nil {
			return err
		}
		return printJSON(graphPathsResult{Patterns: patterns, Traversals: traversals, Topology: topology})
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
	cfg, err := config.Load()
	if err != nil {
		return bootstrap.Dependencies{}, nil, fmt.Errorf("load config: %w", err)
	}
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		return bootstrap.Dependencies{}, nil, fmt.Errorf("open dependencies: %w", err)
	}
	if deps.GraphStore == nil {
		_ = closeDeps()
		return bootstrap.Dependencies{}, nil, fmt.Errorf("graph store is required")
	}
	return deps, closeDeps, nil
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
