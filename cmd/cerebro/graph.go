package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

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

type graphIngestResult struct {
	SourceID          string `json:"source_id"`
	TenantID          string `json:"tenant_id,omitempty"`
	PagesRead         uint32 `json:"pages_read"`
	EventsRead        uint32 `json:"events_read"`
	EntitiesProjected uint32 `json:"entities_projected"`
	LinksProjected    uint32 `json:"links_projected"`
	GraphNodesBefore  int64  `json:"graph_nodes_before,omitempty"`
	GraphLinksBefore  int64  `json:"graph_links_before,omitempty"`
	GraphNodesAfter   int64  `json:"graph_nodes_after,omitempty"`
	GraphLinksAfter   int64  `json:"graph_links_after,omitempty"`
	NextCursor        string `json:"next_cursor,omitempty"`
}

func runGraph(args []string) error {
	if len(args) == 0 {
		return usageError(graphUsage())
	}
	switch args[0] {
	case "ingest":
		sourceID, sourceConfig, tenantID, pageLimit, cursor, err := parseGraphIngestArgs(args[1:])
		if err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		ctx := context.Background()
		deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
		if err != nil {
			return fmt.Errorf("open dependencies: %w", err)
		}
		defer func() {
			if err := closeDeps(); err != nil {
				log.Printf("close dependencies: %v", err)
			}
		}()
		if deps.GraphStore == nil {
			return fmt.Errorf("graph store is required")
		}
		sourceConfig, err = prepareSourceConfig(ctx, sourceID, "read", sourceConfig)
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
		result, err := ingestGraph(ctx, sourceops.New(registry), projector, deps.GraphStore, sourceID, sourceConfig, tenantID, pageLimit, cursor)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "rebuild":
		runtimeID, mode, pageLimit, eventLimit, previewLimit, dryRun, err := parseGraphRebuildArgs(args[1:])
		if err != nil {
			return err
		}
		if !dryRun {
			return fmt.Errorf("graph rebuild currently only supports dry_run=true")
		}
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		ctx := context.Background()
		deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
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
	return fmt.Sprintf("usage: %s graph [ingest|rebuild] ...", os.Args[0])
}

func graphIngestUsage() string {
	return fmt.Sprintf("usage: %s graph ingest <source-id> [tenant_id=<tenant-id>] [page_limit=N] [cursor=<cursor>] [key=value ...]", os.Args[0])
}

func parseGraphIngestArgs(args []string) (string, map[string]string, string, uint32, *cerebrov1.SourceCursor, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", nil, "", 0, nil, usageError(graphIngestUsage())
	}
	sourceID := strings.TrimSpace(args[0])
	sourceConfig := make(map[string]string)
	pageLimit := uint32(defaultGraphIngestPageLimit)
	var (
		cursor   *cerebrov1.SourceCursor
		tenantID string
	)
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return "", nil, "", 0, nil, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		switch strings.TrimSpace(key) {
		case "cursor":
			if strings.TrimSpace(value) != "" {
				cursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(value)}
			}
		case "page_limit":
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return "", nil, "", 0, nil, fmt.Errorf("parse page_limit: %w", err)
			}
			if parsed == 0 || parsed > maxGraphIngestPageLimit {
				return "", nil, "", 0, nil, fmt.Errorf("page_limit must be between 1 and %d", maxGraphIngestPageLimit)
			}
			pageLimit = uint32(parsed)
		case "tenant_id":
			tenantID = strings.TrimSpace(value)
		default:
			sourceConfig[strings.TrimSpace(key)] = value
		}
	}
	return sourceID, sourceConfig, tenantID, pageLimit, cursor, nil
}

func ingestGraph(
	ctx context.Context,
	sourceService *sourceops.Service,
	projector ports.SourceProjector,
	graphStore ports.GraphStore,
	sourceID string,
	sourceConfig map[string]string,
	tenantID string,
	pageLimit uint32,
	cursor *cerebrov1.SourceCursor,
) (*graphIngestResult, error) {
	result := &graphIngestResult{
		SourceID: strings.TrimSpace(sourceID),
		TenantID: strings.TrimSpace(tenantID),
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
	for i := uint32(0); i < pageLimit; i++ {
		response, err := sourceService.Read(ctx, &cerebrov1.ReadSourceRequest{
			SourceId: sourceID,
			Config:   sourceConfig,
			Cursor:   cursor,
		})
		if err != nil {
			return nil, err
		}
		result.PagesRead++
		for _, event := range response.GetEvents() {
			projected, err := projector.Project(ctx, graphIngestEvent(event, tenantID))
			if err != nil {
				return nil, fmt.Errorf("project source event %q: %w", event.GetId(), err)
			}
			result.EventsRead++
			result.EntitiesProjected += projected.EntitiesProjected
			result.LinksProjected += projected.LinksProjected
		}
		cursor = response.GetNextCursor()
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
