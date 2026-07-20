package sourcehealth

import (
	"context"
	"math"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

const maxGraphRunStatusLimit = 500

type GraphIngestRunStore interface {
	ListIngestRuns(context.Context, graphstore.IngestRunFilter) ([]graphstore.IngestRun, error)
}

func LatestGraphIngestRuns(ctx context.Context, store GraphIngestRunStore, runtimeIDs []string) (map[string]*graphstore.IngestRun, error) {
	byRuntime := map[string]*graphstore.IngestRun{}
	runtimeIDs = normalizeRuntimeIDs(runtimeIDs)
	if len(runtimeIDs) == 0 {
		return byRuntime, nil
	}
	for start := 0; start < len(runtimeIDs); start += maxGraphRunStatusLimit {
		end := min(start+maxGraphRunStatusLimit, len(runtimeIDs))
		batch := runtimeIDs[start:end]
		runs, err := store.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeIDs: batch, Limit: len(batch), LatestByRuntime: true})
		if err != nil {
			return nil, err
		}
		for index := range runs {
			run := runs[index]
			if runtimeID := strings.TrimSpace(run.RuntimeID); runtimeID != "" {
				byRuntime[runtimeID] = &run
			}
		}
	}
	return byRuntime, nil
}

func LatestFindingEvaluationRuns(ctx context.Context, store ports.FindingEvaluationRunStore, runtimeIDs []string) (map[string]*cerebrov1.FindingEvaluationRun, error) {
	byRuntime := map[string]*cerebrov1.FindingEvaluationRun{}
	runtimeIDs = normalizeRuntimeIDs(runtimeIDs)
	if len(runtimeIDs) == 0 {
		return byRuntime, nil
	}
	runs, err := store.ListFindingEvaluationRuns(ctx, ports.ListFindingEvaluationRunsRequest{RuntimeIDs: runtimeIDs, Limit: uint32Limit(len(runtimeIDs)), LatestByRuntime: true})
	if err != nil {
		return nil, err
	}
	for _, run := range runs {
		if run == nil {
			continue
		}
		if runtimeID := strings.TrimSpace(run.GetRuntimeId()); runtimeID != "" {
			byRuntime[runtimeID] = run
		}
	}
	return byRuntime, nil
}

func normalizeRuntimeIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uint32Limit(value int) uint32 {
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value) // #nosec G115 -- values above MaxUint32 return before this conversion.
}
