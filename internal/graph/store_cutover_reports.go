package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
)

// StoreReportProbe defines one derived report comparison over snapshot-backed graph views.
type StoreReportProbe struct {
	Name  string
	Build func(*Graph) (any, error)
}

// CompareGraphStoreReports compares derived report outputs across two stores.
func CompareGraphStoreReports(ctx context.Context, primary, shadow GraphStore, probes []StoreReportProbe) (*StoreParityReport, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if primary == nil || shadow == nil {
		return nil, ErrStoreUnavailable
	}
	primarySnapshot, err := primary.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot primary store: %w", err)
	}
	shadowSnapshot, err := shadow.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot shadow store: %w", err)
	}
	report, err := buildReportParityReport(primarySnapshot, shadowSnapshot, probes)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// ObserveShadowReadGraphStoreReports compares report outputs for a shadow-read store and emits drift.
func ObserveShadowReadGraphStoreReports(ctx context.Context, store GraphStore, probes []StoreReportProbe) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	shadowStore, ok := store.(*ShadowReadGraphStore)
	if !ok || shadowStore == nil || len(probes) == 0 {
		return nil
	}
	primarySnapshot, err := shadowStore.GraphStore.Snapshot(ctx)
	if err != nil {
		return err
	}
	shadowSnapshot, err := shadowStore.shadow.Snapshot(ctx)
	if err != nil {
		shadowStore.emitShadowError(ctx, "report_parity", err)
		return nil
	}
	report, err := buildReportParityReport(primarySnapshot, shadowSnapshot, probes)
	if err != nil {
		return err
	}
	shadowStore.emit(ctx, report)
	return nil
}

func buildReportParityReport(primarySnapshot, shadowSnapshot *Snapshot, probes []StoreReportProbe) (StoreParityReport, error) {
	report := StoreParityReport{}
	report.PrimaryNodeCount, report.PrimaryEdgeCount = activeSnapshotCounts(primarySnapshot)
	report.ShadowNodeCount, report.ShadowEdgeCount = activeSnapshotCounts(shadowSnapshot)

	primaryGraph := GraphViewFromSnapshot(primarySnapshot)
	shadowGraph := GraphViewFromSnapshot(shadowSnapshot)
	mismatches, err := compareReportProbes(primaryGraph, shadowGraph, probes)
	if err != nil {
		return StoreParityReport{}, err
	}
	report.Mismatches = mismatches
	return report, nil
}

func compareReportProbes(primary, shadow *Graph, probes []StoreReportProbe) ([]StoreParityMismatch, error) {
	mismatches := make([]StoreParityMismatch, 0, len(probes))
	for index, probe := range probes {
		if probe.Build == nil {
			continue
		}
		name := firstNonEmpty(probe.Name, fmt.Sprintf("report-probe-%d", index+1))
		primaryResult, err := probe.Build(primary)
		if err != nil {
			return nil, fmt.Errorf("run primary report probe %q: %w", name, err)
		}
		shadowResult, err := probe.Build(shadow)
		if err != nil {
			return nil, fmt.Errorf("run shadow report probe %q: %w", name, err)
		}
		primarySummary, err := normalizeReportParityValue(primaryResult)
		if err != nil {
			return nil, fmt.Errorf("normalize primary report probe %q: %w", name, err)
		}
		shadowSummary, err := normalizeReportParityValue(shadowResult)
		if err != nil {
			return nil, fmt.Errorf("normalize shadow report probe %q: %w", name, err)
		}
		if reflect.DeepEqual(primarySummary, shadowSummary) {
			continue
		}
		mismatches = append(mismatches, StoreParityMismatch{
			Class:      StoreParityMismatchReportDrift,
			Operation:  "report",
			Identifier: name,
			Details: map[string]any{
				"primary": primarySummary,
				"shadow":  shadowSummary,
			},
		})
	}
	return mismatches, nil
}

func normalizeReportParityValue(value any) (map[string]any, error) {
	if value == nil {
		return map[string]any{}, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(payload, &normalized); err != nil {
		return nil, err
	}
	normalized = stripGeneratedAt(normalized)
	if asMap, ok := normalized.(map[string]any); ok {
		return asMap, nil
	}
	return map[string]any{"value": normalized}, nil
}

func stripGeneratedAt(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "generated_at")
		for key, child := range typed {
			typed[key] = stripGeneratedAt(child)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = stripGeneratedAt(child)
		}
		return typed
	default:
		return value
	}
}
