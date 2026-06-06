package findingevidence

import (
	"math"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Normalize returns a cloned evidence record with run history fields populated.
func Normalize(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	if evidence == nil {
		return nil
	}
	normalized := proto.Clone(evidence).(*cerebrov1.FindingEvidence)
	runIDs := append([]string{}, normalized.GetRunIds()...)
	if runID := strings.TrimSpace(normalized.GetRunId()); runID != "" {
		runIDs = append(runIDs, runID)
	}
	normalized.RunIds = uniqueSortedStrings(runIDs)
	if len(normalized.GetGraphPathUrns()) == 0 {
		normalized.GraphPathUrns = graphPathURNs(normalized.GetGraphRows())
	}
	if len(normalized.GetObservations()) == 0 {
		if observation := ObservationFor(normalized); observation != nil {
			normalized.Observations = []*cerebrov1.FindingEvidenceObservation{observation}
		}
	}
	normalized.ObservationCount = boundedUint32(len(normalized.GetObservations()))
	return normalized
}

// ObservationFor builds the per-run observation snapshot for one evidence write.
func ObservationFor(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidenceObservation {
	if evidence == nil || strings.TrimSpace(evidence.GetRunId()) == "" {
		return nil
	}
	observedAt := evidence.GetLastObservedAt()
	if observedAt == nil || observedAt.AsTime().IsZero() {
		observedAt = evidence.GetCreatedAt()
	}
	return &cerebrov1.FindingEvidenceObservation{
		RunId:         strings.TrimSpace(evidence.GetRunId()),
		ObservedAt:    observedAt,
		ClaimIds:      uniqueSortedStrings(evidence.GetClaimIds()),
		EventIds:      uniqueSortedStrings(evidence.GetEventIds()),
		GraphRootUrns: uniqueSortedStrings(evidence.GetGraphRootUrns()),
		GraphPathUrns: uniqueSortedStrings(append(evidence.GetGraphPathUrns(), graphPathURNs(evidence.GetGraphRows())...)),
		GraphRows:     cloneGraphEvidenceRows(evidence.GetGraphRows()),
	}
}

// Merge returns a deduplicated evidence record that preserves historical run observations.
func Merge(existing *cerebrov1.FindingEvidence, latest *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	if existing == nil {
		return Normalize(latest)
	}
	if latest == nil {
		return Normalize(existing)
	}
	existing = Normalize(existing)
	latest = Normalize(latest)

	merged := proto.Clone(latest).(*cerebrov1.FindingEvidence)
	if earlierTimestamp(existing.GetCreatedAt(), latest.GetCreatedAt()) == existing.GetCreatedAt() {
		merged.CreatedAt = existing.GetCreatedAt()
	}
	if later := laterTimestamp(existing.GetLastObservedAt(), latest.GetLastObservedAt()); later != nil {
		merged.LastObservedAt = later
	}
	if strings.TrimSpace(merged.GetRunId()) == "" {
		merged.RunId = strings.TrimSpace(existing.GetRunId())
	}

	merged.ClaimIds = uniqueSortedStrings(append(existing.GetClaimIds(), latest.GetClaimIds()...))
	merged.EventIds = uniqueSortedStrings(append(existing.GetEventIds(), latest.GetEventIds()...))
	merged.GraphRootUrns = uniqueSortedStrings(append(existing.GetGraphRootUrns(), latest.GetGraphRootUrns()...))
	merged.GraphRows = mergeGraphEvidenceRows(existing.GetGraphRows(), latest.GetGraphRows())
	merged.GraphPathUrns = uniqueSortedStrings(append(append(existing.GetGraphPathUrns(), latest.GetGraphPathUrns()...), graphPathURNs(merged.GetGraphRows())...))
	merged.RunIds = uniqueSortedStrings(append(append(existing.GetRunIds(), latest.GetRunIds()...), existing.GetRunId(), latest.GetRunId()))
	merged.Attributes = mergeStringMaps(existing.GetAttributes(), latest.GetAttributes())
	merged.Observations = mergeObservations(existing.GetObservations(), latest.GetObservations())
	merged.ObservationCount = boundedUint32(len(merged.GetObservations()))
	return merged
}

func boundedUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

func mergeGraphEvidenceRows(groups ...[]*cerebrov1.GraphEvidenceRow) []*cerebrov1.GraphEvidenceRow {
	rowsByKey := map[string]*cerebrov1.GraphEvidenceRow{}
	for _, group := range groups {
		for _, row := range group {
			if row == nil {
				continue
			}
			cloned := proto.Clone(row).(*cerebrov1.GraphEvidenceRow)
			key := graphRowKey(cloned)
			if existing := rowsByKey[key]; existing != nil {
				existing.Paths = mergeGraphEvidencePaths(existing.GetPaths(), cloned.GetPaths())
				continue
			}
			cloned.Paths = mergeGraphEvidencePaths(cloned.GetPaths())
			rowsByKey[key] = cloned
		}
	}
	keys := make([]string, 0, len(rowsByKey))
	for key := range rowsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([]*cerebrov1.GraphEvidenceRow, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, rowsByKey[key])
	}
	if len(rows) == 0 {
		return nil
	}
	return rows
}

func mergeGraphEvidencePaths(groups ...[]*cerebrov1.GraphEvidencePath) []*cerebrov1.GraphEvidencePath {
	pathsByKey := map[string]*cerebrov1.GraphEvidencePath{}
	for _, group := range groups {
		for _, path := range group {
			if path == nil {
				continue
			}
			cloned := proto.Clone(path).(*cerebrov1.GraphEvidencePath)
			pathsByKey[graphPathKey(cloned)] = cloned
		}
	}
	keys := make([]string, 0, len(pathsByKey))
	for key := range pathsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	paths := make([]*cerebrov1.GraphEvidencePath, 0, len(keys))
	for _, key := range keys {
		paths = append(paths, pathsByKey[key])
	}
	if len(paths) == 0 {
		return nil
	}
	return paths
}

func mergeObservations(groups ...[]*cerebrov1.FindingEvidenceObservation) []*cerebrov1.FindingEvidenceObservation {
	observationsByKey := map[string]*cerebrov1.FindingEvidenceObservation{}
	for _, group := range groups {
		for _, observation := range group {
			if observation == nil {
				continue
			}
			cloned := proto.Clone(observation).(*cerebrov1.FindingEvidenceObservation)
			cloned.ClaimIds = uniqueSortedStrings(cloned.GetClaimIds())
			cloned.EventIds = uniqueSortedStrings(cloned.GetEventIds())
			cloned.GraphRootUrns = uniqueSortedStrings(cloned.GetGraphRootUrns())
			cloned.GraphRows = mergeGraphEvidenceRows(cloned.GetGraphRows())
			cloned.GraphPathUrns = uniqueSortedStrings(append(cloned.GetGraphPathUrns(), graphPathURNs(cloned.GetGraphRows())...))
			observationsByKey[observationKey(cloned)] = cloned
		}
	}
	keys := make([]string, 0, len(observationsByKey))
	for key := range observationsByKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := observationsByKey[keys[i]]
		right := observationsByKey[keys[j]]
		if left.GetObservedAt().AsTime().Equal(right.GetObservedAt().AsTime()) {
			return keys[i] < keys[j]
		}
		return left.GetObservedAt().AsTime().Before(right.GetObservedAt().AsTime())
	})
	observations := make([]*cerebrov1.FindingEvidenceObservation, 0, len(keys))
	for _, key := range keys {
		observations = append(observations, observationsByKey[key])
	}
	if len(observations) == 0 {
		return nil
	}
	return observations
}

func cloneGraphEvidenceRows(rows []*cerebrov1.GraphEvidenceRow) []*cerebrov1.GraphEvidenceRow {
	if len(rows) == 0 {
		return nil
	}
	cloned := make([]*cerebrov1.GraphEvidenceRow, 0, len(rows))
	for _, row := range rows {
		if row == nil {
			continue
		}
		cloned = append(cloned, proto.Clone(row).(*cerebrov1.GraphEvidenceRow))
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func graphPathURNs(rows []*cerebrov1.GraphEvidenceRow) []string {
	urns := []string{}
	for _, row := range rows {
		if row == nil {
			continue
		}
		for _, path := range row.GetPaths() {
			if path == nil {
				continue
			}
			urns = append(urns, path.GetFromUrn(), path.GetToUrn())
		}
	}
	return uniqueSortedStrings(urns)
}

func graphRowKey(row *cerebrov1.GraphEvidenceRow) string {
	if row == nil {
		return ""
	}
	return strings.TrimSpace(row.GetLabel()) + "\x00" + stringMapKey(row.GetAttributes())
}

func graphPathKey(path *cerebrov1.GraphEvidencePath) string {
	if path == nil {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(path.GetFromUrn()),
		strings.TrimSpace(path.GetRelation()),
		strings.TrimSpace(path.GetToUrn()),
		strings.TrimSpace(path.GetObservedAt()),
		stringMapKey(path.GetAttributes()),
	}, "\x00")
}

func observationKey(observation *cerebrov1.FindingEvidenceObservation) string {
	if observation == nil {
		return ""
	}
	rowKeys := make([]string, 0, len(observation.GetGraphRows()))
	for _, row := range observation.GetGraphRows() {
		rowKeys = append(rowKeys, graphRowKey(row))
		for _, path := range row.GetPaths() {
			rowKeys = append(rowKeys, graphPathKey(path))
		}
	}
	sort.Strings(rowKeys)
	return strings.Join([]string{
		strings.TrimSpace(observation.GetRunId()),
		timestampKey(observation.GetObservedAt()),
		strings.Join(uniqueSortedStrings(observation.GetClaimIds()), "\x00"),
		strings.Join(uniqueSortedStrings(observation.GetEventIds()), "\x00"),
		strings.Join(uniqueSortedStrings(observation.GetGraphRootUrns()), "\x00"),
		strings.Join(uniqueSortedStrings(observation.GetGraphPathUrns()), "\x00"),
		strings.Join(rowKeys, "\x00"),
	}, "\x01")
}

func stringMapKey(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, strings.TrimSpace(key)+"="+strings.TrimSpace(values[key]))
	}
	return strings.Join(parts, "\x00")
}

func mergeStringMaps(existing map[string]string, latest map[string]string) map[string]string {
	if len(existing) == 0 && len(latest) == 0 {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(latest))
	for key, value := range existing {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			merged[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	for key, value := range latest {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			merged[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func earlierTimestamp(left *timestamppb.Timestamp, right *timestamppb.Timestamp) *timestamppb.Timestamp {
	if left == nil || left.AsTime().IsZero() {
		return right
	}
	if right == nil || right.AsTime().IsZero() || left.AsTime().Before(right.AsTime()) {
		return left
	}
	return right
}

func laterTimestamp(left *timestamppb.Timestamp, right *timestamppb.Timestamp) *timestamppb.Timestamp {
	if left == nil || left.AsTime().IsZero() {
		return right
	}
	if right == nil || right.AsTime().IsZero() || left.AsTime().After(right.AsTime()) {
		return left
	}
	return right
}

func timestampKey(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}
