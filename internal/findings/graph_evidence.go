package findings

import (
	"encoding/json"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func newGraphEvidenceRow(label string, attributes map[string]string, paths ...*cerebrov1.GraphEvidencePath) *cerebrov1.GraphEvidenceRow {
	return &cerebrov1.GraphEvidenceRow{
		Label:      strings.TrimSpace(label),
		Attributes: compactStringMap(attributes),
		Paths:      compactGraphEvidencePaths(paths),
	}
}

func newGraphEvidencePath(fromURN, fromLabel, fromType, relation, toURN, toLabel, toType string, attributes map[string]string) *cerebrov1.GraphEvidencePath {
	compactAttributes := compactStringMap(attributes)
	return &cerebrov1.GraphEvidencePath{
		FromUrn:    strings.TrimSpace(fromURN),
		FromLabel:  strings.TrimSpace(fromLabel),
		FromType:   strings.TrimSpace(fromType),
		Relation:   strings.TrimSpace(relation),
		ToUrn:      strings.TrimSpace(toURN),
		ToLabel:    strings.TrimSpace(toLabel),
		ToType:     strings.TrimSpace(toType),
		Attributes: compactAttributes,
		ObservedAt: graphPathObservedAt(compactAttributes),
	}
}

func graphPathObservedAt(attributes map[string]string) string {
	for _, key := range []string{"at", "observed_at", "last_observed_at", "last_seen_at", "last_active_date", "created_at", "updated_at"} {
		if value := strings.TrimSpace(attributes[key]); value != "" {
			return value
		}
	}
	return ""
}

func compactStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func compactGraphEvidencePaths(paths []*cerebrov1.GraphEvidencePath) []*cerebrov1.GraphEvidencePath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]*cerebrov1.GraphEvidencePath, 0, len(paths))
	for _, path := range paths {
		if path == nil {
			continue
		}
		if strings.TrimSpace(path.GetFromUrn()) == "" && strings.TrimSpace(path.GetToUrn()) == "" {
			continue
		}
		out = append(out, path)
	}
	return out
}

func stringMapJSON(values []map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	cleaned := make([]map[string]string, 0, len(values))
	for _, value := range values {
		compact := compactStringMap(value)
		if len(compact) == 0 {
			continue
		}
		cleaned = append(cleaned, compact)
	}
	if len(cleaned) == 0 {
		return ""
	}
	payload, err := json.Marshal(cleaned)
	if err != nil {
		return ""
	}
	return string(payload)
}

func sortedStringSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			keys = append(keys, trimmed)
		}
	}
	sort.Strings(keys)
	return keys
}
