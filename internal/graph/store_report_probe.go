package graph

import "encoding/json"

// StoreReportProbe defines one snapshot-backed derived report workload.
type StoreReportProbe struct {
	Name  string
	Build func(*Graph) (any, error)
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
