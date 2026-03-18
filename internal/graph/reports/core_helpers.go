package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

func temporalNowUTC() time.Time {
	return time.Now().UTC()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func buildReportGraphSnapshotID(meta Metadata) string {
	if meta.BuiltAt.IsZero() {
		return ""
	}
	providers := append([]string(nil), meta.Providers...)
	accounts := append([]string(nil), meta.Accounts...)
	sort.Strings(providers)
	sort.Strings(accounts)
	payload := fmt.Sprintf("%s|%d|%d|%s|%s",
		meta.BuiltAt.UTC().Format(time.RFC3339Nano),
		meta.NodeCount,
		meta.EdgeCount,
		strings.Join(providers, ","),
		strings.Join(accounts, ","),
	)
	sum := sha256.Sum256([]byte(payload))
	return "graph_snapshot:" + hex.EncodeToString(sum[:12])
}

func sanitizeReportFileName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "artifact"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-", "..", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-.")
	if value == "" {
		return "artifact"
	}
	return value
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func sortedSchemaKindCounts(values map[string]int) []SchemaKindCount {
	if len(values) == 0 {
		return nil
	}
	out := make([]SchemaKindCount, 0, len(values))
	for kind, count := range values {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			kind = "<empty>"
		}
		out = append(out, SchemaKindCount{Kind: kind, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func normalizeNodeMetadataProfile(profile NodeMetadataProfile) NodeMetadataProfile {
	required := uniqueSortedStrings(profile.RequiredKeys)
	requiredSet := make(map[string]struct{}, len(required))
	for _, key := range required {
		requiredSet[key] = struct{}{}
	}

	optionalRaw := uniqueSortedStrings(profile.OptionalKeys)
	optional := make([]string, 0, len(optionalRaw))
	for _, key := range optionalRaw {
		if _, ok := requiredSet[key]; ok {
			continue
		}
		optional = append(optional, key)
	}
	optional = uniqueSortedStrings(optional)

	timestamps := uniqueSortedStrings(profile.TimestampKeys)
	enumValues := make(map[string][]string)
	for key, values := range profile.EnumValues {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		normalizedValues := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			normalizedValues = append(normalizedValues, value)
		}
		normalizedValues = uniqueSortedStrings(normalizedValues)
		if len(normalizedValues) == 0 {
			continue
		}
		enumValues[key] = normalizedValues
	}
	if len(enumValues) == 0 {
		enumValues = nil
	}

	profile = NodeMetadataProfile{
		RequiredKeys:  required,
		OptionalKeys:  optional,
		TimestampKeys: timestamps,
		EnumValues:    enumValues,
	}
	if !hasNodeMetadataProfile(profile) {
		return NodeMetadataProfile{}
	}
	return profile
}

func hasNodeMetadataProfile(profile NodeMetadataProfile) bool {
	return len(profile.RequiredKeys) > 0 ||
		len(profile.OptionalKeys) > 0 ||
		len(profile.TimestampKeys) > 0 ||
		len(profile.EnumValues) > 0
}

func matchesPropertyType(value any, expectedType string) bool {
	switch expectedType {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			return true
		default:
			return false
		}
	case "number":
		switch value.(type) {
		case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
			return true
		default:
			return false
		}
	case "object":
		if value == nil {
			return false
		}
		kind := reflect.TypeOf(value).Kind()
		return kind == reflect.Map || kind == reflect.Struct
	case "array":
		if value == nil {
			return false
		}
		kind := reflect.TypeOf(value).Kind()
		return kind == reflect.Slice || kind == reflect.Array
	case "timestamp":
		switch typed := value.(type) {
		case time.Time:
			return true
		case string:
			_, err := time.Parse(time.RFC3339, strings.TrimSpace(typed))
			return err == nil
		default:
			return false
		}
	case "duration":
		switch typed := value.(type) {
		case time.Duration:
			return true
		case string:
			_, err := time.ParseDuration(strings.TrimSpace(typed))
			return err == nil
		default:
			return false
		}
	default:
		return true
	}
}
