package sync

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

var awsCompositeKeyColumns = map[string][]string{
	"aws_autoscaling_lifecycle_hooks": {"auto_scaling_group_name", "lifecycle_hook_name"},
	"aws_backup_protected_resources":  {"resource_arn"},
	"aws_cloudcontrol_resource_types": {"type_name"},
	"aws_cloudcontrol_resources":      {"type_name", "identifier"},
	"aws_cloudformation_stack_resources": {
		"stack_id",
		"logical_resource_id",
	},
	"aws_cognito_identity_providers": {"user_pool_id", "provider_name"},
	"aws_cognito_user_pool_clients":  {"user_pool_id", "client_id"},
	"aws_ec2_regional_configs":       {"region"},
	"aws_inspector2_coverage":        {"resource_type", "resource_id", "scan_type"},
	"aws_organizations_account_parents": {
		"child_id",
		"parent_id",
	},
	"aws_organizations_policy_targets": {"policy_id", "target_id"},
	"aws_route53_record_sets": {
		"hosted_zone_id",
		"name",
		"type",
		"set_identifier",
		"region",
	},
	"aws_ssm_managed_instances": {"instance_id"},
	"aws_ssm_patch_compliance":  {"instance_id", "baseline_id"},
	"default_actions":           {"listener_arn", "action_order"},
}

func normalizeAWSTableSpecs(tables []TableSpec) []TableSpec {
	normalized := make([]TableSpec, 0, len(tables))
	for _, table := range tables {
		normalized = append(normalized, normalizeAWSTableSpec(table))
	}
	return normalized
}

func normalizeAWSTableSpec(table TableSpec) TableSpec {
	table.Columns = ensureColumns(table.Columns, "account_id", "region")
	if table.Scope == TableRegionScopeRegional && isGlobalTableName(table.Name) {
		table.Scope = TableRegionScopeGlobal
	}
	if !hasColumn(table.Columns, "arn") && !hasColumn(table.Columns, "id") {
		table.Columns = ensureColumns(table.Columns, "id")
	}
	return table
}

func ensureColumns(columns []string, required ...string) []string {
	updated := make([]string, 0, len(columns)+len(required))
	updated = append(updated, columns...)
	for _, column := range required {
		if !hasColumn(updated, column) {
			updated = append(updated, column)
		}
	}
	return updated
}

func (e *SyncEngine) normalizeAWSRows(table TableSpec, region string, rows []map[string]interface{}) []map[string]interface{} {
	for _, row := range rows {
		normalizeRowValues(row)

		if hasColumn(table.Columns, "account_id") && stringValue(row["account_id"]) == "" {
			row["account_id"] = e.accountID
		}

		regionValue := strings.ToLower(stringValue(row["region"]))
		if hasColumn(table.Columns, "region") && (regionValue == "" || regionValue == "global") {
			row["region"] = region
		}

		baseID := deriveAWSBaseID(table.Name, row)
		if hasColumn(table.Columns, "id") && stringValue(row["id"]) == "" && baseID != "" {
			row["id"] = baseID
		}

		if stringValue(row["_cq_id"]) == "" && baseID != "" {
			row["_cq_id"] = buildCQID(e.accountID, region, baseID)
		} else if id := stringValue(row["_cq_id"]); id != "" {
			row["_cq_id"] = id
		}
	}

	return sanitizeRows(table.Name, table.Columns, rows, e.logger)
}

func normalizeRows(tableName string, columns []string, rows []map[string]interface{}, logger *slog.Logger) []map[string]interface{} {
	for _, row := range rows {
		normalizeRowValues(row)
	}
	return sanitizeRows(tableName, columns, rows, logger)
}

func normalizeRowValues(row map[string]interface{}) {
	for key, value := range row {
		if isTimestampField(key) {
			if normalized, ok := normalizeTimestampValue(value); ok {
				row[key] = normalized
				continue
			}
		}

		if normalized, ok := normalizeTimeValue(value); ok {
			row[key] = normalized
			continue
		}

		if isTagSchemaField(key) {
			if normalized, ok := normalizeTags(value); ok {
				row[key] = normalized
			}
		}
	}
}

func isTagSchemaField(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "tags", "labels", "resource_labels":
		return true
	default:
		return false
	}
}

func isTimestampField(key string) bool {
	name := strings.ToLower(strings.TrimSpace(key))
	if name == "" {
		return false
	}

	if strings.HasSuffix(name, "_time") || strings.HasSuffix(name, "_timestamp") || strings.HasSuffix(name, "_at") {
		return true
	}

	switch name {
	case "created", "updated", "last_modified", "create_time", "update_time", "delete_time", "expire_time", "timestamp", "time":
		return true
	default:
		return false
	}
}

func normalizeTimestampValue(value interface{}) (interface{}, bool) {
	const maxSignedInt64 = int64(^uint64(0) >> 1)

	if normalized, ok := normalizeTimeValue(value); ok {
		return normalized, true
	}

	switch typed := value.(type) {
	case string:
		return normalizeTimestampString(typed)
	case []byte:
		return normalizeTimestampString(string(typed))
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return normalizeTimestampEpoch(parsed)
		}
		if parsed, err := typed.Float64(); err == nil {
			return normalizeTimestampEpoch(int64(parsed))
		}
	case int:
		return normalizeTimestampEpoch(int64(typed))
	case int8:
		return normalizeTimestampEpoch(int64(typed))
	case int16:
		return normalizeTimestampEpoch(int64(typed))
	case int32:
		return normalizeTimestampEpoch(int64(typed))
	case int64:
		return normalizeTimestampEpoch(typed)
	case uint:
		if uint64(typed) > uint64(maxSignedInt64) {
			return nil, false
		}
		return normalizeTimestampEpoch(int64(typed)) // #nosec G115 -- guarded above to int64 max.
	case uint8:
		return normalizeTimestampEpoch(int64(typed))
	case uint16:
		return normalizeTimestampEpoch(int64(typed))
	case uint32:
		return normalizeTimestampEpoch(int64(typed))
	case uint64:
		if typed > uint64(maxSignedInt64) {
			return nil, false
		}
		return normalizeTimestampEpoch(int64(typed))
	case float32:
		return normalizeTimestampEpoch(int64(typed))
	case float64:
		return normalizeTimestampEpoch(int64(typed))
	}

	return nil, false
}

func normalizeTimestampString(raw string) (interface{}, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", true
	}

	if digits, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return normalizeTimestampEpoch(digits)
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			if parsed.IsZero() {
				return "", true
			}
			return parsed.UTC().Format(time.RFC3339), true
		}
	}

	return nil, false
}

func normalizeTimestampEpoch(value int64) (interface{}, bool) {
	if value <= 0 {
		return "", true
	}

	var parsed time.Time
	switch {
	case value >= 1_000_000_000_000_000_000:
		parsed = time.Unix(0, value)
	case value >= 1_000_000_000_000_000:
		parsed = time.UnixMicro(value)
	case value >= 1_000_000_000_000:
		parsed = time.UnixMilli(value)
	default:
		parsed = time.Unix(value, 0)
	}

	if parsed.IsZero() {
		return "", true
	}
	return parsed.UTC().Format(time.RFC3339), true
}

func normalizeTimeValue(value interface{}) (interface{}, bool) {
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return "", true
		}
		return typed.UTC().Format(time.RFC3339), true
	case *time.Time:
		if typed == nil || typed.IsZero() {
			return "", true
		}
		return typed.UTC().Format(time.RFC3339), true
	default:
		return nil, false
	}
}

func normalizeTags(value interface{}) (interface{}, bool) {
	if value == nil {
		return nil, false
	}

	switch typed := value.(type) {
	case map[string]string:
		return typed, true
	case map[string]*string:
		normalized := make(map[string]string, len(typed))
		for key, entry := range typed {
			normalized[key] = stringValue(entry)
		}
		return normalized, true
	case map[string]interface{}:
		return tagsFromMap(typed), true
	case string:
		if normalized, ok := normalizeTagsFromJSON(typed); ok {
			return normalized, true
		}
	}

	if normalized, ok := normalizeTagMap(value); ok {
		return normalized, true
	}

	if normalized, ok := normalizeTagSlice(value); ok {
		return normalized, true
	}

	return nil, false
}

func normalizeTagsFromJSON(raw string) (interface{}, bool) {
	if raw == "" {
		return map[string]string{}, true
	}

	var tags map[string]string
	if err := json.Unmarshal([]byte(raw), &tags); err == nil {
		return tags, true
	}

	var tagMap map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &tagMap); err == nil {
		return tagsFromMap(tagMap), true
	}

	var tagList []map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &tagList); err == nil {
		return tagsFromMapSlice(tagList), true
	}

	return nil, false
}

func normalizeTagMap(value interface{}) (interface{}, bool) {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil, false
	}
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Map {
		return nil, false
	}

	normalized := make(map[string]string, rv.Len())
	for _, key := range rv.MapKeys() {
		entry := rv.MapIndex(key)
		normalized[stringValue(key.Interface())] = stringValue(entry.Interface())
	}

	return normalized, true
}

func normalizeTagSlice(value interface{}) (interface{}, bool) {
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}

	if rv.Type().Elem().Kind() == reflect.String {
		return nil, false
	}

	if rv.Len() == 0 {
		return map[string]string{}, true
	}

	tags := make(map[string]string)
	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		if elem.Kind() == reflect.Ptr {
			if elem.IsNil() {
				continue
			}
			elem = elem.Elem()
		}

		if elem.Kind() == reflect.Struct {
			if key, val, ok := tagPairFromStruct(elem); ok {
				tags[key] = val
			}
			continue
		}

		if elem.Kind() == reflect.Map {
			if key, val, ok := tagPairFromMap(elem); ok {
				tags[key] = val
			}
		}
	}

	if len(tags) == 0 {
		return nil, false
	}

	return tags, true
}

func tagPairFromStruct(value reflect.Value) (string, string, bool) {
	keyField := value.FieldByName("Key")
	valueField := value.FieldByName("Value")
	if keyField.IsValid() && valueField.IsValid() {
		key := stringValue(keyField.Interface())
		val := stringValue(valueField.Interface())
		if key != "" {
			return key, val, true
		}
	}

	keyField = value.FieldByName("TagKey")
	valueField = value.FieldByName("TagValue")
	if keyField.IsValid() && valueField.IsValid() {
		key := stringValue(keyField.Interface())
		val := stringValue(valueField.Interface())
		if key != "" {
			return key, val, true
		}
	}

	return "", "", false
}

func tagPairFromMap(value reflect.Value) (string, string, bool) {
	if value.Kind() != reflect.Map {
		return "", "", false
	}

	mapKey := reflect.ValueOf("Key")
	mapVal := reflect.ValueOf("Value")
	if mapKey.Type() == value.Type().Key() {
		key := value.MapIndex(mapKey)
		val := value.MapIndex(mapVal)
		if key.IsValid() && val.IsValid() {
			keyStr := stringValue(key.Interface())
			if keyStr != "" {
				return keyStr, stringValue(val.Interface()), true
			}
		}
	}

	mapKey = reflect.ValueOf("key")
	mapVal = reflect.ValueOf("value")
	if mapKey.Type() == value.Type().Key() {
		key := value.MapIndex(mapKey)
		val := value.MapIndex(mapVal)
		if key.IsValid() && val.IsValid() {
			keyStr := stringValue(key.Interface())
			if keyStr != "" {
				return keyStr, stringValue(val.Interface()), true
			}
		}
	}

	return "", "", false
}

func tagsFromMap(values map[string]interface{}) map[string]string {
	converted := make(map[string]string, len(values))
	for key, value := range values {
		converted[key] = stringValue(value)
	}
	return converted
}

func tagsFromMapSlice(values []map[string]interface{}) map[string]string {
	converted := make(map[string]string, len(values))
	for _, entry := range values {
		key := stringValue(entry["Key"])
		if key == "" {
			key = stringValue(entry["key"])
		}
		if key == "" {
			continue
		}
		val := stringValue(entry["Value"])
		if val == "" {
			val = stringValue(entry["value"])
		}
		converted[key] = val
	}
	return converted
}

func deriveAWSBaseID(table string, row map[string]interface{}) string {
	if arn := stringValue(row["arn"]); arn != "" {
		return arn
	}
	if id := stringValue(row["id"]); id != "" {
		return id
	}
	if columns, ok := awsCompositeKeyColumns[table]; ok {
		if composite := joinRowValues(row, columns); composite != "" {
			return composite
		}
	}

	for _, key := range []string{"resource_arn", "resource_id", "instance_id"} {
		if value := stringValue(row[key]); value != "" {
			return value
		}
	}

	return ""
}

func joinRowValues(row map[string]interface{}, columns []string) string {
	values := make([]string, 0, len(columns))
	for _, column := range columns {
		values = append(values, stringValue(row[column]))
	}
	joined := strings.Join(values, ":")
	if strings.Trim(joined, ":") == "" {
		return ""
	}
	return joined
}

func buildCQID(accountID, region, baseID string) string {
	if baseID == "" {
		return ""
	}
	if strings.HasPrefix(baseID, "arn:") {
		return baseID
	}

	parts := make([]string, 0, 3)
	if accountID != "" {
		parts = append(parts, accountID)
	}
	if region != "" {
		parts = append(parts, region)
	}
	parts = append(parts, baseID)
	return strings.Join(parts, ":")
}

func sanitizeRows(tableName string, columns []string, rows []map[string]interface{}, logger *slog.Logger) []map[string]interface{} {
	allowed := make(map[string]struct{}, len(columns)+2)
	for _, column := range columns {
		allowed[strings.ToLower(column)] = struct{}{}
	}
	allowed["_cq_id"] = struct{}{}
	allowed["_cq_hash"] = struct{}{}

	unknown := make(map[string]struct{})
	for _, row := range rows {
		for key := range row {
			if _, ok := allowed[strings.ToLower(key)]; !ok {
				unknown[strings.ToLower(key)] = struct{}{}
				delete(row, key)
			}
		}
	}

	if len(unknown) > 0 && logger != nil {
		columns := make([]string, 0, len(unknown))
		for column := range unknown {
			columns = append(columns, column)
		}
		sort.Strings(columns)
		logger.Warn("dropping unexpected columns", "table", tableName, "columns", columns)
	}

	return rows
}

func stringValue(value interface{}) string {
	if value == nil {
		return ""
	}

	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case fmt.Stringer:
		return typed.String()
	}

	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return ""
		}
		return stringValue(rv.Elem().Interface())
	}

	return fmt.Sprint(value)
}
