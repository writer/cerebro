package contracttest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourceregistry"
)

type Fixture struct {
	SourceID       string
	ResourceFamily string
	Ref            string
	Body           []byte
}

type FixtureResult struct {
	SourceID       string
	ResourceFamily string
	EventCount     int
}

func ValidateFixture(ctx context.Context, definition connectordefinitions.Definition, fixture Fixture) (FixtureResult, error) {
	family, ok := familyByID(definition.ResourceFamilies, fixture.ResourceFamily)
	if !ok {
		return FixtureResult{}, fmt.Errorf("%s fixture references unknown family %q", definition.SourceID, fixture.ResourceFamily)
	}
	records, err := recordsFromFixtureBody(family, fixture.Body)
	if err != nil {
		return FixtureResult{}, err
	}
	if len(records) == 0 {
		return FixtureResult{}, fmt.Errorf("%s %s record_selector yielded no records", definition.SourceID, family.ID)
	}
	if err := validateProjectionFields(definition.SourceID, family, records[0]); err != nil {
		return FixtureResult{}, err
	}
	if err := validateRequiredPayloadFields(definition.SourceID, family, records[0]); err != nil {
		return FixtureResult{}, err
	}
	runtimeResult, err := sourceregistry.ReadDynamicDefinitionFixture(ctx, definition, family.ID, fixture.Body)
	if err != nil {
		return FixtureResult{}, fmt.Errorf("%s %s runtime read: %w", definition.SourceID, family.ID, err)
	}
	if runtimeResult.EventCount == 0 {
		return FixtureResult{}, fmt.Errorf("%s %s runtime emitted no events", definition.SourceID, family.ID)
	}
	if runtimeResult.Query == nil {
		return FixtureResult{}, fmt.Errorf("%s %s fixture server received no request", definition.SourceID, family.ID)
	}
	if err := validatePaginationRequest(definition.SourceID, family, runtimeResult.Query); err != nil {
		return FixtureResult{}, err
	}
	for _, kind := range runtimeResult.EventKinds {
		if got := strings.TrimSpace(kind); got != eventKind(definition.SourceID, family) {
			return FixtureResult{}, fmt.Errorf("%s %s event kind = %q, want %q", definition.SourceID, family.ID, got, eventKind(definition.SourceID, family))
		}
	}
	for _, ref := range runtimeResult.SchemaRefs {
		if got := strings.TrimSpace(ref); got != schemaRef(definition.SourceID, family) {
			return FixtureResult{}, fmt.Errorf("%s %s schema_ref = %q, want %q", definition.SourceID, family.ID, got, schemaRef(definition.SourceID, family))
		}
	}
	return FixtureResult{SourceID: definition.SourceID, ResourceFamily: family.ID, EventCount: runtimeResult.EventCount}, nil
}

func familyByID(families []connectordefinitions.ResourceFamily, familyID string) (connectordefinitions.ResourceFamily, bool) {
	for _, family := range families {
		if strings.TrimSpace(family.ID) == strings.TrimSpace(familyID) {
			return family, true
		}
	}
	return connectordefinitions.ResourceFamily{}, false
}

func recordsFromFixtureBody(family connectordefinitions.ResourceFamily, body []byte) ([]map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%s fixture is not valid JSON: %w", family.ID, err)
	}
	rawRecords, err := selectRecords(value, family)
	if err != nil {
		return nil, err
	}
	records := make([]map[string]any, 0, len(rawRecords))
	for _, raw := range rawRecords {
		record, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s fixture selected a non-object record", family.ID)
		}
		records = append(records, record)
	}
	return records, nil
}

func selectRecords(value any, family connectordefinitions.ResourceFamily) ([]any, error) {
	if family.Singleton {
		return []any{value}, nil
	}
	if records, ok := value.([]any); ok {
		return records, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s fixture response must be an object or array", family.ID)
	}
	keys := []string{}
	if key := strings.TrimSpace(family.ListKey); key != "" {
		keys = append(keys, key)
	}
	if key := listKeyFromSelector(family.RecordSelector); key != "" {
		keys = append(keys, key)
	}
	keys = append(keys, "data", "items", "results", "records")
	for _, key := range keys {
		if records, ok := object[key].([]any); ok {
			return records, nil
		}
	}
	return nil, fmt.Errorf("%s fixture response did not contain a selected record list", family.ID)
}

func validateProjectionFields(sourceID string, family connectordefinitions.ResourceFamily, record map[string]any) error {
	if family.Projection == nil {
		return nil
	}
	for target, path := range family.Projection.Fields {
		path = strings.TrimSpace(path)
		if target == "" || path == "" {
			continue
		}
		if !pathResolves(record, path) {
			return fmt.Errorf("%s %s projection field %s source path %q did not resolve to a non-empty value", sourceID, family.ID, target, path)
		}
	}
	return nil
}

func validateRequiredPayloadFields(sourceID string, family connectordefinitions.ResourceFamily, record map[string]any) error {
	for _, path := range family.Event.RequiredPayloadFields {
		if !pathResolves(record, path) {
			return fmt.Errorf("%s %s required payload field %q did not resolve to a non-empty value", sourceID, family.ID, path)
		}
	}
	return nil
}

func validatePaginationRequest(sourceID string, family connectordefinitions.ResourceFamily, query url.Values) error {
	if family.Pagination == nil {
		return nil
	}
	for _, key := range []string{family.Pagination.PageSizeParam, family.Pagination.LimitParam} {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		raw := strings.TrimSpace(query.Get(key))
		if raw == "" {
			return fmt.Errorf("%s %s pagination param %q was not sent", sourceID, family.ID, key)
		}
		if _, err := strconv.Atoi(raw); err != nil {
			return fmt.Errorf("%s %s pagination param %q = %q is not an integer", sourceID, family.ID, key, raw)
		}
	}
	if family.Pagination.Type == "page" && strings.TrimSpace(family.Pagination.PageParam) != "" && query.Get(family.Pagination.PageParam) == "" {
		return fmt.Errorf("%s %s pagination param %q was not sent", sourceID, family.ID, family.Pagination.PageParam)
	}
	return nil
}

func pathResolves(record map[string]any, path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	for _, alternative := range strings.Split(path, "|") {
		if valueAtPath(record, strings.TrimSpace(alternative)) {
			return true
		}
	}
	return false
}

func valueAtPath(record map[string]any, path string) bool {
	if path == "" {
		return false
	}
	var current any = record
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[part]
		if !ok {
			return false
		}
	}
	switch typed := current.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case nil:
		return false
	case []any:
		return len(typed) != 0
	case map[string]any:
		return len(typed) != 0
	default:
		return fmt.Sprint(typed) != ""
	}
}

func listKeyFromSelector(selector string) string {
	selector = strings.TrimSpace(selector)
	if strings.HasPrefix(selector, "$.") && strings.HasSuffix(selector, "[*]") {
		key := strings.TrimSuffix(strings.TrimPrefix(selector, "$."), "[*]")
		if !strings.Contains(key, ".") {
			return key
		}
	}
	return ""
}

func eventKind(sourceID string, family connectordefinitions.ResourceFamily) string {
	if kind := strings.TrimSpace(family.Event.Kind); kind != "" {
		return kind
	}
	if kind := strings.TrimSpace(family.EventKind); kind != "" {
		return kind
	}
	return strings.TrimSpace(sourceID) + "." + strings.TrimSpace(family.ID)
}

func schemaRef(sourceID string, family connectordefinitions.ResourceFamily) string {
	if ref := strings.TrimSpace(family.Event.SchemaRef); ref != "" {
		return ref
	}
	return strings.TrimSpace(sourceID) + "/" + strings.TrimSpace(family.ID) + "/v1"
}
