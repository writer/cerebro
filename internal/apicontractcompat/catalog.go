package apicontractcompat

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Catalog struct {
	APIVersion    string             `json:"api_version"`
	Kind          string             `json:"kind"`
	GeneratedAt   time.Time          `json:"generated_at,omitempty"`
	EndpointCount int                `json:"endpoint_count"`
	Endpoints     []EndpointContract `json:"endpoints"`
}

type EndpointContract struct {
	ID               string              `json:"id"`
	Path             string              `json:"path"`
	Method           string              `json:"method"`
	OperationID      string              `json:"operation_id,omitempty"`
	QueryParams      []ParameterContract `json:"query_params,omitempty"`
	Request          *RequestContract    `json:"request,omitempty"`
	SuccessResponses []ResponseContract  `json:"success_responses,omitempty"`
}

type ParameterContract struct {
	Name       string `json:"name"`
	Required   bool   `json:"required"`
	SchemaType string `json:"schema_type,omitempty"`
}

type RequestContract struct {
	ContentTypes   []string        `json:"content_types,omitempty"`
	RequiredFields []FieldContract `json:"required_fields,omitempty"`
}

type ResponseContract struct {
	StatusCode   string          `json:"status_code"`
	ContentTypes []string        `json:"content_types,omitempty"`
	Fields       []FieldContract `json:"fields,omitempty"`
}

type FieldContract struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type CompareReport struct {
	GeneratedAt       time.Time            `json:"generated_at"`
	BaselineEndpoints int                  `json:"baseline_endpoints"`
	CurrentEndpoints  int                  `json:"current_endpoints"`
	AddedEndpoints    []string             `json:"added_endpoints,omitempty"`
	RemovedEndpoints  []string             `json:"removed_endpoints,omitempty"`
	BreakingChanges   []CompatibilityIssue `json:"breaking_changes,omitempty"`
}

type CompatibilityIssue struct {
	EndpointID    string `json:"endpoint_id"`
	ChangeType    string `json:"change_type"`
	Detail        string `json:"detail"`
	StatusCode    string `json:"status_code,omitempty"`
	FieldPath     string `json:"field_path,omitempty"`
	PreviousType  string `json:"previous_type,omitempty"`
	CurrentType   string `json:"current_type,omitempty"`
	ParameterName string `json:"parameter_name,omitempty"`
}

type fieldMeta struct {
	Type     string
	Required bool
}

func BuildCatalogFromFile(path string, generatedAt time.Time) (Catalog, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller provides the explicit OpenAPI/catalog path to snapshot
	if err != nil {
		return Catalog{}, err
	}
	return BuildCatalogFromYAML(payload, generatedAt)
}

func BuildCatalogFromYAML(payload []byte, generatedAt time.Time) (Catalog, error) {
	var root map[string]any
	if err := yaml.Unmarshal(payload, &root); err != nil {
		return Catalog{}, fmt.Errorf("decode openapi yaml: %w", err)
	}
	paths := mapFromAny(root["paths"])
	catalog := Catalog{
		APIVersion:  "devex.cerebro/v1alpha1",
		Kind:        "HTTPAPIContractCatalog",
		GeneratedAt: generatedAt.UTC(),
	}
	if len(paths) == 0 {
		return catalog, nil
	}

	endpoints := make([]EndpointContract, 0)
	for rawPath, rawItem := range paths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}
		pathItem := mapFromAny(rawItem)
		pathParams := parseParameters(root, pathItem["parameters"])
		for _, method := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
			op := mapFromAny(pathItem[method])
			if len(op) == 0 {
				continue
			}
			queryParams := mergeQueryParameters(pathParams, parseParameters(root, op["parameters"]))
			endpoint := EndpointContract{
				ID:               strings.ToUpper(method) + " " + path,
				Path:             path,
				Method:           strings.ToUpper(method),
				OperationID:      strings.TrimSpace(anyToString(op["operationId"])),
				QueryParams:      queryParams,
				Request:          parseRequestContract(root, op["requestBody"]),
				SuccessResponses: parseSuccessResponses(root, op["responses"]),
			}
			endpoints = append(endpoints, endpoint)
		}
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
	catalog.EndpointCount = len(endpoints)
	catalog.Endpoints = endpoints
	return catalog, nil
}

func CompareCatalogs(baseline, current Catalog, generatedAt time.Time) CompareReport {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	report := CompareReport{
		GeneratedAt:       generatedAt.UTC(),
		BaselineEndpoints: baseline.EndpointCount,
		CurrentEndpoints:  current.EndpointCount,
	}
	baselineMap := make(map[string]EndpointContract, len(baseline.Endpoints))
	currentMap := make(map[string]EndpointContract, len(current.Endpoints))
	for _, endpoint := range baseline.Endpoints {
		baselineMap[endpoint.ID] = endpoint
	}
	for _, endpoint := range current.Endpoints {
		currentMap[endpoint.ID] = endpoint
	}

	for id := range currentMap {
		if _, ok := baselineMap[id]; !ok {
			report.AddedEndpoints = append(report.AddedEndpoints, id)
		}
	}
	for id, baselineEndpoint := range baselineMap {
		currentEndpoint, ok := currentMap[id]
		if !ok {
			report.RemovedEndpoints = append(report.RemovedEndpoints, id)
			report.BreakingChanges = append(report.BreakingChanges, CompatibilityIssue{
				EndpointID: id,
				ChangeType: "removed_endpoint",
				Detail:     "endpoint was removed",
			})
			continue
		}
		report.BreakingChanges = append(report.BreakingChanges, compareEndpointQueryParams(id, baselineEndpoint, currentEndpoint)...)
		report.BreakingChanges = append(report.BreakingChanges, compareEndpointRequest(id, baselineEndpoint, currentEndpoint)...)
		report.BreakingChanges = append(report.BreakingChanges, compareEndpointResponses(id, baselineEndpoint, currentEndpoint)...)
	}
	sort.Strings(report.AddedEndpoints)
	sort.Strings(report.RemovedEndpoints)
	sort.Slice(report.BreakingChanges, func(i, j int) bool {
		left := report.BreakingChanges[i]
		right := report.BreakingChanges[j]
		if left.EndpointID != right.EndpointID {
			return left.EndpointID < right.EndpointID
		}
		if left.ChangeType != right.ChangeType {
			return left.ChangeType < right.ChangeType
		}
		if left.StatusCode != right.StatusCode {
			return left.StatusCode < right.StatusCode
		}
		if left.FieldPath != right.FieldPath {
			return left.FieldPath < right.FieldPath
		}
		return left.ParameterName < right.ParameterName
	})
	return report
}

func compareEndpointQueryParams(endpointID string, baseline, current EndpointContract) []CompatibilityIssue {
	baselineParams := map[string]ParameterContract{}
	currentParams := map[string]ParameterContract{}
	for _, param := range baseline.QueryParams {
		baselineParams[param.Name] = param
	}
	for _, param := range current.QueryParams {
		currentParams[param.Name] = param
	}
	issues := make([]CompatibilityIssue, 0)
	for name, param := range baselineParams {
		currentParam, ok := currentParams[name]
		if !ok {
			issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "removed_query_parameter", Detail: "query parameter was removed", ParameterName: name})
			continue
		}
		if param.SchemaType != currentParam.SchemaType {
			issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "changed_query_parameter_type", Detail: "query parameter schema type changed", ParameterName: name, PreviousType: param.SchemaType, CurrentType: currentParam.SchemaType})
		}
		if param.Required != currentParam.Required {
			issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "changed_query_parameter_required", Detail: "query parameter requiredness changed", ParameterName: name, PreviousType: strconv.FormatBool(param.Required), CurrentType: strconv.FormatBool(currentParam.Required)})
		}
	}
	return issues
}

func compareEndpointRequest(endpointID string, baseline, current EndpointContract) []CompatibilityIssue {
	baselineFields := requestFieldMap(baseline.Request)
	currentFields := requestFieldMap(current.Request)
	issues := make([]CompatibilityIssue, 0)
	for path, baselineType := range baselineFields {
		currentType, ok := currentFields[path]
		if !ok {
			issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "removed_required_request_field", Detail: "required request field was removed", FieldPath: path, PreviousType: baselineType})
			continue
		}
		if baselineType != currentType {
			issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "changed_required_request_field_type", Detail: "required request field type changed", FieldPath: path, PreviousType: baselineType, CurrentType: currentType})
		}
	}
	return issues
}

func compareEndpointResponses(endpointID string, baseline, current EndpointContract) []CompatibilityIssue {
	baselineResponses := responseMap(baseline.SuccessResponses)
	currentResponses := responseMap(current.SuccessResponses)
	issues := make([]CompatibilityIssue, 0)
	for status, baselineResponse := range baselineResponses {
		currentResponse, ok := currentResponses[status]
		if !ok {
			issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "removed_success_status_code", Detail: "success response status code was removed", StatusCode: status})
			continue
		}
		baselineFields := responseFieldMap(baselineResponse)
		currentFields := responseFieldMap(currentResponse)
		for fieldPath, baselineType := range baselineFields {
			currentType, ok := currentFields[fieldPath]
			if !ok {
				issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "removed_response_field", Detail: "response field was removed", StatusCode: status, FieldPath: fieldPath, PreviousType: baselineType})
				continue
			}
			if baselineType != currentType {
				issues = append(issues, CompatibilityIssue{EndpointID: endpointID, ChangeType: "changed_response_field_type", Detail: "response field type changed", StatusCode: status, FieldPath: fieldPath, PreviousType: baselineType, CurrentType: currentType})
			}
		}
	}
	return issues
}

func parseParameters(root map[string]any, raw any) []ParameterContract {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	params := make([]ParameterContract, 0, len(items))
	for _, item := range items {
		resolved := resolveSchemaRef(root, mapFromAny(item))
		if len(resolved) == 0 {
			continue
		}
		location := strings.ToLower(strings.TrimSpace(anyToString(resolved["in"])))
		if location != "query" {
			continue
		}
		params = append(params, ParameterContract{
			Name:       strings.TrimSpace(anyToString(resolved["name"])),
			Required:   toBool(resolved["required"]),
			SchemaType: schemaType(root, resolved["schema"]),
		})
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	return params
}

func mergeQueryParameters(groups ...[]ParameterContract) []ParameterContract {
	merged := map[string]ParameterContract{}
	for _, group := range groups {
		for _, param := range group {
			if strings.TrimSpace(param.Name) == "" {
				continue
			}
			merged[param.Name] = param
		}
	}
	if len(merged) == 0 {
		return nil
	}
	params := make([]ParameterContract, 0, len(merged))
	for _, param := range merged {
		params = append(params, param)
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	return params
}

func parseRequestContract(root map[string]any, raw any) *RequestContract {
	body := resolveSchemaRef(root, mapFromAny(raw))
	if len(body) == 0 {
		return nil
	}
	content := mapFromAny(body["content"])
	if len(content) == 0 {
		return nil
	}
	contentTypes := make([]string, 0, len(content))
	fields := map[string]fieldMeta{}
	for contentType, rawMedia := range content {
		contentTypes = append(contentTypes, strings.TrimSpace(contentType))
		media := mapFromAny(rawMedia)
		flattenSchema(root, media["schema"], "", false, fields)
	}
	sort.Strings(contentTypes)
	requiredFields := make([]FieldContract, 0)
	for path, meta := range fields {
		if !meta.Required {
			continue
		}
		requiredFields = append(requiredFields, FieldContract{Path: path, Type: meta.Type})
	}
	sort.Slice(requiredFields, func(i, j int) bool { return requiredFields[i].Path < requiredFields[j].Path })
	return &RequestContract{ContentTypes: contentTypes, RequiredFields: requiredFields}
}

func parseSuccessResponses(root map[string]any, raw any) []ResponseContract {
	responses := mapFromAny(raw)
	if len(responses) == 0 {
		return nil
	}
	contracts := make([]ResponseContract, 0)
	for status, rawResponse := range responses {
		status = strings.TrimSpace(status)
		if !isSuccessStatus(status) {
			continue
		}
		response := resolveSchemaRef(root, mapFromAny(rawResponse))
		content := mapFromAny(response["content"])
		fields := map[string]fieldMeta{}
		contentTypes := make([]string, 0, len(content))
		for contentType, rawMedia := range content {
			contentTypes = append(contentTypes, strings.TrimSpace(contentType))
			media := mapFromAny(rawMedia)
			flattenSchema(root, media["schema"], "", false, fields)
		}
		sort.Strings(contentTypes)
		fieldContracts := make([]FieldContract, 0, len(fields))
		for path, meta := range fields {
			fieldContracts = append(fieldContracts, FieldContract{Path: path, Type: meta.Type})
		}
		sort.Slice(fieldContracts, func(i, j int) bool { return fieldContracts[i].Path < fieldContracts[j].Path })
		contracts = append(contracts, ResponseContract{StatusCode: status, ContentTypes: contentTypes, Fields: fieldContracts})
	}
	sort.Slice(contracts, func(i, j int) bool { return contracts[i].StatusCode < contracts[j].StatusCode })
	return contracts
}

func flattenSchema(root map[string]any, raw any, path string, required bool, fields map[string]fieldMeta) {
	schema := resolveSchemaRef(root, mapFromAny(raw))
	if len(schema) == 0 {
		return
	}
	if allOf, ok := schema["allOf"].([]any); ok {
		for _, item := range allOf {
			flattenSchema(root, item, path, required, fields)
		}
		return
	}
	if variants, ok := schema["oneOf"].([]any); ok && len(variants) > 0 {
		if path != "" {
			addField(fields, path, unionSchemaTypes(root, variants), required)
		}
		return
	}
	if variants, ok := schema["anyOf"].([]any); ok && len(variants) > 0 {
		if path != "" {
			addField(fields, path, unionSchemaTypes(root, variants), required)
		}
		return
	}

	typ := schemaType(root, schema)
	if path != "" {
		addField(fields, path, typ, required)
	}
	if typ == "object" {
		properties := mapFromAny(schema["properties"])
		if len(properties) == 0 {
			return
		}
		requiredSet := requiredKeys(schema["required"])
		keys := make([]string, 0, len(properties))
		for key := range properties {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			flattenSchema(root, properties[key], childPath, requiredSet[key], fields)
		}
		return
	}
	if typ == "array" {
		items := mapFromAny(schema["items"])
		if len(items) == 0 {
			return
		}
		childPath := "[]"
		if path != "" {
			childPath = path + "[]"
		}
		flattenSchema(root, items, childPath, required, fields)
	}
}

func addField(fields map[string]fieldMeta, path, typ string, required bool) {
	if strings.TrimSpace(path) == "" {
		return
	}
	typ = strings.TrimSpace(typ)
	if typ == "" {
		typ = "any"
	}
	existing, ok := fields[path]
	if !ok {
		fields[path] = fieldMeta{Type: typ, Required: required}
		return
	}
	existing.Required = existing.Required || required
	if existing.Type != typ {
		existing.Type = mergeTypes(existing.Type, typ)
	}
	fields[path] = existing
}

func unionSchemaTypes(root map[string]any, values []any) string {
	types := make([]string, 0, len(values))
	for _, value := range values {
		types = append(types, schemaType(root, value))
	}
	return mergeTypes(types...)
}

func mergeTypes(types ...string) string {
	set := map[string]struct{}{}
	for _, typ := range types {
		typ = strings.TrimSpace(typ)
		if typ == "" {
			continue
		}
		set[typ] = struct{}{}
	}
	if len(set) == 0 {
		return "any"
	}
	ordered := make([]string, 0, len(set))
	for typ := range set {
		ordered = append(ordered, typ)
	}
	sort.Strings(ordered)
	if len(ordered) == 1 {
		return ordered[0]
	}
	return "union(" + strings.Join(ordered, "|") + ")"
}

func schemaType(root map[string]any, raw any) string {
	schema := resolveSchemaRef(root, mapFromAny(raw))
	if len(schema) == 0 {
		return "any"
	}
	if variants, ok := schema["oneOf"].([]any); ok && len(variants) > 0 {
		return unionSchemaTypes(root, variants)
	}
	if variants, ok := schema["anyOf"].([]any); ok && len(variants) > 0 {
		return unionSchemaTypes(root, variants)
	}
	typ := strings.ToLower(strings.TrimSpace(anyToString(schema["type"])))
	if typ != "" {
		return typ
	}
	if len(mapFromAny(schema["properties"])) > 0 || schema["additionalProperties"] != nil {
		return "object"
	}
	if len(mapFromAny(schema["items"])) > 0 {
		return "array"
	}
	return "any"
}

func resolveSchemaRef(root map[string]any, schema map[string]any) map[string]any {
	if len(schema) == 0 {
		return nil
	}
	ref := strings.TrimSpace(anyToString(schema["$ref"]))
	if ref == "" {
		return schema
	}
	resolved := resolveRef(root, ref)
	if len(resolved) == 0 {
		return schema
	}
	return resolved
}

func resolveRef(root map[string]any, ref string) map[string]any {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	var current any = root
	for _, part := range parts {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(typed) {
				return nil
			}
			current = typed[idx]
		default:
			return nil
		}
	}
	return mapFromAny(current)
}

func requiredKeys(raw any) map[string]bool {
	out := map[string]bool{}
	switch typed := raw.(type) {
	case []any:
		for _, value := range typed {
			key := strings.TrimSpace(anyToString(value))
			if key != "" {
				out[key] = true
			}
		}
	case []string:
		for _, value := range typed {
			key := strings.TrimSpace(value)
			if key != "" {
				out[key] = true
			}
		}
	}
	return out
}

func requestFieldMap(contract *RequestContract) map[string]string {
	fields := map[string]string{}
	if contract == nil {
		return fields
	}
	for _, field := range contract.RequiredFields {
		fields[field.Path] = field.Type
	}
	return fields
}

func responseMap(responses []ResponseContract) map[string]ResponseContract {
	out := make(map[string]ResponseContract, len(responses))
	for _, response := range responses {
		out[response.StatusCode] = response
	}
	return out
}

func responseFieldMap(response ResponseContract) map[string]string {
	fields := map[string]string{}
	for _, field := range response.Fields {
		fields[field.Path] = field.Type
	}
	return fields
}

func isSuccessStatus(code string) bool {
	code = strings.TrimSpace(code)
	return len(code) == 3 && strings.HasPrefix(code, "2")
}

func mapFromAny(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, val := range typed {
			out[anyToString(key)] = val
		}
		return out
	default:
		return nil
	}
}

func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case fmt.Stringer:
		return typed.String()
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}

func toBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}
