package openapigen

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions"
)

const (
	defaultMaxFamilies = 4
	defaultTenantID    = "builtin_catalog"
)

var pathParamPattern = regexp.MustCompile(`\{([^{}]+)\}`)

// Request configures OpenAPI-to-connector-definition generation.
type Request struct {
	SourceID    string
	TenantID    string
	DisplayName string
	Description string
	Categories  []string
	BaseURL     string
	AuthModel   string
	MaxFamilies int
	AllFamilies bool
}

// Endpoint reports one OpenAPI endpoint considered by the generator.
type Endpoint struct {
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	RenderedPath       string   `json:"rendered_path,omitempty"`
	FamilyID           string   `json:"family_id,omitempty"`
	RecordSelector     string   `json:"record_selector,omitempty"`
	IDField            string   `json:"id_field,omitempty"`
	NameField          string   `json:"name_field,omitempty"`
	ProjectionTemplate string   `json:"projection_template,omitempty"`
	Score              int      `json:"score,omitempty"`
	Reasons            []string `json:"reasons,omitempty"`
}

// Report describes generation decisions without embedding the generated definition.
type Report struct {
	SourceID      string     `json:"source_id"`
	BaseURL       string     `json:"base_url,omitempty"`
	AuthModel     string     `json:"auth_model,omitempty"`
	ConfigFields  []string   `json:"config_fields,omitempty"`
	Selected      []Endpoint `json:"selected,omitempty"`
	Skipped       []Endpoint `json:"skipped,omitempty"`
	EndpointCount int        `json:"endpoint_count,omitempty"`
}

type candidate struct {
	endpoint          Endpoint
	resource          connectordefinitions.ResourceFamily
	configFields      []connectordefinitions.Field
	permissionsNeeded []string
	staticSegments    []string
}

// Generate builds a connector definition from high-value read endpoints in an OpenAPI document.
func Generate(doc *openapi3.T, request Request) (connectordefinitions.Definition, Report, error) {
	if doc == nil {
		return connectordefinitions.Definition{}, Report{}, fmt.Errorf("OpenAPI document is required")
	}
	sourceID := normalizeID(firstNonEmpty(request.SourceID, infoTitle(doc), "openapi_source"))
	displayName := strings.TrimSpace(firstNonEmpty(request.DisplayName, infoTitle(doc), titleFromID(sourceID)))
	description := strings.TrimSpace(firstNonEmpty(request.Description, infoDescription(doc), "Generated from an OpenAPI description."))
	tenantID := normalizeID(firstNonEmpty(request.TenantID, defaultTenantID))
	baseURL, baseURLConfigField := inferBaseURL(doc, request.BaseURL)
	auth := inferAuth(doc, request.AuthModel)
	candidates := collectCandidates(doc, sourceID)
	if len(candidates) == 0 {
		return connectordefinitions.Definition{}, Report{}, fmt.Errorf("no sourcegen-ready GET list endpoints found in OpenAPI document")
	}
	maxFamilies := request.MaxFamilies
	if request.AllFamilies {
		maxFamilies = 0
	} else if maxFamilies <= 0 {
		maxFamilies = defaultMaxFamilies
	}
	selected, skipped := selectCandidates(candidates, maxFamilies)
	configFields := mergeConfigFields(baseURLConfigField, selected)
	definition := connectordefinitions.Definition{
		SchemaVersion:  connectordefinitions.SchemaVersionIntegrationV1,
		TenantID:       tenantID,
		SourceID:       sourceID,
		DisplayName:    displayName,
		Description:    description,
		Categories:     normalizeStrings(defaultIfEmpty(request.Categories, []string{"security"})),
		Runtime:        connectordefinitions.RuntimeJSONAPI,
		Stage:          connectordefinitions.StageDraft,
		CurrentVersion: 1,
		ConfigFields:   configFields,
		Auth:           auth,
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: baseURL,
			Verification: &connectordefinitions.VerificationSpec{
				Method:       "GET",
				Path:         selected[0].resource.Path,
				ExpectStatus: []int{200},
			},
			Retry: &connectordefinitions.RetrySpec{
				Statuses:         []int{429, 500, 502, 503, 504},
				Backoff:          "exponential",
				RetryAfterHeader: "Retry-After",
				MaxAttempts:      3,
			},
		},
		ResourceFamilies: resourcesFromCandidates(selected),
	}
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return connectordefinitions.Definition{}, Report{}, err
	}
	if normalized.Validation.Status == connectordefinitions.ValidationBlocked {
		return connectordefinitions.Definition{}, Report{}, fmt.Errorf("generated definition is not valid: %s", normalized.Validation.Summary)
	}
	report := Report{
		SourceID:      normalized.SourceID,
		BaseURL:       baseURL,
		AuthModel:     normalized.Auth.Model,
		ConfigFields:  fieldKeys(normalized.ConfigFields),
		Selected:      endpointsFromCandidates(selected),
		Skipped:       endpointsFromCandidates(skipped),
		EndpointCount: len(candidates),
	}
	return normalized, report, nil
}

func collectCandidates(doc *openapi3.T, sourceID string) []candidate {
	paths := sortedPathItems(doc)
	candidates := []candidate{}
	for _, pair := range paths {
		if pair.item == nil {
			continue
		}
		operations := pair.item.Operations()
		methods := sortedOperationMethods(operations)
		for _, method := range methods {
			operation := operations[method]
			if operation == nil || operation.Deprecated {
				continue
			}
			schema := responseSchema(operation)
			if method != "GET" && (method != "POST" || !isPostListing(operation, schema)) {
				continue
			}
			selector, listKey, itemSchema, ok := recordShape(pair.path, schema)
			if !ok {
				continue
			}
			renderedPath, pathConfigFields := renderPathTemplate(pair.path)
			staticSegments := staticPathSegments(pair.path)
			familyID := familyIDFromPath(pair.path)
			properties := schemaProperties(itemSchema)
			idField := chooseField(properties, []string{"id", "uuid", "uid", "sid", "key", "slug", "name", "email", "uri", "self", "ref", "handle", "external_id", "object_id", "resource_id", "asset_id", "record_id", "item_id", "entity_id", "guid", "_id"})
			if idField == "" {
				idField = "id"
			}
			nameField := chooseField(properties, []string{"name", "display_name", "displayName", "title", "friendly_name", "label", "login", "username", "email", "slug", "summary", "description", "subject", "hostname", "url", "self"})
			template := projectionTemplate(familyID, pair.path, operation, properties)
			eventKind := eventKind(sourceID, familyID)
			resource := connectordefinitions.ResourceFamily{
				ID:             familyID,
				Label:          titleFromID(familyID),
				Path:           renderedPath,
				Method:         method,
				RecordSelector: selector,
				ListKey:        listKey,
				IDField:        idField,
				NameField:      nameField,
				Event: connectordefinitions.EventMappingSpec{
					Kind:                  eventKind,
					SchemaRef:             sourceID + "/" + familyID + "/v1",
					URNKind:               sourceID + "_" + familyID,
					RequiredPayloadFields: []string{idField},
				},
				Pagination: paginationSpec(pair.item, operation),
				Projection: projectionSpec(template, familyID, idField, nameField, properties),
				Coverage: []connectordefinitions.CoverageDimensionSpec{{
					ID:        coverageID(template, familyID),
					Type:      coverageType(template),
					Title:     titleFromID(familyID),
					Families:  []string{familyID},
					Support:   "partial",
					HighValue: isHighValue(template, familyID, pair.path),
				}},
				PermissionsNeeded:     permissionsNeeded(doc, operation),
				SensitivePayloadPaths: sensitivePaths(properties),
				DefaultEnabled:        isHighValue(template, familyID, pair.path),
			}
			score, reasons := endpointScore(pair.path, operation, selector, template, pathConfigFields)
			candidates = append(candidates, candidate{
				endpoint: Endpoint{
					Method:             method,
					Path:               pair.path,
					RenderedPath:       renderedPath,
					FamilyID:           familyID,
					RecordSelector:     selector,
					IDField:            idField,
					NameField:          nameField,
					ProjectionTemplate: template,
					Score:              score,
					Reasons:            reasons,
				},
				resource:          resource,
				configFields:      pathConfigFields,
				permissionsNeeded: resource.PermissionsNeeded,
				staticSegments:    staticSegments,
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].endpoint.Score != candidates[j].endpoint.Score {
			return candidates[i].endpoint.Score > candidates[j].endpoint.Score
		}
		if candidates[i].resource.ID != candidates[j].resource.ID {
			return candidates[i].resource.ID < candidates[j].resource.ID
		}
		return candidates[i].endpoint.Path < candidates[j].endpoint.Path
	})
	return candidates
}

func selectCandidates(candidates []candidate, maxFamilies int) ([]candidate, []candidate) {
	selected := []candidate{}
	skipped := []candidate{}
	used := map[string]struct{}{}
	selectedKeys := map[string]struct{}{}
	prepare := func(next candidate) candidate {
		next.resource.ID = uniqueFamilyID(next.resource.ID, next.staticSegments, used)
		next.resource.Label = titleFromID(next.resource.ID)
		next.resource.Event.Kind = eventKindFromExisting(next.resource.Event.Kind, next.resource.ID)
		next.resource.Event.SchemaRef = schemaRefFromExisting(next.resource.Event.SchemaRef, next.resource.ID)
		next.resource.Event.URNKind = urnKindFromExisting(next.resource.Event.URNKind, next.resource.ID)
		next.resource.Coverage[0].ID = coverageID(next.resource.Projection.Template, next.resource.ID)
		next.resource.Coverage[0].Title = titleFromID(next.resource.ID)
		next.resource.Coverage[0].Families = []string{next.resource.ID}
		next.endpoint.FamilyID = next.resource.ID
		used[next.resource.ID] = struct{}{}
		return next
	}
	add := func(next candidate) {
		key := candidateKey(next)
		next = prepare(next)
		selected = append(selected, next)
		selectedKeys[key] = struct{}{}
	}
	if maxFamilies > 0 {
		seenTemplates := map[string]struct{}{}
		for _, next := range candidates {
			if len(selected) >= maxFamilies {
				break
			}
			template := ""
			if next.resource.Projection != nil {
				template = next.resource.Projection.Template
			}
			if _, ok := seenTemplates[template]; ok {
				continue
			}
			seenTemplates[template] = struct{}{}
			add(next)
		}
	}
	for _, next := range candidates {
		if _, ok := selectedKeys[candidateKey(next)]; ok {
			continue
		}
		if maxFamilies > 0 && len(selected) >= maxFamilies {
			skipped = append(skipped, next)
			continue
		}
		add(next)
	}
	return selected, skipped
}

func candidateKey(candidate candidate) string {
	return candidate.endpoint.Method + " " + candidate.endpoint.Path + " " + candidate.endpoint.FamilyID
}

func resourcesFromCandidates(candidates []candidate) []connectordefinitions.ResourceFamily {
	resources := make([]connectordefinitions.ResourceFamily, 0, len(candidates))
	for _, candidate := range candidates {
		resources = append(resources, candidate.resource)
	}
	return resources
}

func endpointsFromCandidates(candidates []candidate) []Endpoint {
	endpoints := make([]Endpoint, 0, len(candidates))
	for _, candidate := range candidates {
		endpoints = append(endpoints, candidate.endpoint)
	}
	return endpoints
}

func inferAuth(doc *openapi3.T, override string) connectordefinitions.AuthSpec {
	if model := strings.TrimSpace(override); model != "" {
		return authSpec(model, nil)
	}
	for _, scheme := range sortedSecuritySchemes(doc) {
		value := scheme.scheme
		if value == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value.Type)) {
		case "oauth2":
			if value.Flows != nil {
				if value.Flows.ClientCredentials != nil {
					return oauthAuthSpec("oauth_client_credentials", value.Flows.ClientCredentials)
				}
				if value.Flows.AuthorizationCode != nil {
					return oauthAuthSpec("oauth_authorization_code", value.Flows.AuthorizationCode)
				}
			}
		case "http":
			switch strings.ToLower(strings.TrimSpace(value.Scheme)) {
			case "bearer":
				return authSpec("bearer_token", nil)
			case "basic":
				return authSpec("basic", nil)
			}
		case "apikey":
			return authSpec("api_key", nil)
		}
	}
	return authSpec("bearer_token", nil)
}

func oauthAuthSpec(model string, flow *openapi3.OAuthFlow) connectordefinitions.AuthSpec {
	spec := authSpec(model, nil)
	if flow == nil {
		return spec
	}
	spec.AuthorizationURL = flow.AuthorizationURL
	spec.TokenURL = flow.TokenURL
	spec.RefreshURL = flow.RefreshURL
	spec.Scopes = sortedStringMapKeys(flow.Scopes)
	spec.ScopeSeparator = " "
	spec.TokenRequestAuthMethod = "client_secret_basic"
	spec.TokenExpirationBufferSeconds = 300
	return spec
}

func authSpec(model string, _ *openapi3.SecurityScheme) connectordefinitions.AuthSpec {
	model = strings.TrimSpace(model)
	spec := connectordefinitions.AuthSpec{
		Model:              model,
		RequiresReferences: model != "none",
	}
	switch model {
	case "none":
		return spec
	case "api_key":
		spec.CredentialFields = []connectordefinitions.Field{secretField("api_key", "API key")}
	case "basic":
		spec.CredentialFields = []connectordefinitions.Field{
			{Key: "username", Label: "Username", Required: true, ReferenceOnly: true},
			secretField("password", "Password"),
		}
	case "oauth_client_credentials":
		spec.CredentialFields = []connectordefinitions.Field{
			secretField("client_id", "Client ID"),
			secretField("client_secret", "Client secret"),
		}
	case "oauth_authorization_code":
		spec.CredentialFields = []connectordefinitions.Field{secretField("oauth_client_reference", "OAuth client reference")}
	default:
		spec.CredentialFields = []connectordefinitions.Field{secretField("token", "Bearer token")}
	}
	return spec
}

func secretField(key, label string) connectordefinitions.Field {
	return connectordefinitions.Field{
		Key:           key,
		Label:         label,
		Required:      true,
		Secret:        true,
		ReferenceOnly: true,
	}
}

func inferBaseURL(doc *openapi3.T, override string) (string, *connectordefinitions.Field) {
	if value := strings.TrimSpace(override); value != "" {
		return value, nil
	}
	for _, server := range doc.Servers {
		if server == nil {
			continue
		}
		value := strings.TrimSpace(server.URL)
		if value == "" {
			continue
		}
		return normalizeServerURL(value), nil
	}
	return "https://${config.api_base_url}", &connectordefinitions.Field{
		Key:         "api_base_url",
		Label:       "API base URL",
		Required:    true,
		Placeholder: "api.example.com",
	}
}

func normalizeServerURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(value, "/")
	}
	return strings.TrimRight(parsed.String(), "/")
}

// isPostListing determines whether a POST operation is a listing endpoint
// (returns an array of records) rather than a creation/action endpoint.
// A POST is considered a listing endpoint if its response schema is an array
// or an object with an array field (same shape as GET listing endpoints).
func isPostListing(_ *openapi3.Operation, schema *openapi3.SchemaRef) bool {
	value := schemaValue(schema)
	if value == nil {
		return false
	}
	if isSchemaType(value, "array") {
		return true
	}
	if isSchemaType(value, "object") && value.Properties != nil {
		for _, prop := range value.Properties {
			if isArraySchema(prop) {
				return true
			}
		}
	}
	return false
}

func responseSchema(operation *openapi3.Operation) *openapi3.SchemaRef {
	if operation == nil || operation.Responses == nil {
		return nil
	}
	for _, status := range []int{200, 206, 201} {
		if schema := schemaFromResponse(operation.Responses.Status(status)); schema != nil {
			return schema
		}
	}
	responses := operation.Responses.Map()
	codes := make([]string, 0, len(responses))
	for code := range responses {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		if !strings.HasPrefix(code, "2") {
			continue
		}
		if schema := schemaFromResponse(responses[code]); schema != nil {
			return schema
		}
	}
	return schemaFromResponse(operation.Responses.Default())
}

func schemaFromResponse(response *openapi3.ResponseRef) *openapi3.SchemaRef {
	if response == nil || response.Value == nil {
		return nil
	}
	if media := response.Value.Content.Get("application/json"); media != nil && media.Schema != nil {
		return media.Schema
	}
	keys := make([]string, 0, len(response.Value.Content))
	for key := range response.Value.Content {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.Contains(key, "json") {
			continue
		}
		if media := response.Value.Content[key]; media != nil && media.Schema != nil {
			return media.Schema
		}
	}
	for _, key := range keys {
		if media := response.Value.Content[key]; media != nil && media.Schema != nil {
			return media.Schema
		}
	}
	return nil
}

func recordShape(path string, schema *openapi3.SchemaRef) (string, string, *openapi3.SchemaRef, bool) {
	value := schemaValue(schema)
	if value == nil {
		return "", "", nil, false
	}
	if isSchemaType(value, "array") && value.Items != nil {
		return "$[*]", "", value.Items, true
	}
	for _, sub := range value.AllOf {
		if selector, listKey, item, ok := recordShape(path, sub); ok {
			return selector, listKey, item, true
		}
	}
	properties := schemaProperties(schema)
	preferred := append([]string{"data", "items", "results", "records", "resources", "values"}, lastStaticSegment(path), singularize(lastStaticSegment(path)))
	for _, key := range preferred {
		if ref := properties[key]; isArraySchema(ref) {
			return "$." + key + "[*]", key, ref.Value.Items, true
		}
	}
	keys := sortedStringMapKeys(properties)
	for _, key := range keys {
		if ref := properties[key]; isArraySchema(ref) {
			return "$." + key + "[*]", key, ref.Value.Items, true
		}
	}
	return "", "", nil, false
}

func schemaProperties(schema *openapi3.SchemaRef) map[string]*openapi3.SchemaRef {
	out := map[string]*openapi3.SchemaRef{}
	value := schemaValue(schema)
	if value == nil {
		return out
	}
	for _, sub := range value.AllOf {
		for key, ref := range schemaProperties(sub) {
			out[key] = ref
		}
	}
	for key, ref := range value.Properties {
		out[key] = ref
	}
	return out
}

func schemaValue(schema *openapi3.SchemaRef) *openapi3.Schema {
	if schema == nil {
		return nil
	}
	return schema.Value
}

func isArraySchema(schema *openapi3.SchemaRef) bool {
	value := schemaValue(schema)
	return value != nil && isSchemaType(value, "array") && value.Items != nil
}

func isSchemaType(schema *openapi3.Schema, value string) bool {
	return schema != nil && schema.Type != nil && schema.Type.Is(value)
}

func chooseField(properties map[string]*openapi3.SchemaRef, candidates []string) string {
	if len(properties) == 0 {
		return ""
	}
	lower := map[string]string{}
	for key := range properties {
		lower[strings.ToLower(key)] = key
	}
	for _, candidate := range candidates {
		if key, ok := lower[strings.ToLower(candidate)]; ok {
			return key
		}
	}
	keys := sortedStringMapKeys(properties)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func paginationSpec(pathItem *openapi3.PathItem, operation *openapi3.Operation) *connectordefinitions.PaginationSpec {
	names := queryParameterNames(pathItem, operation)
	lowerNames := map[string]string{}
	for name := range names {
		lowerNames[strings.ToLower(name)] = name
	}
	hasCI := func(values ...string) string {
		for _, value := range values {
			if original, ok := lowerNames[strings.ToLower(value)]; ok {
				return original
			}
		}
		return ""
	}
	pageSize := hasCI("per_page", "page_size", "pagesize", "limit", "max_results", "maxresults", "perpage", "take", "count")
	switch {
	case hasCI("cursor", "page_token", "pagetoken", "next_cursor", "nextcursor", "nexttoken", "next_token", "starting_after", "startingafter", "after", "ending_before", "endingbefore", "before") != "":
		return &connectordefinitions.PaginationSpec{Type: "cursor", CursorParam: hasCI("cursor", "page_token", "pagetoken", "next_cursor", "nextcursor", "nexttoken", "next_token", "starting_after", "startingafter", "after", "ending_before", "endingbefore", "before"), PageSizeParam: pageSize, PageSize: 100}
	case hasCI("page") != "":
		return &connectordefinitions.PaginationSpec{Type: "page", PageParam: hasCI("page"), PageSizeParam: pageSize, StartPage: 1, InjectFirstPage: true, PageSize: 100}
	case hasCI("offset", "skip") != "":
		return &connectordefinitions.PaginationSpec{Type: "offset", OffsetParam: hasCI("offset", "skip"), LimitParam: pageSize, PageSize: 100}
	case pageSize != "":
		return &connectordefinitions.PaginationSpec{Type: "page", PageSizeParam: pageSize, PageSize: 100}
	default:
		return &connectordefinitions.PaginationSpec{Type: "none"}
	}
}

func queryParameterNames(pathItem *openapi3.PathItem, operation *openapi3.Operation) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(parameters openapi3.Parameters) {
		for _, ref := range parameters {
			if ref == nil || ref.Value == nil || strings.ToLower(ref.Value.In) != "query" {
				continue
			}
			name := strings.TrimSpace(ref.Value.Name)
			if name != "" {
				out[name] = struct{}{}
			}
		}
	}
	if pathItem != nil {
		add(pathItem.Parameters)
	}
	if operation != nil {
		add(operation.Parameters)
	}
	return out
}

func renderPathTemplate(path string) (string, []connectordefinitions.Field) {
	fields := []connectordefinitions.Field{}
	seen := map[string]struct{}{}
	rendered := pathParamPattern.ReplaceAllStringFunc(path, func(match string) string {
		raw := strings.Trim(match, "{}")
		key := normalizeID(raw)
		if key == "" {
			key = "path_value"
		}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			fields = append(fields, connectordefinitions.Field{
				Key:      key,
				Label:    titleFromID(key),
				Required: true,
				Help:     "Path parameter inferred from the OpenAPI operation.",
			})
		}
		return "${config." + key + "}"
	})
	return rendered, fields
}

func projectionTemplate(familyID, path string, operation *openapi3.Operation, properties map[string]*openapi3.SchemaRef) string {
	text := strings.ToLower(strings.Join(append([]string{familyID, path, operation.OperationID, operation.Summary}, operation.Tags...), " "))
	resourceText := strings.ToLower(strings.Join([]string{familyID, lastStaticSegment(path)}, " "))
	switch {
	case containsAny(text, "audit", "activity", "event", "log"):
		return "audit_event"
	case containsAny(resourceText, "membership", "member_user", "group_member", "team_member"):
		return "group_membership"
	case containsAny(resourceText, "user", "person", "people", "member", "account", "principal", "identity", "email"):
		return "identity_user"
	case containsAny(resourceText, "group", "team", "role", "organization", "workspace"):
		return "identity_group"
	case containsAny(text, "alert", "alarm", "notification", "incident", "pager", "siren"):
		return "alert"
	case containsAny(text, "finding", "vulnerability", "vuln", "issue", "risk", "detection", "threat"):
		return "finding"
	case containsAny(resourceText, "secret", "credential", "token", "password", "api_key", "apikey", "vault"):
		return "secret"
	case containsAny(text, "deployment", "deploy", "release", "build"):
		return "deployment"
	case containsAny(text, "policy", "compliance", "control", "rule", "standard", "framework", "baseline", "posture"):
		return "policy"
	case containsAny(text, "evidence", "case", "artifact"):
		return "evidence_cas_reference"
	case hasFindingShape(properties):
		return "finding"
	default:
		return "asset"
	}
}

func projectionSpec(template, familyID, idField, nameField string, properties map[string]*openapi3.SchemaRef) *connectordefinitions.ProjectionSpec {
	fields := map[string]string{}
	if idField != "" {
		fields["id"] = idField
	}
	if nameField != "" {
		fields["name"] = nameField
	}
	switch template {
	case "finding":
		fields["finding_id"] = firstNonEmpty(idField, "id")
		fields["title"] = firstNonEmpty(nameField, chooseField(properties, []string{"title", "summary", "name"}), idField)
		if severity := chooseField(properties, []string{"severity", "risk", "priority"}); severity != "" {
			fields["severity"] = severity
		}
		if status := chooseField(properties, []string{"status", "state", "resolution"}); status != "" {
			fields["status"] = status
		}
	case "asset":
		fields["resource_id"] = firstNonEmpty(idField, "id")
		fields["resource_name"] = firstNonEmpty(nameField, idField)
		fields["resource_type"] = familyID
	case "secret":
		fields["secret_id"] = firstNonEmpty(idField, "id")
		fields["secret_name"] = firstNonEmpty(nameField, idField)
		fields["secret_type"] = familyID
	case "policy":
		fields["policy_id"] = firstNonEmpty(idField, "id")
		fields["policy_name"] = firstNonEmpty(nameField, idField)
		fields["policy_type"] = familyID
	case "deployment":
		fields["deployment_id"] = firstNonEmpty(idField, "id")
		fields["deployment_name"] = firstNonEmpty(nameField, idField)
		fields["deployment_environment"] = chooseField(properties, []string{"environment", "env", "stage", "target"})
		fields["deployment_status"] = chooseField(properties, []string{"status", "state", "ready"})
	case "alert":
		fields["alert_id"] = firstNonEmpty(idField, "id")
		fields["alert_name"] = firstNonEmpty(nameField, chooseField(properties, []string{"title", "summary", "subject"}), idField)
		fields["alert_severity"] = chooseField(properties, []string{"severity", "priority", "level", "risk"})
		fields["alert_status"] = chooseField(properties, []string{"status", "state", "resolved"})
	case "evidence_cas_reference":
		fields["evidence_id"] = firstNonEmpty(idField, "id")
		fields["evidence_type"] = familyID
	default:
		fields["provider_id"] = firstNonEmpty(idField, "id")
	}
	return &connectordefinitions.ProjectionSpec{Template: template, Fields: fields}
}

func endpointScore(path string, operation *openapi3.Operation, selector, template string, configFields []connectordefinitions.Field) (int, []string) {
	score := 40
	reasons := []string{"GET list response"}
	text := strings.ToLower(strings.Join(append([]string{path, operation.OperationID, operation.Summary}, operation.Tags...), " "))
	if selector != "" {
		score += 20
		reasons = append(reasons, "array response")
	}
	if containsAny(text, "list", "search", "query", "all") {
		score += 15
		reasons = append(reasons, "list-like operation")
	}
	if !pathEndsWithParam(path) {
		score += 10
		reasons = append(reasons, "collection path")
	}
	if bonus := highValueBonus(template, familyIDFromPath(path), path); bonus > 0 {
		score += bonus
		reasons = append(reasons, "security graph projection")
	}
	if len(configFields) > 0 {
		score -= len(configFields) * 2
		reasons = append(reasons, "requires path config")
	}
	return score, reasons
}

func permissionsNeeded(doc *openapi3.T, operation *openapi3.Operation) []string {
	var requirements openapi3.SecurityRequirements
	if operation != nil && operation.Security != nil {
		requirements = *operation.Security
	} else if doc != nil {
		requirements = doc.Security
	}
	values := []string{}
	for _, requirement := range requirements {
		for scheme, scopes := range requirement {
			if len(scopes) == 0 {
				values = append(values, scheme)
				continue
			}
			values = append(values, scopes...)
		}
	}
	return normalizeStrings(values)
}

func sensitivePaths(properties map[string]*openapi3.SchemaRef) []string {
	values := []string{}
	for key := range properties {
		lower := strings.ToLower(key)
		if containsAny(lower, "secret", "token", "password", "private_key", "credential") {
			values = append(values, key)
		}
	}
	return normalizeStrings(values)
}

func mergeConfigFields(baseURLField *connectordefinitions.Field, candidates []candidate) []connectordefinitions.Field {
	fields := []connectordefinitions.Field{}
	seen := map[string]struct{}{}
	add := func(field connectordefinitions.Field) {
		field.Key = normalizeID(field.Key)
		if field.Key == "" {
			return
		}
		if _, ok := seen[field.Key]; ok {
			return
		}
		seen[field.Key] = struct{}{}
		fields = append(fields, field)
	}
	if baseURLField != nil {
		add(*baseURLField)
	}
	for _, candidate := range candidates {
		for _, field := range candidate.configFields {
			add(field)
		}
	}
	return fields
}

type pathItemPair struct {
	path string
	item *openapi3.PathItem
}

func sortedPathItems(doc *openapi3.T) []pathItemPair {
	if doc == nil || doc.Paths == nil {
		return nil
	}
	values := []pathItemPair{}
	for path, item := range doc.Paths.Map() {
		values = append(values, pathItemPair{path: path, item: item})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].path < values[j].path })
	return values
}

func sortedOperationMethods(operations map[string]*openapi3.Operation) []string {
	methods := make([]string, 0, len(operations))
	for method := range operations {
		methods = append(methods, strings.ToUpper(method))
	}
	sort.Strings(methods)
	return methods
}

type securitySchemePair struct {
	name   string
	scheme *openapi3.SecurityScheme
}

func sortedSecuritySchemes(doc *openapi3.T) []securitySchemePair {
	if doc == nil {
		return nil
	}
	values := []securitySchemePair{}
	for name, ref := range doc.Components.SecuritySchemes {
		if ref == nil || ref.Value == nil {
			continue
		}
		values = append(values, securitySchemePair{name: name, scheme: ref.Value})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].name < values[j].name })
	return values
}

func fieldKeys(fields []connectordefinitions.Field) []string {
	keys := make([]string, 0, len(fields))
	for _, field := range fields {
		keys = append(keys, field.Key)
	}
	return keys
}

func familyIDFromPath(path string) string {
	segment := singularize(lastStaticSegment(path))
	if segment == "" {
		return "resource"
	}
	return normalizeID(segment)
}

func lastStaticSegment(path string) string {
	segments := staticPathSegments(path)
	if len(segments) == 0 {
		return ""
	}
	return segments[len(segments)-1]
}

func staticPathSegments(path string) []string {
	parts := strings.Split(path, "/")
	segments := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "{") || strings.HasSuffix(part, "}") {
			continue
		}
		segments = append(segments, normalizeID(part))
	}
	return segments
}

func uniqueFamilyID(base string, segments []string, used map[string]struct{}) string {
	base = normalizeID(base)
	if base == "" {
		base = "resource"
	}
	if _, ok := used[base]; !ok {
		return base
	}
	for i := len(segments) - 2; i >= 0; i-- {
		candidate := normalizeID(segments[i] + "_" + base)
		if _, ok := used[candidate]; !ok {
			return candidate
		}
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s_%d", base, suffix)
		if _, ok := used[candidate]; !ok {
			return candidate
		}
	}
}

func eventKind(sourceID, familyID string) string {
	return normalizeEventPart(sourceID) + "." + normalizeEventPart(familyID)
}

func eventKindFromExisting(existing, familyID string) string {
	prefix, _, ok := strings.Cut(existing, ".")
	if !ok || prefix == "" {
		prefix = "openapi"
	}
	return prefix + "." + normalizeEventPart(familyID)
}

func schemaRefFromExisting(existing, familyID string) string {
	prefix, _, ok := strings.Cut(existing, "/")
	if !ok || prefix == "" {
		prefix = "openapi"
	}
	return prefix + "/" + familyID + "/v1"
}

func urnKindFromExisting(existing, familyID string) string {
	prefix, _, ok := strings.Cut(existing, "_")
	if !ok || prefix == "" {
		prefix = "openapi"
	}
	return prefix + "_" + familyID
}

func normalizeEventPart(value string) string {
	value = normalizeID(value)
	value = strings.ReplaceAll(value, "-", "_")
	if value == "" {
		return "openapi"
	}
	return value
}

func coverageID(template, familyID string) string {
	switch template {
	case "audit_event":
		return "audit_events"
	case "finding":
		return "findings"
	case "secret":
		return "secrets"
	case "policy":
		return "policies"
	case "deployment":
		return "deployments"
	case "alert":
		return "alerts"
	default:
		return familyID
	}
}

func coverageType(template string) string {
	switch template {
	case "audit_event":
		return "audit_event"
	case "finding":
		return "remediation_state"
	case "secret":
		return "entity_family"
	case "policy":
		return "lifecycle_state"
	case "deployment":
		return "deployment_state"
	case "alert":
		return "alert_state"
	default:
		return "entity_family"
	}
}

func isHighValue(template, familyID, path string) bool {
	return highValueBonus(template, familyID, path) > 0
}

func highValueBonus(template, familyID, path string) int {
	switch template {
	case "finding":
		return 35
	case "audit_event":
		return 30
	case "identity_user", "identity_group", "group_membership":
		return 25
	case "secret":
		return 25
	case "policy":
		return 20
	case "deployment":
		return 15
	case "alert":
		return 20
	}
	text := strings.ToLower(strings.Join([]string{familyID, path}, " "))
	if containsAny(text, "asset", "device", "endpoint", "repository", "repo", "permission", "role", "secret", "token", "key", "package", "dependency", "workflow", "runner", "hook", "installation", "organization") {
		return 10
	}
	return 0
}

func pathEndsWithParam(path string) bool {
	path = strings.TrimRight(path, "/")
	last := path[strings.LastIndex(path, "/")+1:]
	return strings.HasPrefix(last, "{") && strings.HasSuffix(last, "}")
}

func infoTitle(doc *openapi3.T) string {
	if doc == nil || doc.Info == nil {
		return ""
	}
	return doc.Info.Title
}

func infoDescription(doc *openapi3.T) string {
	if doc == nil || doc.Info == nil {
		return ""
	}
	return doc.Info.Description
}

func normalizeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return ""
	}
	if out[0] < 'a' || out[0] > 'z' {
		out = "x_" + out
	}
	return out
}

func titleFromID(value string) string {
	parts := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(value, "_", " "), "-", " "))
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, " ")
}

func singularize(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasSuffix(value, "ies") && len(value) > 3:
		return strings.TrimSuffix(value, "ies") + "y"
	case strings.HasSuffix(value, "ses"):
		return value
	case strings.HasSuffix(value, "s") && !strings.HasSuffix(value, "ss") && len(value) > 1:
		return strings.TrimSuffix(value, "s")
	default:
		return value
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func defaultIfEmpty(values []string, defaults []string) []string {
	if len(values) == 0 {
		return defaults
	}
	return values
}

func normalizeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedStringMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func hasAnyProperty(properties map[string]*openapi3.SchemaRef, names ...string) bool {
	lower := map[string]struct{}{}
	for key := range properties {
		lower[strings.ToLower(key)] = struct{}{}
	}
	for _, name := range names {
		if _, ok := lower[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}

func hasFindingShape(properties map[string]*openapi3.SchemaRef) bool {
	return hasAnyProperty(properties, "severity", "risk_score", "cvss", "cve", "finding_id") ||
		(hasAnyProperty(properties, "status", "state") && hasAnyProperty(properties, "resource_urn", "resource_id", "asset_id"))
}
