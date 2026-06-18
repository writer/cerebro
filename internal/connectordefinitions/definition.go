package connectordefinitions

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	RuntimeJSONAPI = "json_api"

	SchemaVersionIntegrationV1 = "cerebro.integration/v1"

	StageDraft     = "draft"
	StageSandbox   = "sandbox"
	StagePilot     = "pilot"
	StageApproved  = "approved"
	StageCertified = "certified"

	ValidationReady   = "ready"
	ValidationWarning = "warning"
	ValidationBlocked = "blocked"
)

var (
	ErrInvalidDefinition = errors.New("invalid connector definition")

	idPattern         = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	definitionIDRun   = regexp.MustCompile(`[^a-z0-9_-]+`)
	templateVar       = regexp.MustCompile(`\$\{([a-z]+)\.([a-z][a-z0-9_-]*)\}`)
	statusIdentifier  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	stageOrder        = []string{StageDraft, StageSandbox, StagePilot, StageApproved, StageCertified}
	supportedMethods  = map[string]struct{}{"GET": {}, "POST": {}}
	paginationTypes   = map[string]struct{}{"": {}, "none": {}, "cursor": {}, "page": {}, "offset": {}, "link": {}, "next_url": {}}
	incrementalStates = map[string]struct{}{"": {}, "high_watermark": {}, "opaque_cursor": {}}
	stageRank         = map[string]int{
		StageDraft:     0,
		StageSandbox:   1,
		StagePilot:     2,
		StageApproved:  3,
		StageCertified: 4,
	}
	authModels = map[string]struct{}{
		"none":                     {},
		"api_key":                  {},
		"bearer_token":             {},
		"basic":                    {},
		"oauth_authorization_code": {},
		"oauth_client_credentials": {},
		"two_step":                 {},
		"jwt":                      {},
		"signature":                {},
		"aws_sigv4":                {},
	}
)

// Definition is a versioned dynamic connector manifest that can be validated,
// tested, piloted, and later promoted into a built-in Source CDK implementation.
type Definition struct {
	SchemaVersion    string           `json:"schema_version,omitempty"`
	ID               string           `json:"id"`
	TenantID         string           `json:"tenant_id"`
	SourceID         string           `json:"source_id"`
	DisplayName      string           `json:"display_name"`
	Description      string           `json:"description,omitempty"`
	Categories       []string         `json:"categories,omitempty"`
	Runtime          string           `json:"runtime"`
	Stage            string           `json:"stage"`
	Maturity         string           `json:"maturity,omitempty"`
	CurrentVersion   int              `json:"current_version"`
	ConfigFields     []Field          `json:"config_fields,omitempty"`
	Auth             AuthSpec         `json:"auth"`
	Transport        *TransportSpec   `json:"transport,omitempty"`
	ResourceFamilies []ResourceFamily `json:"resource_families,omitempty"`
	ScopeOptions     []ScopeOption    `json:"scope_options,omitempty"`
	Validation       ValidationResult `json:"validation"`
	Promotion        PromotionState   `json:"promotion"`
	CreatedAt        string           `json:"created_at,omitempty"`
	UpdatedAt        string           `json:"updated_at,omitempty"`
}

// Field describes non-secret configuration or credential references required by a connector definition.
type Field struct {
	Key           string `json:"key"`
	Label         string `json:"label,omitempty"`
	Required      bool   `json:"required,omitempty"`
	Secret        bool   `json:"secret,omitempty"`
	ReferenceOnly bool   `json:"reference_only,omitempty"`
	Help          string `json:"help,omitempty"`
	Placeholder   string `json:"placeholder,omitempty"`
}

// AuthSpec describes the supported credential shape for a connector definition.
type AuthSpec struct {
	Model                         string            `json:"model"`
	CredentialFields              []Field           `json:"credential_fields,omitempty"`
	SupportedStoreIDs             []string          `json:"supported_store_ids,omitempty"`
	RequiresReferences            bool              `json:"requires_references,omitempty"`
	AuthorizationURL              string            `json:"authorization_url,omitempty"`
	TokenURL                      string            `json:"token_url,omitempty"`
	RefreshURL                    string            `json:"refresh_url,omitempty"`
	Scopes                        []string          `json:"scopes,omitempty"`
	ScopeSeparator                string            `json:"scope_separator,omitempty"`
	TokenRequestAuthMethod        string            `json:"token_request_auth_method,omitempty"`
	TokenParams                   map[string]string `json:"token_params,omitempty"`
	RefreshParams                 map[string]string `json:"refresh_params,omitempty"`
	PKCE                          string            `json:"pkce,omitempty"`
	TokenExpirationBufferSeconds  int               `json:"token_expiration_buffer_seconds,omitempty"`
	AlternateAccessTokenJSONPath  string            `json:"alternate_access_token_json_path,omitempty"`
	AlternateRefreshTokenJSONPath string            `json:"alternate_refresh_token_json_path,omitempty"`
}

// TransportSpec describes generic HTTP transport behavior shared across families.
type TransportSpec struct {
	BaseURL      string            `json:"base_url,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Query        map[string]string `json:"query,omitempty"`
	Body         map[string]any    `json:"body,omitempty"`
	Verification *VerificationSpec `json:"verification,omitempty"`
	Retry        *RetrySpec        `json:"retry,omitempty"`
}

// VerificationSpec describes the connection check request.
type VerificationSpec struct {
	Method       string            `json:"method,omitempty"`
	Path         string            `json:"path"`
	Headers      map[string]string `json:"headers,omitempty"`
	ExpectStatus []int             `json:"expect_status,omitempty"`
}

// RetrySpec describes provider retry and backoff behavior.
type RetrySpec struct {
	Statuses         []int  `json:"statuses,omitempty"`
	Backoff          string `json:"backoff,omitempty"`
	RetryAfterHeader string `json:"retry_after_header,omitempty"`
	MaxAttempts      int    `json:"max_attempts,omitempty"`
}

// PaginationSpec describes one supported pagination strategy.
type PaginationSpec struct {
	Type            string `json:"type,omitempty"`
	CursorParam     string `json:"cursor_param,omitempty"`
	CursorJSONPath  string `json:"cursor_json_path,omitempty"`
	PageParam       string `json:"page_param,omitempty"`
	PageSizeParam   string `json:"page_size_param,omitempty"`
	OffsetParam     string `json:"offset_param,omitempty"`
	LimitParam      string `json:"limit_param,omitempty"`
	LinkHeader      string `json:"link_header,omitempty"`
	NextURLJSONPath string `json:"next_url_json_path,omitempty"`
	StartPage       int    `json:"start_page,omitempty"`
	PageSize        int    `json:"page_size,omitempty"`
	InjectFirstPage bool   `json:"inject_first_page,omitempty"`
}

// IncrementalSpec describes durable state for changed-record reads.
type IncrementalSpec struct {
	CursorField string `json:"cursor_field,omitempty"`
	CursorPath  string `json:"cursor_path,omitempty"`
	RequestKey  string `json:"request_key,omitempty"`
	RequestIn   string `json:"request_in,omitempty"`
	State       string `json:"state,omitempty"`
}

// EventMappingSpec describes the event contract emitted for a resource family.
type EventMappingSpec struct {
	Kind                  string   `json:"kind,omitempty"`
	SchemaRef             string   `json:"schema_ref,omitempty"`
	URNKind               string   `json:"urn_kind,omitempty"`
	RequiredAttributes    []string `json:"required_attributes,omitempty"`
	RequiredPayloadFields []string `json:"required_payload_fields,omitempty"`
}

// ProjectionSpec describes a generic projector template for emitted events.
type ProjectionSpec struct {
	Template string            `json:"template,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// CoverageDimensionSpec mirrors sourcecdk coverage dimensions without coupling
// dynamic connector definitions to source package loading.
type CoverageDimensionSpec struct {
	ID                     string   `json:"id,omitempty"`
	Type                   string   `json:"type"`
	Title                  string   `json:"title,omitempty"`
	Families               []string `json:"families,omitempty"`
	Support                string   `json:"support"`
	HighValue              bool     `json:"high_value,omitempty"`
	KnownUnsupportedFields []string `json:"known_unsupported_fields,omitempty"`
	Notes                  []string `json:"notes,omitempty"`
}

// ResourceFamily describes one read-only resource collection exposed by the connector runtime.
type ResourceFamily struct {
	ID                    string                  `json:"id"`
	Label                 string                  `json:"label,omitempty"`
	Path                  string                  `json:"path"`
	Method                string                  `json:"method,omitempty"`
	RecordSelector        string                  `json:"record_selector,omitempty"`
	ListKey               string                  `json:"list_key,omitempty"`
	IDField               string                  `json:"id_field"`
	NameField             string                  `json:"name_field,omitempty"`
	UpdatedAtField        string                  `json:"updated_at_field,omitempty"`
	EventKind             string                  `json:"event_kind,omitempty"`
	Event                 EventMappingSpec        `json:"event,omitempty"`
	Pagination            *PaginationSpec         `json:"pagination,omitempty"`
	Incremental           *IncrementalSpec        `json:"incremental,omitempty"`
	Projection            *ProjectionSpec         `json:"projection,omitempty"`
	Coverage              []CoverageDimensionSpec `json:"coverage,omitempty"`
	PermissionsNeeded     []string                `json:"permissions_needed,omitempty"`
	SensitivePayloadPaths []string                `json:"sensitive_payload_paths,omitempty"`
	DefaultEnabled        bool                    `json:"default_enabled,omitempty"`
}

// ScopeOption exposes a resource family as a selectable scope option in the UI.
type ScopeOption struct {
	ID               string   `json:"id"`
	Label            string   `json:"label"`
	Families         []string `json:"families,omitempty"`
	DefaultEnabled   bool     `json:"default_enabled,omitempty"`
	PermissionNote   string   `json:"permission_note,omitempty"`
	NeedsUserReview  bool     `json:"needs_user_review,omitempty"`
	UnsupportedNotes []string `json:"unsupported_notes,omitempty"`
}

// ValidationResult describes the current readiness of a connector definition.
type ValidationResult struct {
	Status     string            `json:"status"`
	Summary    string            `json:"summary"`
	Checks     []ValidationCheck `json:"checks"`
	Generated  bool              `json:"generated,omitempty"`
	ObservedAt string            `json:"observed_at,omitempty"`
}

// ValidationCheck is one readiness gate.
type ValidationCheck struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail,omitempty"`
	NextAction string `json:"next_action,omitempty"`
	Blocking   bool   `json:"blocking,omitempty"`
}

// PromotionState describes the next safe lifecycle moves for a definition.
type PromotionState struct {
	EligibleStages []string `json:"eligible_stages,omitempty"`
	RequiredGates  []string `json:"required_gates,omitempty"`
	LastTarget     string   `json:"last_target,omitempty"`
	NextAction     string   `json:"next_action,omitempty"`
}

// PromotionRequest describes a lifecycle-stage promotion request.
type PromotionRequest struct {
	TargetStage string `json:"target_stage"`
	Reason      string `json:"reason,omitempty"`
}

// PromotionResult describes a completed lifecycle-stage promotion.
type PromotionResult struct {
	Definition Definition `json:"definition"`
	Promoted   bool       `json:"promoted"`
	Target     string     `json:"target_stage"`
	NextAction string     `json:"next_action"`
}

// Normalize fills defaults, trims strings, and recalculates validation and promotion metadata.
func Normalize(definition Definition) (Definition, error) {
	definition.SchemaVersion = strings.TrimSpace(definition.SchemaVersion)
	definition.TenantID = strings.TrimSpace(definition.TenantID)
	definition.SourceID = normalizeIdentifier(definition.SourceID)
	definition.ID = normalizeDefinitionID(definition.ID)
	if definition.ID == "" && definition.SourceID != "" && definition.TenantID != "" {
		definition.ID = defaultDefinitionID(definition.TenantID, definition.SourceID)
	}
	definition.DisplayName = strings.TrimSpace(definition.DisplayName)
	if definition.DisplayName == "" && definition.SourceID != "" {
		definition.DisplayName = titleFromID(definition.SourceID)
	}
	definition.Description = strings.TrimSpace(definition.Description)
	definition.Categories = normalizeStringList(definition.Categories)
	definition.Runtime = strings.TrimSpace(definition.Runtime)
	if definition.Runtime == "" {
		definition.Runtime = RuntimeJSONAPI
	}
	definition.Stage = strings.TrimSpace(definition.Stage)
	if definition.Stage == "" {
		definition.Stage = StageDraft
	}
	definition.Maturity = strings.TrimSpace(definition.Maturity)
	definition.Auth.Model = strings.TrimSpace(definition.Auth.Model)
	if definition.Auth.Model == "" {
		definition.Auth.Model = "bearer_token"
	}
	definition.Auth.AuthorizationURL = strings.TrimSpace(definition.Auth.AuthorizationURL)
	definition.Auth.TokenURL = strings.TrimSpace(definition.Auth.TokenURL)
	definition.Auth.RefreshURL = strings.TrimSpace(definition.Auth.RefreshURL)
	definition.Auth.ScopeSeparator = strings.TrimSpace(definition.Auth.ScopeSeparator)
	definition.Auth.TokenRequestAuthMethod = strings.TrimSpace(definition.Auth.TokenRequestAuthMethod)
	definition.Auth.PKCE = strings.TrimSpace(definition.Auth.PKCE)
	definition.Auth.AlternateAccessTokenJSONPath = strings.TrimSpace(definition.Auth.AlternateAccessTokenJSONPath)
	definition.Auth.AlternateRefreshTokenJSONPath = strings.TrimSpace(definition.Auth.AlternateRefreshTokenJSONPath)
	definition.Auth.Scopes = normalizeStringList(definition.Auth.Scopes)
	definition.Auth.TokenParams = normalizeStringMap(definition.Auth.TokenParams)
	definition.Auth.RefreshParams = normalizeStringMap(definition.Auth.RefreshParams)
	definition.Transport = normalizeTransportSpec(definition.Transport)
	definition.ConfigFields = normalizeFields(definition.ConfigFields)
	definition.Auth.CredentialFields = normalizeFields(definition.Auth.CredentialFields)
	definition.Auth.SupportedStoreIDs = normalizeStringList(definition.Auth.SupportedStoreIDs)
	definition.ResourceFamilies = normalizeResourceFamilies(definition.ResourceFamilies)
	definition.ScopeOptions = normalizeScopeOptions(definition.ScopeOptions, definition.ResourceFamilies)
	definition.Validation = Validate(definition)
	definition.Promotion = promotionState(definition)
	return definition, nil
}

// Validate evaluates the definition without contacting a third party.
func Validate(definition Definition) ValidationResult {
	checks := []ValidationCheck{}
	add := func(check ValidationCheck) {
		checks = append(checks, check)
	}
	if !idPattern.MatchString(strings.TrimSpace(definition.ID)) {
		add(blocking("id", "Definition ID", "Use lowercase letters, digits, hyphens, or underscores, starting with a letter."))
	} else {
		add(passing("id", "Definition ID", "Stable definition id is present."))
	}
	if !idPattern.MatchString(strings.TrimSpace(definition.SourceID)) {
		add(blocking("source_id", "Source ID", "Use a Source CDK-compatible lowercase source id."))
	} else {
		add(passing("source_id", "Source ID", "Source id can be promoted into a Source CDK module later."))
	}
	if strings.TrimSpace(definition.TenantID) == "" {
		add(blocking("tenant", "Tenant scope", "Dynamic connector definitions are tenant-local before certification."))
	} else {
		add(passing("tenant", "Tenant scope", "Definition is scoped to one tenant until certified."))
	}
	if definition.Runtime != RuntimeJSONAPI {
		add(blocking("runtime", "Runtime executor", fmt.Sprintf("Runtime %q is not supported yet; use %s.", definition.Runtime, RuntimeJSONAPI)))
	} else {
		add(passing("runtime", "Runtime executor", "Uses the safe declarative JSON API executor."))
	}
	if _, ok := stageRank[definition.Stage]; !ok {
		add(blocking("stage", "Lifecycle stage", "Use draft, sandbox, pilot, approved, or certified."))
	} else {
		add(passing("stage", "Lifecycle stage", "Lifecycle state is explicit."))
	}
	if definition.SchemaVersion != "" && definition.SchemaVersion != SchemaVersionIntegrationV1 {
		add(blocking("schema_version", "Schema version", fmt.Sprintf("Use %s for integration definitions.", SchemaVersionIntegrationV1)))
	}
	if _, ok := authModels[definition.Auth.Model]; !ok {
		add(blocking("auth", "Auth model", fmt.Sprintf("Auth model %q is not supported.", definition.Auth.Model)))
	} else if definition.Auth.Model != "none" && len(definition.Auth.CredentialFields) == 0 {
		add(blocking("auth_fields", "Credential fields", "Add reference-only credential fields for this auth model."))
	} else {
		add(passing("auth", "Auth model", "Credential shape is explicit and reference-aware."))
	}
	validateAuthModelDetails(definition.Auth, add)
	for _, field := range append(append([]Field{}, definition.ConfigFields...), definition.Auth.CredentialFields...) {
		if !idPattern.MatchString(field.Key) {
			add(blocking("field_"+field.Key, "Field keys", "Field keys must be lowercase identifiers."))
		}
		if field.Secret && !field.ReferenceOnly {
			add(blocking("secret_"+field.Key, "Secret boundary", "Secret fields must be reference-only in dynamic connector definitions."))
		}
	}
	validateTransport(definition.Transport, add)
	if len(definition.ResourceFamilies) == 0 {
		add(blocking("resources", "Resource families", "Add at least one read-only resource family."))
	} else {
		add(passing("resources", "Resource families", fmt.Sprintf("%d resource families are modeled.", len(definition.ResourceFamilies))))
	}
	for _, family := range definition.ResourceFamilies {
		if !idPattern.MatchString(family.ID) {
			add(blocking("family_"+family.ID, "Resource family ID", "Family ids must be lowercase identifiers."))
		}
		path := strings.TrimSpace(family.Path)
		if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") || strings.Contains(path, "://") {
			add(blocking("path_"+family.ID, "Resource path", "Resource paths must be relative API paths such as /v1/assets."))
		}
		if method := strings.ToUpper(strings.TrimSpace(family.Method)); method != "" {
			if _, ok := supportedMethods[method]; !ok {
				add(blocking("method_"+family.ID, "Read-only method", "Generic connector reads support GET and POST list/search endpoints."))
			}
		}
		if strings.TrimSpace(family.IDField) == "" {
			add(blocking("id_field_"+family.ID, "Resource identity", "Each resource family needs a stable id field."))
		}
		validateFamilyIntegrationFields(family, add)
	}
	status := ValidationReady
	for _, check := range checks {
		if check.Blocking {
			status = ValidationBlocked
			break
		}
		if check.Status == ValidationWarning {
			status = ValidationWarning
		}
	}
	summary := "Definition is ready for sandbox validation."
	switch status {
	case ValidationBlocked:
		summary = "Definition needs required fields before it can be promoted."
	case ValidationWarning:
		summary = "Definition can continue with user review."
	}
	sort.SliceStable(checks, func(i, j int) bool {
		if checks[i].Blocking != checks[j].Blocking {
			return checks[i].Blocking
		}
		return checks[i].ID < checks[j].ID
	})
	return ValidationResult{
		Status:     status,
		Summary:    summary,
		Checks:     checks,
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// Promote moves a definition to a later lifecycle stage after validation gates pass.
func Promote(definition Definition, request PromotionRequest) (PromotionResult, error) {
	normalized, err := Normalize(definition)
	if err != nil {
		return PromotionResult{}, err
	}
	target := strings.TrimSpace(request.TargetStage)
	if target == "" {
		target = nextStage(normalized.Stage)
	}
	if _, ok := stageRank[target]; !ok {
		return PromotionResult{}, fmt.Errorf("%w: unsupported target stage %q", ErrInvalidDefinition, request.TargetStage)
	}
	if stageRank[target] <= stageRank[normalized.Stage] {
		return PromotionResult{}, fmt.Errorf("%w: target stage must move the definition forward", ErrInvalidDefinition)
	}
	if stageRank[target]-stageRank[normalized.Stage] > 1 {
		return PromotionResult{}, fmt.Errorf("%w: promote one lifecycle stage at a time", ErrInvalidDefinition)
	}
	if normalized.Validation.Status == ValidationBlocked {
		return PromotionResult{
			Definition: normalized,
			Promoted:   false,
			Target:     target,
			NextAction: normalized.Validation.Summary,
		}, nil
	}
	normalized.Stage = target
	normalized.Validation = Validate(normalized)
	normalized.Promotion = promotionState(normalized)
	normalized.Promotion.LastTarget = target
	return PromotionResult{
		Definition: normalized,
		Promoted:   true,
		Target:     target,
		NextAction: normalized.Promotion.NextAction,
	}, nil
}

func promotionState(definition Definition) PromotionState {
	if definition.Validation.Status == ValidationBlocked {
		return PromotionState{
			RequiredGates: blockingGateIDs(definition.Validation.Checks),
			NextAction:    "Resolve blocking definition checks before promotion.",
		}
	}
	next := nextStage(definition.Stage)
	if next == "" {
		return PromotionState{
			NextAction: "Connector is certified. Code promotion can be requested through the hardened source path.",
		}
	}
	required := []string{"definition_validation"}
	if next == StagePilot {
		required = append(required, "sandbox_probe")
	}
	if next == StageApproved || next == StageCertified {
		required = append(required, "admin_review")
	}
	return PromotionState{
		EligibleStages: []string{next},
		RequiredGates:  required,
		NextAction:     "Promote to " + next + " when the listed gates are satisfied.",
	}
}

func nextStage(stage string) string {
	rank, ok := stageRank[strings.TrimSpace(stage)]
	if !ok || rank+1 >= len(stageOrder) {
		return ""
	}
	return stageOrder[rank+1]
}

func blockingGateIDs(checks []ValidationCheck) []string {
	gates := make([]string, 0, len(checks))
	for _, check := range checks {
		if check.Blocking {
			gates = append(gates, check.ID)
		}
	}
	sort.Strings(gates)
	return gates
}

func passing(id string, label string, detail string) ValidationCheck {
	return ValidationCheck{ID: id, Label: label, Status: ValidationReady, Severity: "info", Detail: detail}
}

func blocking(id string, label string, nextAction string) ValidationCheck {
	return ValidationCheck{ID: id, Label: label, Status: ValidationBlocked, Severity: "error", NextAction: nextAction, Blocking: true}
}

func validateAuthModelDetails(auth AuthSpec, add func(ValidationCheck)) {
	switch auth.Model {
	case "oauth_authorization_code":
		if auth.AuthorizationURL == "" {
			add(blocking("auth_authorization_url", "Authorization URL", "OAuth authorization-code providers require an authorization URL."))
		}
		if auth.TokenURL == "" {
			add(blocking("auth_token_url", "Token URL", "OAuth authorization-code providers require a token URL."))
		}
	case "oauth_client_credentials", "two_step":
		if auth.TokenURL == "" {
			add(blocking("auth_token_url", "Token URL", "Token-exchange auth models require a token URL."))
		}
	case "jwt":
		if !hasCredentialField(auth.CredentialFields, "private_key") && !hasCredentialField(auth.CredentialFields, "signing_key") {
			add(blocking("auth_jwt_key", "JWT signing key", "JWT auth requires a private_key or signing_key credential field."))
		}
	case "signature", "aws_sigv4":
		if len(auth.CredentialFields) == 0 {
			add(blocking("auth_signing_fields", "Signing credentials", "Signed request auth requires explicit credential fields."))
		}
	}
	if auth.TokenExpirationBufferSeconds < 0 {
		add(blocking("auth_token_expiration_buffer", "Token expiration buffer", "Token expiration buffer must not be negative."))
	}
}

func validateTransport(transport *TransportSpec, add func(ValidationCheck)) {
	if transport == nil {
		return
	}
	if transport.BaseURL != "" && !safeTemplate(transport.BaseURL, map[string]struct{}{"config": {}, "connection": {}, "credential": {}}) {
		add(blocking("transport_base_url", "Transport base URL", "Base URL templates may only reference config, connection, or credential fields."))
	}
	if strings.ContainsAny(transport.BaseURL, "\r\n\t\\") {
		add(blocking("transport_base_url_chars", "Transport base URL", "Base URL must not contain control characters or backslashes."))
	}
	if transport.Verification != nil {
		method := strings.ToUpper(strings.TrimSpace(transport.Verification.Method))
		if method == "" {
			method = "GET"
		}
		if _, ok := supportedMethods[method]; !ok {
			add(blocking("verification_method", "Verification method", "Verification supports GET and POST requests."))
		}
		if !validRelativePath(transport.Verification.Path) {
			add(blocking("verification_path", "Verification path", "Verification path must be a relative API path such as /v1/me."))
		}
		for _, status := range transport.Verification.ExpectStatus {
			if status < 100 || status > 599 {
				add(blocking("verification_status", "Verification status", "Expected HTTP statuses must be between 100 and 599."))
			}
		}
	}
	if transport.Retry != nil {
		for _, status := range transport.Retry.Statuses {
			if status < 100 || status > 599 {
				add(blocking("retry_status", "Retry status", "Retry HTTP statuses must be between 100 and 599."))
			}
		}
		if transport.Retry.MaxAttempts < 0 {
			add(blocking("retry_attempts", "Retry attempts", "Retry attempts must not be negative."))
		}
	}
}

func validateFamilyIntegrationFields(family ResourceFamily, add func(ValidationCheck)) {
	if family.Pagination != nil {
		if _, ok := paginationTypes[family.Pagination.Type]; !ok {
			add(blocking("pagination_"+family.ID, "Pagination", "Pagination type must be none, cursor, page, offset, link, or next_url."))
		}
		if family.Pagination.PageSize < 0 {
			add(blocking("pagination_page_size_"+family.ID, "Pagination page size", "Pagination page size must not be negative."))
		}
	}
	if family.Incremental != nil {
		if _, ok := incrementalStates[family.Incremental.State]; !ok {
			add(blocking("incremental_"+family.ID, "Incremental state", "Incremental state must be high_watermark or opaque_cursor."))
		}
		if strings.TrimSpace(family.Incremental.CursorField) == "" && strings.TrimSpace(family.Incremental.CursorPath) == "" {
			add(blocking("incremental_cursor_"+family.ID, "Incremental cursor", "Incremental sync needs a cursor field or cursor path."))
		}
	}
	if family.Event.Kind != "" && !validEventKind(family.Event.Kind) {
		add(blocking("event_kind_"+family.ID, "Event kind", "Event kinds must use dotted lowercase identifier syntax."))
	}
	if family.Event.SchemaRef != "" && strings.ContainsAny(family.Event.SchemaRef, "\r\n\t ") {
		add(blocking("schema_ref_"+family.ID, "Schema ref", "Schema refs must not contain whitespace."))
	}
	for _, dimension := range family.Coverage {
		if strings.TrimSpace(dimension.Type) == "" || strings.TrimSpace(dimension.Support) == "" {
			add(blocking("coverage_"+family.ID, "Coverage", "Coverage dimensions need type and support."))
		}
	}
}

func normalizeIdentifier(value string) string {
	return strings.Trim(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", "_")), "_-")
}

func normalizeDefinitionID(value string) string {
	return strings.Trim(definitionIDRun.ReplaceAllString(strings.ToLower(strings.TrimSpace(value)), "-"), "-_")
}

func defaultDefinitionID(tenantID string, sourceID string) string {
	tenant := normalizeDefinitionID(tenantID)
	if tenant == "" {
		return sourceID
	}
	id := tenant + "-" + sourceID
	if len(id) > 96 {
		return id[:96]
	}
	return id
}

func normalizeFields(fields []Field) []Field {
	normalized := make([]Field, 0, len(fields))
	seen := map[string]struct{}{}
	for _, field := range fields {
		field.Key = normalizeIdentifier(field.Key)
		if field.Key == "" {
			continue
		}
		if _, ok := seen[field.Key]; ok {
			continue
		}
		seen[field.Key] = struct{}{}
		field.Label = strings.TrimSpace(field.Label)
		field.Help = strings.TrimSpace(field.Help)
		field.Placeholder = strings.TrimSpace(field.Placeholder)
		normalized = append(normalized, field)
	}
	return normalized
}

func normalizeResourceFamilies(families []ResourceFamily) []ResourceFamily {
	normalized := make([]ResourceFamily, 0, len(families))
	seen := map[string]struct{}{}
	for _, family := range families {
		family.ID = normalizeIdentifier(family.ID)
		if family.ID == "" {
			continue
		}
		if _, ok := seen[family.ID]; ok {
			continue
		}
		seen[family.ID] = struct{}{}
		family.Label = strings.TrimSpace(family.Label)
		family.Path = strings.TrimSpace(family.Path)
		family.Method = strings.ToUpper(strings.TrimSpace(family.Method))
		if family.Method == "" {
			family.Method = "GET"
		}
		family.ListKey = strings.TrimSpace(family.ListKey)
		family.RecordSelector = strings.TrimSpace(family.RecordSelector)
		family.IDField = strings.TrimSpace(family.IDField)
		family.NameField = strings.TrimSpace(family.NameField)
		family.UpdatedAtField = strings.TrimSpace(family.UpdatedAtField)
		legacyEventKind := strings.TrimSpace(family.EventKind)
		family.EventKind = legacyEventKind
		if family.EventKind == "" {
			family.EventKind = family.ID
		}
		family.Event = normalizeEventMapping(legacyEventKind, family.Event)
		family.Pagination = normalizePaginationSpec(family.Pagination)
		family.Incremental = normalizeIncrementalSpec(family.Incremental)
		family.Projection = normalizeProjectionSpec(family.Projection)
		family.PermissionsNeeded = normalizeStringList(family.PermissionsNeeded)
		family.SensitivePayloadPaths = normalizeStringList(family.SensitivePayloadPaths)
		for i := range family.Coverage {
			family.Coverage[i] = normalizeCoverageDimensionSpec(family.ID, family.Coverage[i])
		}
		normalized = append(normalized, family)
	}
	return normalized
}

func normalizeTransportSpec(transport *TransportSpec) *TransportSpec {
	if transport == nil {
		return nil
	}
	next := *transport
	next.BaseURL = strings.TrimSpace(next.BaseURL)
	next.Headers = normalizeStringMap(next.Headers)
	next.Query = normalizeStringMap(next.Query)
	if next.Verification != nil {
		verification := *next.Verification
		verification.Method = strings.ToUpper(strings.TrimSpace(verification.Method))
		if verification.Method == "" {
			verification.Method = "GET"
		}
		verification.Path = strings.TrimSpace(verification.Path)
		verification.Headers = normalizeStringMap(verification.Headers)
		next.Verification = &verification
	}
	if next.Retry != nil {
		retry := *next.Retry
		retry.Backoff = strings.TrimSpace(retry.Backoff)
		retry.RetryAfterHeader = strings.TrimSpace(retry.RetryAfterHeader)
		next.Retry = &retry
	}
	return &next
}

func normalizePaginationSpec(pagination *PaginationSpec) *PaginationSpec {
	if pagination == nil {
		return nil
	}
	next := *pagination
	next.Type = strings.TrimSpace(next.Type)
	next.CursorParam = strings.TrimSpace(next.CursorParam)
	next.CursorJSONPath = strings.TrimSpace(next.CursorJSONPath)
	next.PageParam = strings.TrimSpace(next.PageParam)
	next.PageSizeParam = strings.TrimSpace(next.PageSizeParam)
	next.OffsetParam = strings.TrimSpace(next.OffsetParam)
	next.LimitParam = strings.TrimSpace(next.LimitParam)
	next.LinkHeader = strings.TrimSpace(next.LinkHeader)
	next.NextURLJSONPath = strings.TrimSpace(next.NextURLJSONPath)
	return &next
}

func normalizeIncrementalSpec(incremental *IncrementalSpec) *IncrementalSpec {
	if incremental == nil {
		return nil
	}
	next := *incremental
	next.CursorField = strings.TrimSpace(next.CursorField)
	next.CursorPath = strings.TrimSpace(next.CursorPath)
	next.RequestKey = strings.TrimSpace(next.RequestKey)
	next.RequestIn = strings.TrimSpace(next.RequestIn)
	next.State = strings.TrimSpace(next.State)
	if next.State == "" {
		next.State = "high_watermark"
	}
	return &next
}

func normalizeEventMapping(legacyKind string, event EventMappingSpec) EventMappingSpec {
	event.Kind = strings.TrimSpace(event.Kind)
	if event.Kind == "" && validEventKind(legacyKind) {
		event.Kind = strings.TrimSpace(legacyKind)
	}
	event.SchemaRef = strings.TrimSpace(event.SchemaRef)
	event.URNKind = strings.TrimSpace(event.URNKind)
	event.RequiredAttributes = normalizeStringList(event.RequiredAttributes)
	event.RequiredPayloadFields = normalizeStringList(event.RequiredPayloadFields)
	return event
}

func normalizeProjectionSpec(projection *ProjectionSpec) *ProjectionSpec {
	if projection == nil {
		return nil
	}
	next := *projection
	next.Template = normalizeIdentifier(next.Template)
	next.Fields = normalizeStringMap(next.Fields)
	return &next
}

func normalizeCoverageDimensionSpec(familyID string, dimension CoverageDimensionSpec) CoverageDimensionSpec {
	dimension.ID = normalizeIdentifier(dimension.ID)
	if dimension.ID == "" && strings.TrimSpace(dimension.Type) != "" {
		dimension.ID = normalizeIdentifier(familyID + "_" + strings.TrimSpace(dimension.Type))
	}
	dimension.Type = strings.TrimSpace(dimension.Type)
	dimension.Title = strings.TrimSpace(dimension.Title)
	dimension.Families = normalizeStringList(dimension.Families)
	if len(dimension.Families) == 0 && familyID != "" {
		dimension.Families = []string{familyID}
	}
	dimension.Support = strings.TrimSpace(dimension.Support)
	dimension.KnownUnsupportedFields = normalizeStringList(dimension.KnownUnsupportedFields)
	dimension.Notes = normalizeStringList(dimension.Notes)
	return dimension
}

func normalizeScopeOptions(options []ScopeOption, families []ResourceFamily) []ScopeOption {
	normalized := make([]ScopeOption, 0, len(options)+len(families))
	seen := map[string]struct{}{}
	for _, option := range options {
		option.ID = normalizeIdentifier(option.ID)
		if option.ID == "" {
			continue
		}
		if _, ok := seen[option.ID]; ok {
			continue
		}
		seen[option.ID] = struct{}{}
		option.Label = strings.TrimSpace(option.Label)
		option.Families = normalizeStringList(option.Families)
		option.PermissionNote = strings.TrimSpace(option.PermissionNote)
		option.UnsupportedNotes = normalizeStringList(option.UnsupportedNotes)
		normalized = append(normalized, option)
	}
	for _, family := range families {
		if _, ok := seen[family.ID]; ok {
			continue
		}
		seen[family.ID] = struct{}{}
		label := strings.TrimSpace(family.Label)
		if label == "" {
			label = titleFromID(family.ID)
		}
		normalized = append(normalized, ScopeOption{
			ID:             family.ID,
			Label:          label,
			Families:       []string{family.ID},
			DefaultEnabled: family.DefaultEnabled,
		})
	}
	return normalized
}

func normalizeStringList(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		normalized[key] = value
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func titleFromID(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool {
		return r == '_' || r == '-'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func hasCredentialField(fields []Field, key string) bool {
	for _, field := range fields {
		if field.Key == key {
			return true
		}
	}
	return false
}

func safeTemplate(value string, allowedScopes map[string]struct{}) bool {
	for _, match := range templateVar.FindAllStringSubmatch(value, -1) {
		if len(match) != 3 {
			return false
		}
		if _, ok := allowedScopes[match[1]]; !ok {
			return false
		}
	}
	return true
}

func validRelativePath(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.Contains(path, "\\") && !strings.Contains(path, "://")
}

func validEventKind(kind string) bool {
	parts := strings.Split(kind, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !statusIdentifier.MatchString(part) {
			return false
		}
	}
	return true
}
