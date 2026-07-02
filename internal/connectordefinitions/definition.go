package connectordefinitions

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
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

	IngestModePull    = "pull"
	IngestModeDeposit = "deposit"

	GateDefinitionValidation = "definition_validation"
	GateSandboxProbe         = "sandbox_probe"
	GateAdminReview          = "admin_review"
)

var (
	ErrInvalidDefinition = errors.New("invalid connector definition")

	idPattern           = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	entityTypePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	definitionIDRun     = regexp.MustCompile(`[^a-z0-9_-]+`)
	templateVar         = regexp.MustCompile(`\$\{([a-z]+)\.([a-z][a-z0-9_-]*)\}`)
	statusIdentifier    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	stageOrder          = []string{StageDraft, StageSandbox, StagePilot, StageApproved, StageCertified}
	supportedMethods    = map[string]struct{}{"GET": {}, "POST": {}}
	paginationTypes     = map[string]struct{}{"": {}, "none": {}, "cursor": {}, "page": {}, "offset": {}, "link": {}, "next_url": {}}
	incrementalStates   = map[string]struct{}{"": {}, "high_watermark": {}, "opaque_cursor": {}}
	ingestModes         = map[string]struct{}{IngestModePull: {}, IngestModeDeposit: {}}
	projectionRelations = map[string]struct{}{
		"attached_to": {},
		"belongs_to":  {},
		"contains":    {},
		"member_of":   {},
		"owned_by":    {},
	}
	unstableProjectionAttributes = map[string]struct{}{
		"created_at":      {},
		"cursor":          {},
		"event_id":        {},
		"idempotency_key": {},
		"last_seen_at":    {},
		"next_cursor":     {},
		"observed_at":     {},
		"page":            {},
		"page_token":      {},
		"pagination":      {},
		"request_id":      {},
		"run_id":          {},
		"source_event_id": {},
		"timestamp":       {},
		"updated_at":      {},
		"uuid":            {},
	}
	stageRank = map[string]int{
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
	ProviderAPI      *ProviderAPISpec `json:"provider_api,omitempty" yaml:"provider_api,omitempty"`
	Ingest           IngestSpec       `json:"ingest,omitempty"`
	ResourceFamilies []ResourceFamily `json:"resource_families,omitempty"`
	ScopeOptions     []ScopeOption    `json:"scope_options,omitempty"`
	Validation       ValidationResult `json:"validation"`
	Promotion        PromotionState   `json:"promotion"`
	CreatedAt        string           `json:"created_at,omitempty"`
	UpdatedAt        string           `json:"updated_at,omitempty"`
}

// IngestSpec selects the transport direction for a dynamic connector definition.
type IngestSpec struct {
	Mode    string             `json:"mode,omitempty"`
	Deposit *DepositIngestSpec `json:"deposit,omitempty"`
}

// DepositIngestSpec describes customer-pushed records accepted for unreachable data.
type DepositIngestSpec struct {
	ResourceFamilies []string `json:"resource_families,omitempty"`
	FullStateSync    bool     `json:"full_state_sync,omitempty"`
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
	TokenHeader                   string            `json:"token_header,omitempty"`
	TokenScheme                   string            `json:"token_scheme,omitempty"`
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

// ProviderAPISpec records the provider-owned API source that backs a generated
// or promoted connector definition.
type ProviderAPISpec struct {
	Status     string                  `json:"status,omitempty" yaml:"status,omitempty"`
	Transport  string                  `json:"transport,omitempty" yaml:"transport,omitempty"`
	Auth       string                  `json:"auth,omitempty" yaml:"auth,omitempty"`
	BaseURL    string                  `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	Endpoint   string                  `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	References []string                `json:"references,omitempty" yaml:"references,omitempty"`
	Families   []ProviderAPIFamilySpec `json:"families,omitempty" yaml:"families,omitempty"`
}

// ProviderAPIFamilySpec maps one runtime family to a documented provider API
// path or operation.
type ProviderAPIFamilySpec struct {
	ID        string `json:"id,omitempty" yaml:"id,omitempty"`
	Method    string `json:"method,omitempty" yaml:"method,omitempty"`
	Path      string `json:"path,omitempty" yaml:"path,omitempty"`
	Operation string `json:"operation,omitempty" yaml:"operation,omitempty"`
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
	Type            string   `json:"type,omitempty"`
	CursorParam     string   `json:"cursor_param,omitempty"`
	CursorJSONPath  string   `json:"cursor_json_path,omitempty"`
	PageParam       string   `json:"page_param,omitempty"`
	PageSizeParam   string   `json:"page_size_param,omitempty"`
	OffsetParam     string   `json:"offset_param,omitempty"`
	LimitParam      string   `json:"limit_param,omitempty"`
	LinkHeader      string   `json:"link_header,omitempty"`
	NextURLJSONPath string   `json:"next_url_json_path,omitempty"`
	NextCursorKeys  []string `json:"next_cursor_keys,omitempty"`
	HasMoreKey      string   `json:"has_more_key,omitempty"`
	StartPage       int      `json:"start_page,omitempty"`
	PageSize        int      `json:"page_size,omitempty"`
	InjectFirstPage bool     `json:"inject_first_page,omitempty"`
	DisablePageSize bool     `json:"disable_page_size,omitempty"`
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
	Template      string                       `json:"template,omitempty"`
	Fields        map[string]string            `json:"fields,omitempty"`
	Entity        *ProjectionEntitySpec        `json:"entity,omitempty"`
	Relationships []ProjectionRelationshipSpec `json:"relationships,omitempty"`
}

// ProjectionEntitySpec describes how a projected entity URN is built from
// already-emitted event attributes.
type ProjectionEntitySpec struct {
	EntityType     string   `json:"entity_type,omitempty"`
	URNKind        string   `json:"urn_kind,omitempty"`
	IDAttributes   []string `json:"id_attributes,omitempty"`
	LabelAttribute string   `json:"label_attribute,omitempty"`
}

// ProjectionRelationshipSpec describes one declarative graph edge emitted from
// already-emitted event attributes.
type ProjectionRelationshipSpec struct {
	Relation           string                `json:"relation"`
	From               *ProjectionEntitySpec `json:"from,omitempty"`
	To                 ProjectionEntitySpec  `json:"to"`
	RequiredAttributes []string              `json:"required_attributes,omitempty"`
	LinkAttributes     []string              `json:"link_attributes,omitempty"`
	MatchType          string                `json:"match_type,omitempty"`
}

// CoverageDimensionSpec mirrors sourcecdk coverage dimensions without coupling
// dynamic connector definitions to source package loading.
type CoverageDimensionSpec struct {
	ID                     string                   `json:"id,omitempty"`
	Type                   string                   `json:"type"`
	Title                  string                   `json:"title,omitempty"`
	Families               []string                 `json:"families,omitempty"`
	Support                string                   `json:"support"`
	HighValue              bool                     `json:"high_value,omitempty"`
	KnownUnsupportedFields []string                 `json:"known_unsupported_fields,omitempty"`
	Notes                  []string                 `json:"notes,omitempty"`
	EvidenceTypes          []string                 `json:"evidence_types,omitempty"`
	ControlDomains         []string                 `json:"control_domains,omitempty"`
	ControlRefs            []CoverageControlRefSpec `json:"control_refs,omitempty"`
}

// CoverageControlRefSpec connects declarative connector coverage to compliance
// controls while keeping connector definitions independent from compliance.
type CoverageControlRefSpec struct {
	FrameworkID   string `json:"framework_id,omitempty"`
	FrameworkName string `json:"framework_name,omitempty"`
	ControlID     string `json:"control_id"`
}

// ResourceFamily describes one read-only resource collection exposed by the connector runtime.
type ResourceFamily struct {
	ID                    string                  `json:"id"`
	Label                 string                  `json:"label,omitempty"`
	Path                  string                  `json:"path"`
	Method                string                  `json:"method,omitempty"`
	RecordSelector        string                  `json:"record_selector,omitempty"`
	ListKey               string                  `json:"list_key,omitempty"`
	Read                  *ResourceReadSpec       `json:"read,omitempty"`
	Singleton             bool                    `json:"singleton,omitempty"`
	IDField               string                  `json:"id_field"`
	NameField             string                  `json:"name_field,omitempty"`
	UpdatedAtField        string                  `json:"updated_at_field,omitempty"`
	EventKind             string                  `json:"event_kind,omitempty"`
	Event                 EventMappingSpec        `json:"event,omitempty"`
	StaticQuery           map[string]string       `json:"static_query,omitempty"`
	StaticHeaders         map[string]string       `json:"static_headers,omitempty"`
	ConfigQuery           map[string]string       `json:"config_query,omitempty"`
	Pagination            *PaginationSpec         `json:"pagination,omitempty"`
	Incremental           *IncrementalSpec        `json:"incremental,omitempty"`
	Config                *FamilyConfigSpec       `json:"config,omitempty"`
	Projection            *ProjectionSpec         `json:"projection,omitempty"`
	Coverage              []CoverageDimensionSpec `json:"coverage,omitempty"`
	PermissionsNeeded     []string                `json:"permissions_needed,omitempty"`
	SensitivePayloadPaths []string                `json:"sensitive_payload_paths,omitempty"`
	DefaultEnabled        bool                    `json:"default_enabled,omitempty"`
}

// ResourceReadSpec extends the generic JSON API read shape without adding bespoke code.
type ResourceReadSpec struct {
	DetailPath            string            `json:"detail_path,omitempty"`
	AllowBareDetailRecord bool              `json:"allow_bare_detail_record,omitempty"`
	PathParams            []string          `json:"path_params,omitempty"`
	MapRecords            map[string]string `json:"map_records,omitempty"`
	Singleton             bool              `json:"singleton,omitempty"`
	DisablePageSize       bool              `json:"disable_page_size,omitempty"`
}

// FamilyConfigSpec binds static and runtime config values into a resource-family request.
type FamilyConfigSpec struct {
	BaseURL          string            `json:"base_url,omitempty"`
	StaticQuery      map[string]string `json:"static_query,omitempty"`
	ConfigQuery      map[string]string `json:"config_query,omitempty"`
	ConfigAttributes map[string]string `json:"config_attributes,omitempty"`
	IdentityKeys     []string          `json:"identity_keys,omitempty"`
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

// GateEvidence attests that a promotion gate was satisfied before a stage move.
type GateEvidence struct {
	Gate       string `json:"gate"`
	Actor      string `json:"actor,omitempty"`
	Detail     string `json:"detail,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
}

// PromotionRequest describes a lifecycle-stage promotion request.
type PromotionRequest struct {
	TargetStage  string         `json:"target_stage"`
	Reason       string         `json:"reason,omitempty"`
	GateEvidence []GateEvidence `json:"gate_evidence,omitempty"`
}

// PromotionResult describes a completed lifecycle-stage promotion.
type PromotionResult struct {
	Definition    Definition     `json:"definition"`
	Promoted      bool           `json:"promoted"`
	Target        string         `json:"target_stage"`
	NextAction    string         `json:"next_action"`
	AcceptedGates []GateEvidence `json:"accepted_gates,omitempty"`
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
	definition.Auth.TokenHeader = strings.TrimSpace(definition.Auth.TokenHeader)
	definition.Auth.TokenScheme = strings.TrimSpace(definition.Auth.TokenScheme)
	definition.Auth.AlternateAccessTokenJSONPath = strings.TrimSpace(definition.Auth.AlternateAccessTokenJSONPath)
	definition.Auth.AlternateRefreshTokenJSONPath = strings.TrimSpace(definition.Auth.AlternateRefreshTokenJSONPath)
	definition.Auth.Scopes = normalizeStringList(definition.Auth.Scopes)
	definition.Auth.TokenParams = normalizeStringMap(definition.Auth.TokenParams)
	definition.Auth.RefreshParams = normalizeStringMap(definition.Auth.RefreshParams)
	definition.Transport = normalizeTransportSpec(definition.Transport)
	definition.ProviderAPI = normalizeProviderAPISpec(definition.ProviderAPI)
	definition.Ingest = normalizeIngestSpec(definition.Ingest)
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
	validateIngest(definition, add)
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
		depositFamily := isDepositResourceFamily(definition, family.ID)
		if !depositFamily && (path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") || strings.Contains(path, "://") || strings.ContainsAny(path, "?#")) {
			add(blocking("path_"+family.ID, "Resource path", "Resource paths must be relative API paths without query or fragment such as /v1/assets."))
		}
		if depositFamily && path != "" && (!strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") || strings.Contains(path, "://") || strings.ContainsAny(path, "?#")) {
			add(blocking("path_"+family.ID, "Resource path", "Deposit resource paths may be omitted; when present they must be relative API paths without query or fragment."))
		}
		if method := strings.ToUpper(strings.TrimSpace(family.Method)); method != "" {
			if _, ok := supportedMethods[method]; !ok {
				add(blocking("method_"+family.ID, "Read-only method", "Generic connector reads support GET and POST list/search endpoints."))
			}
		}
		if strings.TrimSpace(family.IDField) == "" {
			add(blocking("id_field_"+family.ID, "Resource identity", "Each resource family needs a stable id field."))
		}
		familyBaseURL := ""
		if family.Config != nil {
			familyBaseURL = family.Config.BaseURL
		}
		if familyBaseURL != "" && !safeTemplate(familyBaseURL, map[string]struct{}{"config": {}, "connection": {}, "credential": {}}) {
			add(blocking("base_url_"+family.ID, "Resource base URL", "Resource family base URL templates may only reference config, connection, or credential fields."))
		}
		if strings.ContainsAny(familyBaseURL, "\r\n\t\\") {
			add(blocking("base_url_chars_"+family.ID, "Resource base URL", "Resource family base URL must not contain control characters or backslashes."))
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
	accepted, missing := acceptGateEvidence(evidenceGatesForStage(target), request.GateEvidence)
	if len(missing) > 0 {
		return PromotionResult{
			Definition:    normalized,
			Promoted:      false,
			Target:        target,
			NextAction:    fmt.Sprintf("Provide %s gate evidence before promoting to %s.", strings.Join(missing, ", "), target),
			AcceptedGates: accepted,
		}, nil
	}
	normalized.Stage = target
	normalized.Validation = Validate(normalized)
	normalized.Promotion = promotionState(normalized)
	normalized.Promotion.LastTarget = target
	return PromotionResult{
		Definition:    normalized,
		Promoted:      true,
		Target:        target,
		NextAction:    normalized.Promotion.NextAction,
		AcceptedGates: accepted,
	}, nil
}

// evidenceGatesForStage lists the human-attested gates required before a target stage.
func evidenceGatesForStage(target string) []string {
	switch target {
	case StagePilot:
		return []string{GateSandboxProbe}
	case StageApproved, StageCertified:
		return []string{GateAdminReview}
	default:
		return nil
	}
}

// acceptGateEvidence matches provided evidence against required gates, returning the
// normalized accepted evidence and any still-missing gate IDs.
func acceptGateEvidence(required []string, provided []GateEvidence) ([]GateEvidence, []string) {
	supplied := make(map[string]GateEvidence, len(provided))
	for _, evidence := range provided {
		gate := strings.TrimSpace(evidence.Gate)
		actor := strings.TrimSpace(evidence.Actor)
		if gate == "" || actor == "" {
			continue
		}
		normalized := GateEvidence{
			Gate:       gate,
			Actor:      actor,
			Detail:     strings.TrimSpace(evidence.Detail),
			ObservedAt: strings.TrimSpace(evidence.ObservedAt),
		}
		if normalized.ObservedAt == "" {
			normalized.ObservedAt = time.Now().UTC().Format(time.RFC3339)
		}
		supplied[gate] = normalized
	}
	accepted := make([]GateEvidence, 0, len(required))
	var missing []string
	for _, gate := range required {
		if evidence, ok := supplied[gate]; ok {
			accepted = append(accepted, evidence)
			continue
		}
		missing = append(missing, gate)
	}
	return accepted, missing
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
	required := []string{GateDefinitionValidation}
	required = append(required, evidenceGatesForStage(next)...)
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
	if header := strings.TrimSpace(auth.TokenHeader); header != "" && strings.ContainsAny(header, "\r\n\t :") {
		add(blocking("auth_token_header", "Token header", "Token header must be an HTTP header name such as Authorization or x-api-key."))
	}
	if scheme := strings.TrimSpace(auth.TokenScheme); scheme != "" && strings.ContainsAny(scheme, "\r\n\t") {
		add(blocking("auth_token_scheme", "Token scheme", "Token scheme must not contain whitespace or control characters."))
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

func validateIngest(definition Definition, add func(ValidationCheck)) {
	mode := strings.TrimSpace(definition.Ingest.Mode)
	if mode == "" {
		mode = IngestModePull
	}
	if _, ok := ingestModes[mode]; !ok {
		add(blocking("ingest_mode", "Ingest mode", "Ingest mode must be pull or deposit."))
		return
	}
	if mode == IngestModePull {
		add(passing("ingest_mode", "Ingest mode", "Cerebro pulls records from the provider with the declarative runtime."))
		return
	}
	add(passing("ingest_mode", "Ingest mode", "Connector accepts deposit records through a typed, connector-scoped ingest surface."))
	if definition.Ingest.Deposit == nil || len(definition.Ingest.Deposit.ResourceFamilies) == 0 {
		return
	}
	families := map[string]struct{}{}
	for _, family := range definition.ResourceFamilies {
		families[strings.TrimSpace(family.ID)] = struct{}{}
	}
	for _, familyID := range definition.Ingest.Deposit.ResourceFamilies {
		if _, ok := families[strings.TrimSpace(familyID)]; !ok {
			add(blocking("ingest_deposit_family_"+familyID, "Deposit family", "Deposit resource families must reference a modeled resource family."))
		}
	}
}

func isDepositResourceFamily(definition Definition, familyID string) bool {
	if strings.TrimSpace(definition.Ingest.Mode) != IngestModeDeposit {
		return false
	}
	if definition.Ingest.Deposit == nil || len(definition.Ingest.Deposit.ResourceFamilies) == 0 {
		return true
	}
	familyID = strings.TrimSpace(familyID)
	for _, candidate := range definition.Ingest.Deposit.ResourceFamilies {
		if strings.TrimSpace(candidate) == familyID {
			return true
		}
	}
	return false
}

func validateFamilyIntegrationFields(family ResourceFamily, add func(ValidationCheck)) {
	if family.Read != nil {
		if strings.TrimSpace(family.Read.DetailPath) != "" && !validRelativePath(family.Read.DetailPath) {
			add(blocking("detail_path_"+family.ID, "Detail path", "Detail paths must be relative API paths such as /v1/assets/{id}."))
		}
		for _, param := range family.Read.PathParams {
			if !idPattern.MatchString(strings.TrimSpace(param)) {
				add(blocking("path_param_"+family.ID+"_"+normalizeDefinitionID(param), "Path parameter", "Path parameters must be lowercase identifiers."))
			}
		}
		for key, value := range family.Read.MapRecords {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				add(blocking("map_records_"+family.ID, "Map records", "Map record bindings require non-empty source object and value keys."))
			}
		}
	}
	if family.Config != nil {
		validateFamilyConfigMap(family.ID, "static_query", family.Config.StaticQuery, add)
		validateFamilyConfigMap(family.ID, "config_query", family.Config.ConfigQuery, add)
		validateFamilyConfigMap(family.ID, "config_attributes", family.Config.ConfigAttributes, add)
		for _, key := range family.Config.IdentityKeys {
			if strings.TrimSpace(key) == "" {
				add(blocking("identity_keys_"+family.ID, "Identity keys", "Identity keys must not contain empty values."))
			}
		}
	}
	validateFamilyConfigMap(family.ID, "static_headers", family.StaticHeaders, add)
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
	validateProjectionIntegrationFields(family, add)
	for _, dimension := range family.Coverage {
		if strings.TrimSpace(dimension.Type) == "" || strings.TrimSpace(dimension.Support) == "" {
			add(blocking("coverage_"+family.ID, "Coverage", "Coverage dimensions need type and support."))
		}
		for _, ref := range dimension.ControlRefs {
			if strings.TrimSpace(ref.ControlID) == "" || (strings.TrimSpace(ref.FrameworkID) == "" && strings.TrimSpace(ref.FrameworkName) == "") {
				add(blocking("coverage_control_refs_"+family.ID, "Coverage control refs", "Coverage control refs require framework_name or framework_id and control_id."))
			}
		}
	}
}

func validateFamilyConfigMap(familyID string, name string, values map[string]string, add func(ValidationCheck)) {
	for key, value := range values {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			add(blocking(name+"_"+familyID, "Family config", "Family config bindings require non-empty keys and values."))
		}
	}
}

func validateProjectionIntegrationFields(family ResourceFamily, add func(ValidationCheck)) {
	if family.Projection == nil {
		return
	}
	projection := family.Projection
	attributes := knownProjectionAttributes(family)
	if projection.Entity != nil {
		validateProjectionEntity(family.ID, "projection_entity", *projection.Entity, add)
		validateProjectionAttributeRefs(family.ID, "projection_entity", projection.Entity.IDAttributes, attributes, add)
		if projection.Entity.LabelAttribute != "" {
			validateProjectionAttributeRefs(family.ID, "projection_entity_label", []string{projection.Entity.LabelAttribute}, attributes, add)
		}
	}
	if len(projection.Relationships) == 0 {
		return
	}
	if strings.ReplaceAll(projection.Template, "-", "_") == "audit_event" {
		add(blocking("projection_relationships_"+family.ID, "Projection relationships", "Audit event families cannot emit durable graph relationships in v1."))
	}
	if len(projection.Relationships) > 8 {
		add(blocking("projection_relationships_"+family.ID, "Projection relationships", "Projection relationships are capped at eight per family."))
	}
	for i, relationship := range projection.Relationships {
		id := fmt.Sprintf("projection_relationship_%s_%d", family.ID, i)
		if _, ok := projectionRelations[relationship.Relation]; !ok {
			add(blocking(id+"_relation", "Projection relationship", "Use one of belongs_to, contains, owned_by, member_of, or attached_to."))
		}
		if strings.TrimSpace(relationship.MatchType) == "" {
			add(blocking(id+"_match_type", "Projection relationship match type", "Add a stable match_type explaining the relationship source."))
		}
		if relationship.From != nil {
			validateProjectionEntity(family.ID, id+"_from", *relationship.From, add)
			validateProjectionAttributeRefs(family.ID, id+"_from", relationship.From.IDAttributes, attributes, add)
			if relationship.From.LabelAttribute != "" {
				validateProjectionAttributeRefs(family.ID, id+"_from_label", []string{relationship.From.LabelAttribute}, attributes, add)
			}
		}
		validateProjectionEntity(family.ID, id+"_to", relationship.To, add)
		validateProjectionAttributeRefs(family.ID, id+"_to", relationship.To.IDAttributes, attributes, add)
		if relationship.To.LabelAttribute != "" {
			validateProjectionAttributeRefs(family.ID, id+"_to_label", []string{relationship.To.LabelAttribute}, attributes, add)
		}
		validateProjectionAttributeRefs(family.ID, id+"_required", relationship.RequiredAttributes, attributes, add)
		validateProjectionAttributeRefs(family.ID, id+"_link", relationship.LinkAttributes, attributes, add)
	}
}

func validateProjectionEntity(familyID string, id string, entity ProjectionEntitySpec, add func(ValidationCheck)) {
	if !entityTypePattern.MatchString(strings.TrimSpace(entity.EntityType)) {
		add(blocking(id+"_"+familyID+"_entity_type", "Projection entity type", "Projection entity_type must use dotted lowercase identifier syntax."))
	}
	if !idPattern.MatchString(strings.TrimSpace(entity.URNKind)) {
		add(blocking(id+"_"+familyID+"_urn_kind", "Projection URN kind", "Projection urn_kind must be a lowercase identifier."))
	}
	if len(entity.IDAttributes) == 0 {
		add(blocking(id+"_"+familyID+"_id_attributes", "Projection entity identity", "Projection entities need at least one id_attribute."))
	}
}

func validateProjectionAttributeRefs(familyID string, id string, refs []string, known map[string]struct{}, add func(ValidationCheck)) {
	for _, ref := range refs {
		attr := strings.TrimSpace(ref)
		if attr == "" {
			continue
		}
		if unstableProjectionAttribute(attr) {
			add(blocking(id+"_"+familyID+"_unstable_"+normalizeDefinitionID(attr), "Projection attribute stability", "Projection relationships cannot use event IDs, timestamps, cursors, request IDs, run IDs, or other ephemeral anchors."))
			continue
		}
		if _, ok := known[attr]; !ok {
			add(blocking(id+"_"+familyID+"_attribute_"+normalizeDefinitionID(attr), "Projection attribute", "Projection relationship attributes must be emitted by projection.fields, event.required_attributes, or known template defaults."))
		}
	}
}

func unstableProjectionAttribute(attribute string) bool {
	normalized := canonicalProjectionAttribute(attribute)
	if _, ok := unstableProjectionAttributes[normalized]; ok {
		return true
	}
	return strings.HasSuffix(normalized, "_timestamp") || strings.HasSuffix(normalized, "_cursor") || strings.HasSuffix(normalized, "_request_id") || strings.HasSuffix(normalized, "_run_id")
}

func canonicalProjectionAttribute(attribute string) string {
	var b strings.Builder
	lastUnderscore := true
	lastUpper := false
	for _, r := range strings.TrimSpace(attribute) {
		switch {
		case r == '.' || r == '-' || unicode.IsSpace(r):
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
				lastUpper = false
			}
		case unicode.IsUpper(r):
			if b.Len() > 0 && !lastUnderscore && !lastUpper {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			lastUnderscore = false
			lastUpper = true
		default:
			b.WriteRune(unicode.ToLower(r))
			lastUnderscore = r == '_'
			lastUpper = false
		}
	}
	return strings.Trim(b.String(), "_")
}

func knownProjectionAttributes(family ResourceFamily) map[string]struct{} {
	known := map[string]struct{}{
		"external_id":     {},
		"family":          {},
		"observed_at":     {},
		"provider":        {},
		"resource_id":     {},
		"resource_name":   {},
		"resource_type":   {},
		"resource_urn":    {},
		"source_provider": {},
	}
	addKnown := func(values ...string) {
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				known[value] = struct{}{}
			}
		}
	}
	addKnown(family.Event.RequiredAttributes...)
	addKnown(family.IDField, family.NameField, family.UpdatedAtField)
	if family.Read != nil {
		addKnown(family.Read.PathParams...)
	}
	if family.Config != nil {
		for key := range family.Config.ConfigAttributes {
			addKnown(key)
		}
		addKnown(family.Config.IdentityKeys...)
	}
	switch strings.TrimSpace(family.Projection.Template) {
	case "finding", "vulnerability":
		addKnown("finding_id", "severity", "status", "title", "description")
	case "identity_user":
		addKnown("user_id", "email", "display_name", "status")
	case "identity_group":
		addKnown("group_id", "group_email", "group_name")
	case "group_membership":
		addKnown("group_id", "member_id", "member_email")
	case "audit_event":
		addKnown("event_type", "actor_id", "actor_email")
	case "secret":
		addKnown("secret_id", "secret_name", "secret_type", "secret_status", "secret_rotation_enabled", "secret_last_rotated_at")
	case "policy":
		addKnown("policy_id", "policy_name", "policy_type", "policy_status", "policy_severity")
	case "deployment":
		addKnown("deployment_id", "deployment_name", "deployment_environment", "deployment_status", "deployment_url", "deployment_commit_sha", "deployment_branch")
	case "alert":
		addKnown("alert_id", "alert_name", "alert_severity", "alert_status", "alert_type", "alert_source", "alert_fired_at", "alert_resolved_at")
	}
	if family.Projection != nil {
		for key := range family.Projection.Fields {
			addKnown(key)
		}
	}
	return known
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
		family.Read = normalizeResourceReadSpec(family.Read)
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
		family.StaticQuery = normalizeStringMap(family.StaticQuery)
		family.StaticHeaders = normalizeStringMap(family.StaticHeaders)
		family.ConfigQuery = normalizeStringMap(family.ConfigQuery)
		family.Pagination = normalizePaginationSpec(family.Pagination)
		family.Incremental = normalizeIncrementalSpec(family.Incremental)
		family.Config = normalizeFamilyConfigSpec(family.Config)
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

func normalizeProviderAPISpec(api *ProviderAPISpec) *ProviderAPISpec {
	if api == nil {
		return nil
	}
	next := *api
	next.Status = strings.TrimSpace(next.Status)
	next.Transport = strings.TrimSpace(next.Transport)
	next.Auth = strings.TrimSpace(next.Auth)
	next.BaseURL = strings.TrimSpace(next.BaseURL)
	next.Endpoint = strings.TrimSpace(next.Endpoint)
	next.References = normalizeStringList(next.References)
	families := make([]ProviderAPIFamilySpec, 0, len(next.Families))
	seen := map[string]struct{}{}
	for _, family := range next.Families {
		family.ID = normalizeIdentifier(family.ID)
		family.Method = strings.ToUpper(strings.TrimSpace(family.Method))
		family.Path = strings.TrimSpace(family.Path)
		family.Operation = strings.TrimSpace(family.Operation)
		if family.ID == "" {
			continue
		}
		key := family.ID + "\x00" + family.Method + "\x00" + family.Path + "\x00" + family.Operation
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		families = append(families, family)
	}
	sort.SliceStable(families, func(i int, j int) bool {
		if families[i].ID != families[j].ID {
			return families[i].ID < families[j].ID
		}
		if families[i].Method != families[j].Method {
			return families[i].Method < families[j].Method
		}
		if families[i].Path != families[j].Path {
			return families[i].Path < families[j].Path
		}
		return families[i].Operation < families[j].Operation
	})
	next.Families = families
	return &next
}

func normalizeIngestSpec(ingest IngestSpec) IngestSpec {
	ingest.Mode = strings.ToLower(strings.TrimSpace(ingest.Mode))
	if ingest.Mode == "" {
		ingest.Mode = IngestModePull
	}
	if ingest.Deposit != nil {
		deposit := *ingest.Deposit
		deposit.ResourceFamilies = normalizeIngestResourceFamilies(deposit.ResourceFamilies)
		ingest.Deposit = &deposit
	}
	return ingest
}

func normalizeIngestResourceFamilies(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		family := normalizeIdentifier(value)
		if family == "" {
			continue
		}
		if _, ok := seen[family]; ok {
			continue
		}
		seen[family] = struct{}{}
		normalized = append(normalized, family)
	}
	return normalized
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
	next.NextCursorKeys = normalizeOrderedStringList(next.NextCursorKeys)
	next.HasMoreKey = strings.TrimSpace(next.HasMoreKey)
	return &next
}

func normalizeResourceReadSpec(read *ResourceReadSpec) *ResourceReadSpec {
	if read == nil {
		return nil
	}
	next := *read
	next.DetailPath = strings.TrimSpace(next.DetailPath)
	next.PathParams = normalizeOrderedStringList(next.PathParams)
	next.MapRecords = normalizeStringMap(next.MapRecords)
	if next.DetailPath == "" && len(next.PathParams) == 0 && len(next.MapRecords) == 0 && !next.Singleton && !next.AllowBareDetailRecord && !next.DisablePageSize {
		return nil
	}
	return &next
}

func normalizeFamilyConfigSpec(config *FamilyConfigSpec) *FamilyConfigSpec {
	if config == nil {
		return nil
	}
	next := *config
	next.BaseURL = strings.TrimSpace(next.BaseURL)
	next.StaticQuery = normalizeStringMap(next.StaticQuery)
	next.ConfigQuery = normalizeStringMap(next.ConfigQuery)
	next.ConfigAttributes = normalizeStringMap(next.ConfigAttributes)
	next.IdentityKeys = normalizeStringList(next.IdentityKeys)
	if next.BaseURL == "" && len(next.StaticQuery) == 0 && len(next.ConfigQuery) == 0 && len(next.ConfigAttributes) == 0 && len(next.IdentityKeys) == 0 {
		return nil
	}
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
	next.Entity = normalizeProjectionEntitySpec(next.Entity)
	next.Relationships = normalizeProjectionRelationshipSpecs(next.Relationships)
	return &next
}

func normalizeProjectionEntitySpec(entity *ProjectionEntitySpec) *ProjectionEntitySpec {
	if entity == nil {
		return nil
	}
	next := *entity
	next.EntityType = strings.TrimSpace(next.EntityType)
	next.URNKind = normalizeIdentifier(next.URNKind)
	next.IDAttributes = normalizeOrderedStringList(next.IDAttributes)
	next.LabelAttribute = strings.TrimSpace(next.LabelAttribute)
	return &next
}

func normalizeProjectionRelationshipSpecs(relationships []ProjectionRelationshipSpec) []ProjectionRelationshipSpec {
	if len(relationships) == 0 {
		return nil
	}
	normalized := make([]ProjectionRelationshipSpec, 0, len(relationships))
	for _, relationship := range relationships {
		relationship.Relation = normalizeIdentifier(relationship.Relation)
		relationship.From = normalizeProjectionEntitySpec(relationship.From)
		to := normalizeProjectionEntitySpec(&relationship.To)
		if to != nil {
			relationship.To = *to
		}
		relationship.RequiredAttributes = normalizeOrderedStringList(relationship.RequiredAttributes)
		relationship.LinkAttributes = normalizeOrderedStringList(relationship.LinkAttributes)
		relationship.MatchType = normalizeIdentifier(relationship.MatchType)
		normalized = append(normalized, relationship)
	}
	return normalized
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
	dimension.EvidenceTypes = normalizeStringList(dimension.EvidenceTypes)
	if len(dimension.EvidenceTypes) == 0 {
		dimension.EvidenceTypes = defaultCoverageEvidenceTypes(dimension.Type)
	}
	dimension.ControlDomains = normalizeStringList(dimension.ControlDomains)
	if len(dimension.ControlDomains) == 0 {
		dimension.ControlDomains = defaultCoverageControlDomains(dimension.Type)
	}
	dimension.ControlRefs = normalizeCoverageControlRefSpecs(dimension.ControlRefs)
	return dimension
}

func defaultCoverageEvidenceTypes(dimensionType string) []string {
	switch strings.TrimSpace(dimensionType) {
	case "alert_state":
		return []string{"security_monitoring"}
	case "app_entitlement":
		return []string{"identity_configuration"}
	case "audit_event":
		return []string{"logging_configuration"}
	case "deployment_state":
		return []string{"change_management"}
	case "entity_family":
		return []string{"source_snapshot"}
	case "incremental_sync":
		return []string{"source_sync_status"}
	case "lifecycle_state":
		return []string{"configuration_state"}
	case "relationship":
		return []string{"relationship_evidence"}
	case "remediation_state":
		return []string{"remediation_state"}
	default:
		return nil
	}
}

func defaultCoverageControlDomains(dimensionType string) []string {
	switch strings.TrimSpace(dimensionType) {
	case "alert_state":
		return []string{"logging_monitoring", "security_operations"}
	case "app_entitlement":
		return []string{"identity_access"}
	case "audit_event":
		return []string{"logging_monitoring"}
	case "deployment_state":
		return []string{"secure_delivery"}
	case "entity_family":
		return []string{"asset_inventory"}
	case "incremental_sync":
		return []string{"source_operations"}
	case "lifecycle_state":
		return []string{"security_operations"}
	case "relationship":
		return []string{"asset_inventory"}
	case "remediation_state":
		return []string{"remediation"}
	default:
		return nil
	}
}

func normalizeCoverageControlRefSpecs(refs []CoverageControlRefSpec) []CoverageControlRefSpec {
	if len(refs) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]CoverageControlRefSpec, 0, len(refs))
	for _, ref := range refs {
		next := CoverageControlRefSpec{
			FrameworkID:   strings.TrimSpace(ref.FrameworkID),
			FrameworkName: strings.TrimSpace(ref.FrameworkName),
			ControlID:     strings.TrimSpace(ref.ControlID),
		}
		if next.ControlID == "" || (next.FrameworkID == "" && next.FrameworkName == "") {
			normalized = append(normalized, next)
			continue
		}
		key := next.FrameworkID + "\x00" + next.FrameworkName + "\x00" + next.ControlID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, next)
	}
	sort.Slice(normalized, func(i int, j int) bool {
		if normalized[i].FrameworkName != normalized[j].FrameworkName {
			return normalized[i].FrameworkName < normalized[j].FrameworkName
		}
		if normalized[i].FrameworkID != normalized[j].FrameworkID {
			return normalized[i].FrameworkID < normalized[j].FrameworkID
		}
		return normalized[i].ControlID < normalized[j].ControlID
	})
	return normalized
}

func normalizeScopeOptions(options []ScopeOption, families []ResourceFamily) []ScopeOption {
	normalized := make([]ScopeOption, 0, len(options))
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

func normalizeOrderedStringList(values []string) []string {
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
