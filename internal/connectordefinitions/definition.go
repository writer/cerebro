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

	idPattern       = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	definitionIDRun = regexp.MustCompile(`[^a-z0-9_-]+`)
	stageOrder      = []string{StageDraft, StageSandbox, StagePilot, StageApproved, StageCertified}
	stageRank       = map[string]int{
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
		"oauth_client_credentials": {},
	}
)

// Definition is a versioned dynamic connector manifest that can be validated,
// tested, piloted, and later promoted into a built-in Source CDK implementation.
type Definition struct {
	ID               string           `json:"id"`
	TenantID         string           `json:"tenant_id"`
	SourceID         string           `json:"source_id"`
	DisplayName      string           `json:"display_name"`
	Description      string           `json:"description,omitempty"`
	Runtime          string           `json:"runtime"`
	Stage            string           `json:"stage"`
	CurrentVersion   int              `json:"current_version"`
	ConfigFields     []Field          `json:"config_fields,omitempty"`
	Auth             AuthSpec         `json:"auth"`
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
	Model              string   `json:"model"`
	CredentialFields   []Field  `json:"credential_fields,omitempty"`
	SupportedStoreIDs  []string `json:"supported_store_ids,omitempty"`
	RequiresReferences bool     `json:"requires_references,omitempty"`
}

// ResourceFamily describes one read-only resource collection exposed by the connector runtime.
type ResourceFamily struct {
	ID             string `json:"id"`
	Label          string `json:"label,omitempty"`
	Path           string `json:"path"`
	Method         string `json:"method,omitempty"`
	ListKey        string `json:"list_key,omitempty"`
	IDField        string `json:"id_field"`
	NameField      string `json:"name_field,omitempty"`
	UpdatedAtField string `json:"updated_at_field,omitempty"`
	EventKind      string `json:"event_kind,omitempty"`
	DefaultEnabled bool   `json:"default_enabled,omitempty"`
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
	definition.Runtime = strings.TrimSpace(definition.Runtime)
	if definition.Runtime == "" {
		definition.Runtime = RuntimeJSONAPI
	}
	definition.Stage = strings.TrimSpace(definition.Stage)
	if definition.Stage == "" {
		definition.Stage = StageDraft
	}
	definition.Auth.Model = strings.TrimSpace(definition.Auth.Model)
	if definition.Auth.Model == "" {
		definition.Auth.Model = "bearer_token"
	}
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
	if _, ok := authModels[definition.Auth.Model]; !ok {
		add(blocking("auth", "Auth model", fmt.Sprintf("Auth model %q is not supported.", definition.Auth.Model)))
	} else if definition.Auth.Model != "none" && len(definition.Auth.CredentialFields) == 0 {
		add(blocking("auth_fields", "Credential fields", "Add reference-only credential fields for this auth model."))
	} else {
		add(passing("auth", "Auth model", "Credential shape is explicit and reference-aware."))
	}
	for _, field := range append(append([]Field{}, definition.ConfigFields...), definition.Auth.CredentialFields...) {
		if !idPattern.MatchString(field.Key) {
			add(blocking("field_"+field.Key, "Field keys", "Field keys must be lowercase identifiers."))
		}
		if field.Secret && !field.ReferenceOnly {
			add(blocking("secret_"+field.Key, "Secret boundary", "Secret fields must be reference-only in dynamic connector definitions."))
		}
	}
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
		if method := strings.ToUpper(strings.TrimSpace(family.Method)); method != "" && method != "GET" {
			add(blocking("method_"+family.ID, "Read-only method", "Dynamic connector probes and pilots only support GET resource reads."))
		}
		if strings.TrimSpace(family.IDField) == "" {
			add(blocking("id_field_"+family.ID, "Resource identity", "Each resource family needs a stable id field."))
		}
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
		family.IDField = strings.TrimSpace(family.IDField)
		family.NameField = strings.TrimSpace(family.NameField)
		family.UpdatedAtField = strings.TrimSpace(family.UpdatedAtField)
		family.EventKind = strings.TrimSpace(family.EventKind)
		if family.EventKind == "" {
			family.EventKind = family.ID
		}
		normalized = append(normalized, family)
	}
	return normalized
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
