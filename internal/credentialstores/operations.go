package credentialstores

import (
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectorsecretstores"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	DefaultStoreID         = "cerebro_vault"
	EnvironmentManagedID   = "environment_managed"
	InfisicalID            = "infisical"
	GoogleSecretManagerID  = "google_secret_manager"
	AWSSecretsManagerID    = "aws_secrets_manager"
	AzureKeyVaultID        = "azure_key_vault"
	HashiCorpVaultID       = "hashicorp_vault"
	RuntimeStatusConfigKey = "__cerebro_runtime_status"

	authMethodEncryptedSubmission = "encrypted_submission"
	authMethodEnvironmentManaged  = "environment_managed"
	authMethodExternalReference   = "external_reference"
)

type BuildInput struct {
	GeneratedAt           time.Time
	TenantID              string
	RuntimeStoreStatus    string
	CredentialStoreStatus string
	Stores                []StoreMetadata
	Runtimes              []*cerebrov1.SourceRuntime
	Credentials           []*ports.ConnectorCredentialRecord
	SourceNames           map[string]string
	RequiresTenantFilter  bool
	TenantAllowed         func(string) bool
}

type ListResponse struct {
	GeneratedAt           string        `json:"generated_at"`
	TenantID              string        `json:"tenant_id,omitempty"`
	RuntimeStoreStatus    string        `json:"runtime_store_status"`
	CredentialStoreStatus string        `json:"credential_store_status"`
	Stores                []Operational `json:"stores"`
	Issues                []Issue       `json:"issues,omitempty"`
}

type Operational struct {
	Store    StoreMetadata `json:"store"`
	Health   Health        `json:"health"`
	Usage    Usage         `json:"usage"`
	Bindings []Binding     `json:"bindings,omitempty"`
	Issues   []Issue       `json:"issues,omitempty"`
}

type StoreMetadata struct {
	ID                         string        `json:"id"`
	Label                      string        `json:"label"`
	Provider                   string        `json:"provider"`
	Available                  bool          `json:"available"`
	Default                    bool          `json:"default,omitempty"`
	Mode                       string        `json:"mode"`
	Status                     string        `json:"status,omitempty"`
	Detail                     string        `json:"detail,omitempty"`
	Description                string        `json:"description,omitempty"`
	ReferencePrefixes          []string      `json:"reference_prefixes,omitempty"`
	ReferenceNamespaceTemplate string        `json:"reference_namespace_template,omitempty"`
	ReferenceFieldTemplate     string        `json:"reference_field_template,omitempty"`
	ReferencePlaceholder       string        `json:"reference_placeholder,omitempty"`
	NativeResolutionAvailable  bool          `json:"native_resolution_available,omitempty"`
	SetupSteps                 []SetupStep   `json:"setup_steps,omitempty"`
	RequiredConfig             []ConfigField `json:"required_config,omitempty"`
}

type SetupStep struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Command     string `json:"command,omitempty"`
}

type ConfigField struct {
	Env         string `json:"env"`
	Label       string `json:"label"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

type Health struct {
	Status     string `json:"status"`
	Severity   string `json:"severity,omitempty"`
	Detail     string `json:"detail,omitempty"`
	NextAction string `json:"next_action,omitempty"`
}

type Usage struct {
	Connections     int    `json:"connections"`
	Credentials     int    `json:"credentials"`
	Bindings        int    `json:"bindings"`
	FieldReferences int    `json:"field_references"`
	Issues          int    `json:"issues"`
	LastUpdatedAt   string `json:"last_updated_at,omitempty"`
}

type Binding struct {
	ID                string   `json:"id"`
	StoreID           string   `json:"credential_store_id"`
	SourceID          string   `json:"source_id,omitempty"`
	SourceName        string   `json:"source_name,omitempty"`
	RuntimeID         string   `json:"runtime_id,omitempty"`
	TenantID          string   `json:"tenant_id,omitempty"`
	AuthMethod        string   `json:"auth_method,omitempty"`
	Resolver          string   `json:"resolver,omitempty"`
	CredentialID      string   `json:"credential_id,omitempty"`
	CredentialStatus  string   `json:"credential_status,omitempty"`
	ConnectionStatus  string   `json:"connection_status,omitempty"`
	NextAction        string   `json:"next_action,omitempty"`
	Fields            []string `json:"fields,omitempty"`
	FieldCount        int      `json:"field_count,omitempty"`
	ReferencePrefixes []string `json:"reference_prefixes,omitempty"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
	LastUsedAt        string   `json:"last_used_at,omitempty"`
	LastValidatedAt   string   `json:"last_validated_at,omitempty"`
}

type Issue struct {
	ID           string `json:"id"`
	StoreID      string `json:"credential_store_id,omitempty"`
	SourceID     string `json:"source_id,omitempty"`
	RuntimeID    string `json:"runtime_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Field        string `json:"field,omitempty"`
	Status       string `json:"status"`
	Severity     string `json:"severity"`
	Detail       string `json:"detail"`
	NextAction   string `json:"next_action,omitempty"`
}

type bindingAccumulator struct {
	view            Binding
	fields          map[string]struct{}
	referenceFields map[string]struct{}
	prefixes        map[string]struct{}
	updatedAt       time.Time
}

func BuildOperations(input BuildInput) ListResponse {
	generatedAt := input.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	opsByStore := make(map[string]*Operational, len(input.Stores))
	for _, store := range input.Stores {
		store := store
		opsByStore[store.ID] = &Operational{
			Store:  store,
			Health: baseHealth(store),
		}
	}

	sourceNames := input.SourceNames
	if sourceNames == nil {
		sourceNames = map[string]string{}
	}
	credentialByID := make(map[string]*ports.ConnectorCredentialRecord, len(input.Credentials))
	credentialIDsByStore := map[string]map[string]struct{}{}
	runtimeIDsByStore := map[string]map[string]struct{}{}
	lastUpdatedByStore := map[string]time.Time{}
	bindingsByID := map[string]*bindingAccumulator{}
	issueIDs := map[string]struct{}{}
	issues := []Issue{}

	addIssue := func(issue Issue) {
		issue.ID = strings.TrimSpace(issue.ID)
		if issue.ID == "" {
			issue.ID = StableID("credential_store_issue", issue.StoreID, issue.SourceID, issue.RuntimeID, issue.CredentialID, issue.Field, issue.Detail)
		}
		if _, ok := issueIDs[issue.ID]; ok {
			return
		}
		issueIDs[issue.ID] = struct{}{}
		if issue.Status == "" {
			issue.Status = "warning"
		}
		if issue.Severity == "" {
			if issue.Status == "blocked" {
				issue.Severity = "error"
			} else {
				issue.Severity = "warning"
			}
		}
		issues = append(issues, issue)
		if op, ok := opsByStore[issue.StoreID]; ok {
			op.Issues = append(op.Issues, issue)
			op.Usage.Issues++
		}
	}

	for _, record := range input.Credentials {
		if record == nil {
			continue
		}
		if !tenantVisible(input, record.TenantID) {
			continue
		}
		credentialByID[record.ID] = record
		storeID := firstNonEmpty(record.CredentialStoreID, DefaultStoreID)
		if _, ok := opsByStore[storeID]; !ok {
			addIssue(Issue{
				ID:           StableID("unknown_store", record.ID),
				StoreID:      storeID,
				SourceID:     record.SourceID,
				RuntimeID:    record.RuntimeID,
				CredentialID: record.ID,
				Status:       "blocked",
				Severity:     "error",
				Detail:       "Credential record uses an unsupported credential store.",
				NextAction:   "rotate_credential",
			})
			continue
		}
		if credentialIDsByStore[storeID] == nil {
			credentialIDsByStore[storeID] = map[string]struct{}{}
		}
		credentialIDsByStore[storeID][record.ID] = struct{}{}
		binding := upsertBinding(bindingsByID, storeID, record.SourceID, sourceNames[record.SourceID], record.RuntimeID, record.TenantID, record.ID)
		binding.view.AuthMethod = firstNonEmpty(record.AuthMethod, authMethodEncryptedSubmission)
		binding.view.Resolver = ResolverForStore(storeID, "")
		binding.view.CredentialStatus = firstNonEmpty(record.Status, connectorcredentials.StatusValid)
		binding.view.UpdatedAt = connectorcredentials.TimestampOrZero(record.UpdatedAt)
		binding.view.LastUsedAt = connectorcredentials.TimestampOrZero(record.LastUsedAt)
		binding.view.LastValidatedAt = connectorcredentials.TimestampOrZero(record.LastValidatedAt)
		binding.updatedAt = newerTime(binding.updatedAt, record.UpdatedAt)
		for _, field := range record.Fields {
			addSetValue(binding.fields, field)
		}
		switch firstNonEmpty(record.Status, connectorcredentials.StatusValid) {
		case connectorcredentials.StatusRevoked:
			addIssue(Issue{
				ID:           StableID("revoked_credential", record.ID),
				StoreID:      storeID,
				SourceID:     record.SourceID,
				RuntimeID:    record.RuntimeID,
				CredentialID: record.ID,
				Status:       "blocked",
				Severity:     "error",
				Detail:       "Credential record is revoked.",
				NextAction:   "rotate_credential",
			})
		case connectorcredentials.StatusValid:
			if record.LastValidatedAt.IsZero() {
				addIssue(Issue{
					ID:           StableID("credential_not_validated", record.ID),
					StoreID:      storeID,
					SourceID:     record.SourceID,
					RuntimeID:    record.RuntimeID,
					CredentialID: record.ID,
					Status:       "warning",
					Severity:     "warning",
					Detail:       "Credential has no recorded validation check.",
					NextAction:   "run_connector_preflight",
				})
			}
		}
	}

	for _, runtime := range input.Runtimes {
		if runtime == nil {
			continue
		}
		if !tenantVisible(input, runtime.GetTenantId()) {
			continue
		}
		addRuntimeBindings(runtime, sourceNames, credentialByID, bindingsByID, addIssue)
	}

	for _, binding := range bindingsByID {
		storeID := binding.view.StoreID
		op, ok := opsByStore[storeID]
		if !ok {
			continue
		}
		binding.view.Fields = sortedSetKeys(binding.fields)
		binding.view.FieldCount = len(binding.view.Fields)
		binding.view.ReferencePrefixes = sortedSetKeys(binding.prefixes)
		if binding.view.UpdatedAt == "" && !binding.updatedAt.IsZero() {
			binding.view.UpdatedAt = connectorcredentials.TimestampOrZero(binding.updatedAt)
		}
		op.Bindings = append(op.Bindings, binding.view)
		op.Usage.FieldReferences += len(binding.referenceFields)
		if binding.view.RuntimeID != "" {
			if runtimeIDsByStore[storeID] == nil {
				runtimeIDsByStore[storeID] = map[string]struct{}{}
			}
			runtimeIDsByStore[storeID][binding.view.RuntimeID] = struct{}{}
		}
		if !binding.updatedAt.IsZero() {
			lastUpdatedByStore[storeID] = newerTime(lastUpdatedByStore[storeID], binding.updatedAt)
		}
	}

	for storeID, op := range opsByStore {
		op.Usage.Credentials = len(credentialIDsByStore[storeID])
		op.Usage.Connections = len(runtimeIDsByStore[storeID])
		op.Usage.Bindings = len(op.Bindings)
		op.Usage.LastUpdatedAt = connectorcredentials.TimestampOrZero(lastUpdatedByStore[storeID])
		sort.Slice(op.Bindings, func(i, j int) bool {
			return bindingSortKey(op.Bindings[i]) < bindingSortKey(op.Bindings[j])
		})
		if (op.Usage.Connections > 0 || op.Usage.Credentials > 0) && !op.Store.Available {
			addIssue(Issue{
				ID:         StableID("store_unavailable", storeID),
				StoreID:    storeID,
				Status:     "blocked",
				Severity:   "error",
				Detail:     "Credential store has saved bindings but is not available in this deployment.",
				NextAction: "configure_store",
			})
		}
	}

	views := make([]Operational, 0, len(input.Stores))
	for _, store := range input.Stores {
		op := opsByStore[store.ID]
		op.Health = health(*op)
		views = append(views, *op)
	}
	return ListResponse{
		GeneratedAt:           generatedAt.Format(time.RFC3339),
		TenantID:              strings.TrimSpace(input.TenantID),
		RuntimeStoreStatus:    firstNonEmpty(input.RuntimeStoreStatus, "unavailable"),
		CredentialStoreStatus: firstNonEmpty(input.CredentialStoreStatus, "unavailable"),
		Stores:                views,
		Issues:                issues,
	}
}

func addRuntimeBindings(runtime *cerebrov1.SourceRuntime, sourceNames map[string]string, credentials map[string]*ports.ConnectorCredentialRecord, bindings map[string]*bindingAccumulator, addIssue func(Issue)) {
	sourceID := strings.TrimSpace(runtime.GetSourceId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	sourceName := sourceNames[sourceID]
	for key, value := range runtime.GetConfig() {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || sourceconfig.InternalKey(key) {
			continue
		}
		if credentialID, field, ok := sourceconfig.CredentialReference(value); ok {
			record := credentials[credentialID]
			storeID := DefaultStoreID
			authMethod := authMethodEncryptedSubmission
			status := "missing"
			if record != nil {
				storeID = firstNonEmpty(record.CredentialStoreID, DefaultStoreID)
				authMethod = firstNonEmpty(record.AuthMethod, authMethodEncryptedSubmission)
				status = firstNonEmpty(record.Status, connectorcredentials.StatusValid)
			} else {
				addIssue(Issue{
					ID:           StableID("missing_credential_record", runtimeID, credentialID, field),
					StoreID:      storeID,
					SourceID:     sourceID,
					RuntimeID:    runtimeID,
					CredentialID: credentialID,
					Field:        firstNonEmpty(field, key),
					Status:       "blocked",
					Severity:     "error",
					Detail:       "Runtime references a credential record that is not present.",
					NextAction:   "rotate_credential",
				})
			}
			binding := upsertBinding(bindings, storeID, sourceID, sourceName, runtimeID, tenantID, credentialID)
			binding.view.AuthMethod = firstNonEmpty(binding.view.AuthMethod, authMethod)
			binding.view.Resolver = ResolverForStore(storeID, "credential:")
			binding.view.CredentialStatus = firstNonEmpty(binding.view.CredentialStatus, status)
			binding.view.ConnectionStatus = firstNonEmpty(binding.view.ConnectionStatus, runtimeStatus(runtime))
			binding.view.NextAction = firstNonEmpty(binding.view.NextAction, runtimeNextAction(runtime))
			addSetValue(binding.fields, firstNonEmpty(field, key))
			addSetValue(binding.referenceFields, firstNonEmpty(field, key))
			addSetValue(binding.prefixes, "credential:")
			continue
		}
		if _, ok := sourceconfig.SecretReferenceName(value); ok {
			binding := upsertBinding(bindings, EnvironmentManagedID, sourceID, sourceName, runtimeID, tenantID, "")
			binding.view.AuthMethod = firstNonEmpty(binding.view.AuthMethod, authMethodEnvironmentManaged)
			binding.view.Resolver = ResolverForStore(EnvironmentManagedID, "env:")
			binding.view.ConnectionStatus = firstNonEmpty(binding.view.ConnectionStatus, runtimeStatus(runtime))
			binding.view.NextAction = firstNonEmpty(binding.view.NextAction, runtimeNextAction(runtime))
			addSetValue(binding.fields, key)
			addSetValue(binding.referenceFields, key)
			addSetValue(binding.prefixes, "env:")
			continue
		}
		ref, ok, err := connectorsecretstores.ParseReference(value)
		if err != nil {
			addIssue(Issue{
				ID:         StableID("invalid_native_reference", runtimeID, key),
				StoreID:    StoreIDForNativeReference(value),
				SourceID:   sourceID,
				RuntimeID:  runtimeID,
				Field:      key,
				Status:     "blocked",
				Severity:   "error",
				Detail:     "Runtime credential reference has an invalid secret-store address.",
				NextAction: "fix_credential_reference",
			})
			continue
		}
		if ok {
			storeID := ref.StoreID
			binding := upsertBinding(bindings, storeID, sourceID, sourceName, runtimeID, tenantID, "")
			binding.view.AuthMethod = firstNonEmpty(binding.view.AuthMethod, authMethodExternalReference)
			binding.view.Resolver = ResolverForStore(storeID, ref.Prefix)
			binding.view.ConnectionStatus = firstNonEmpty(binding.view.ConnectionStatus, runtimeStatus(runtime))
			binding.view.NextAction = firstNonEmpty(binding.view.NextAction, runtimeNextAction(runtime))
			addSetValue(binding.fields, key)
			addSetValue(binding.referenceFields, key)
			addSetValue(binding.prefixes, ref.Prefix)
			if err := validateReferenceForRuntime(storeID, sourceID, tenantID, runtimeID, map[string]string{key: value}); err != nil {
				addIssue(Issue{
					ID:         StableID("reference_boundary", runtimeID, key),
					StoreID:    storeID,
					SourceID:   sourceID,
					RuntimeID:  runtimeID,
					Field:      key,
					Status:     "blocked",
					Severity:   "error",
					Detail:     "Runtime credential reference is not allowed for this store or runtime scope.",
					NextAction: "fix_credential_reference",
				})
			}
			continue
		}
		if sourceconfig.SensitiveKey(key) {
			addIssue(Issue{
				ID:         StableID("plaintext_sensitive_config", runtimeID, key),
				SourceID:   sourceID,
				RuntimeID:  runtimeID,
				Field:      key,
				Status:     "blocked",
				Severity:   "error",
				Detail:     "Sensitive runtime field is stored without a credential reference.",
				NextAction: "replace_with_credential_reference",
			})
		}
	}
}

func validateReferenceForRuntime(storeID string, sourceID string, tenantID string, runtimeID string, references map[string]string) error {
	for _, value := range references {
		if err := connectorsecretstores.ValidateReferenceForStore(storeID, value); err != nil {
			return err
		}
		if err := connectorsecretstores.AuthorizeRuntimeReferences(sourceID, tenantID, runtimeID, references); err != nil {
			return err
		}
	}
	return nil
}

func upsertBinding(bindings map[string]*bindingAccumulator, storeID string, sourceID string, sourceName string, runtimeID string, tenantID string, credentialID string) *bindingAccumulator {
	key := StableID("binding", storeID, sourceID, runtimeID, tenantID, credentialID)
	if credentialID == "" {
		key = StableID("binding", storeID, sourceID, runtimeID, tenantID, "references")
	}
	binding, ok := bindings[key]
	if ok {
		return binding
	}
	if sourceName == "" && sourceID != "" {
		sourceName = sourceID
	}
	binding = &bindingAccumulator{
		view: Binding{
			ID:         key,
			StoreID:    storeID,
			SourceID:   sourceID,
			SourceName: sourceName,
			RuntimeID:  runtimeID,
			TenantID:   tenantID,
		},
		fields:          map[string]struct{}{},
		referenceFields: map[string]struct{}{},
		prefixes:        map[string]struct{}{},
	}
	if credentialID != "" {
		binding.view.CredentialID = credentialID
	}
	bindings[key] = binding
	return binding
}

func baseHealth(store StoreMetadata) Health {
	status := firstNonEmpty(store.Status, "needs_configuration")
	severity := "warning"
	nextAction := "configure_store"
	if store.Available {
		status = "ready"
		severity = "success"
		nextAction = "connect_source"
	}
	return Health{
		Status:     status,
		Severity:   severity,
		Detail:     store.Detail,
		NextAction: nextAction,
	}
}

func health(op Operational) Health {
	hasError := false
	hasWarning := false
	for _, issue := range op.Issues {
		switch issue.Severity {
		case "error":
			hasError = true
		case "warning":
			hasWarning = true
		}
	}
	inUse := op.Usage.Connections > 0 || op.Usage.Credentials > 0
	switch {
	case hasError:
		return Health{
			Status:     "needs_attention",
			Severity:   "error",
			Detail:     "Credential bindings need operator action.",
			NextAction: "fix_credential_store_issues",
		}
	case hasWarning:
		return Health{
			Status:     "warning",
			Severity:   "warning",
			Detail:     "Credential bindings have warnings to review.",
			NextAction: "review_credential_store_warnings",
		}
	case inUse && op.Store.Available:
		return Health{
			Status:     "in_use",
			Severity:   "success",
			Detail:     "Credential store has active runtime bindings.",
			NextAction: "monitor_rotation",
		}
	case op.Store.Available:
		return Health{
			Status:     "ready",
			Severity:   "success",
			Detail:     "Credential store is ready for new connector bindings.",
			NextAction: "connect_source",
		}
	default:
		return baseHealth(op.Store)
	}
}

func runtimeStatus(runtime *cerebrov1.SourceRuntime) string {
	status := strings.TrimSpace(runtime.GetConfig()[RuntimeStatusConfigKey])
	if status == "" {
		return "configured"
	}
	return status
}

func runtimeNextAction(runtime *cerebrov1.SourceRuntime) string {
	switch runtimeStatus(runtime) {
	case "healthy", "ready":
		return "monitor_runtime"
	case "failed", "degraded", "needs_attention":
		return "fix_runtime"
	default:
		return "run_source_check"
	}
}

func ResolverForStore(storeID string, prefix string) string {
	switch strings.TrimSpace(storeID) {
	case DefaultStoreID:
		return "cerebro_vault"
	case EnvironmentManagedID:
		return "environment"
	case AWSSecretsManagerID:
		if prefix == connectorsecretstores.PrefixAWSSecretsManager {
			return "native"
		}
		return "environment_projection"
	case InfisicalID, GoogleSecretManagerID, AzureKeyVaultID, HashiCorpVaultID:
		if strings.TrimSpace(prefix) != "" && prefix != "env:" {
			return "native_reference"
		}
		return "environment_projection"
	default:
		return "unknown"
	}
}

func StoreIDForNativeReference(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, connectorsecretstores.PrefixAWSSecretsManager):
		return AWSSecretsManagerID
	case strings.HasPrefix(value, connectorsecretstores.PrefixGoogleSecretMgr):
		return GoogleSecretManagerID
	case strings.HasPrefix(value, connectorsecretstores.PrefixAzureKeyVault):
		return AzureKeyVaultID
	case strings.HasPrefix(value, connectorsecretstores.PrefixHashiCorpVault):
		return HashiCorpVaultID
	case strings.HasPrefix(value, connectorsecretstores.PrefixInfisical):
		return InfisicalID
	default:
		return ""
	}
}

func bindingSortKey(binding Binding) string {
	return strings.ToLower(strings.Join([]string{
		binding.SourceName,
		binding.SourceID,
		binding.RuntimeID,
		binding.CredentialID,
	}, "\x00"))
}

func StableID(parts ...string) string {
	builder := strings.Builder{}
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('_')
		}
		for _, char := range part {
			switch {
			case char >= 'a' && char <= 'z':
				builder.WriteRune(char)
			case char >= '0' && char <= '9':
				builder.WriteRune(char)
			default:
				builder.WriteByte('_')
			}
		}
	}
	return strings.Trim(builder.String(), "_")
}

func tenantVisible(input BuildInput, tenantID string) bool {
	if !input.RequiresTenantFilter {
		return true
	}
	if input.TenantAllowed == nil {
		return false
	}
	return input.TenantAllowed(tenantID)
}

func addSetValue(set map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	set[value] = struct{}{}
}

func newerTime(left time.Time, right time.Time) time.Time {
	if right.IsZero() {
		return left
	}
	if left.IsZero() || right.After(left) {
		return right
	}
	return left
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
