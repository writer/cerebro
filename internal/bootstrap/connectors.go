package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectordiagnostics"
	"github.com/writer/cerebro/internal/connectorpreflight"
	"github.com/writer/cerebro/internal/connectorpreview"
	"github.com/writer/cerebro/internal/connectorsecretstores"
	"github.com/writer/cerebro/internal/connectorvalidation"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceregistry"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const (
	defaultConnectorCredentialStoreID = "cerebro_vault"
	connectorStoreEnvironmentManaged  = "environment_managed"
	connectorActivityDefaultLimit     = 500
	connectorActivityMaxLimit         = 500

	connectorAuthMethodEncryptedSubmission = "encrypted_submission"
	connectorAuthMethodAWSSSOProfile       = "aws_sso_profile"
	connectorAuthMethodInfisicalCLI        = "infisical_cli"
	connectorAuthMethodEnvironmentManaged  = "environment_managed"
	connectorAuthMethodExternalReference   = "external_reference"

	connectorStoreInfisical          = "infisical"
	connectorStoreGoogleSecretMgr    = "google_secret_manager"
	connectorStoreAWSSecretsManager  = "aws_secrets_manager"
	connectorStoreAzureKeyVault      = "azure_key_vault"
	connectorStoreHashiCorpVault     = "hashicorp_vault"
	connectorCredentialStoreModeRefs = "reference"

	connectorAccessAvailable   = "available"
	connectorAccessCatalogOnly = "catalog_only"
	connectorAccessRestricted  = "restricted"

	connectorDefinitionOriginCompiled = "compiled_source"
	connectorDefinitionOriginCatalog  = "builtin_catalog"
	connectorDefinitionOriginTenant   = "tenant_definition"

	connectorReadinessStageSetupEnabled        = "setup_enabled"
	connectorReadinessStageAPIRestricted       = "api_restricted"
	connectorReadinessStageSourcegenReady      = "sourcegen_ready"
	connectorReadinessStageCatalogReady        = "catalog_ready"
	connectorReadinessStageAuthExtensionNeeded = "auth_extension_required"
	connectorReadinessStageRuntimeNeeded       = "runtime_required"
	connectorReadinessStageRuntimeBacked       = "runtime_backed"
	connectorReadinessStageRuntimeUnknown      = "runtime_unknown"

	connectorLibraryViewFull    = "full"
	connectorLibraryViewSummary = "summary"
)

var errConnectorAccessRestricted = errors.New("connector access restricted")

type connectorCatalogEntry struct {
	connectorCatalogIdentity
	connectorCatalogDefinitionState
	connectorCatalogRuntimeState
	connectorCatalogSetupState
	connectorCatalogAccessState
}
type connectorCatalogIdentity struct {
	SourceID    string `json:"source_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}
type connectorCatalogDefinitionState struct {
	EmittedKinds          []string                      `json:"emitted_kinds"`
	CatalogStatus         string                        `json:"catalog_status,omitempty"`
	ClassifierOutput      string                        `json:"classifier_output,omitempty"`
	AuthModel             string                        `json:"auth_model,omitempty"`
	RuntimeExecutable     bool                          `json:"runtime_executable,omitempty"`
	MissingFeatures       []string                      `json:"missing_features,omitempty"`
	CatalogCategories     []string                      `json:"catalog_categories,omitempty"`
	VerificationEndpoint  string                        `json:"verification_endpoint,omitempty"`
	ResourceFamilies      []connectorResourceFamilyView `json:"resource_families,omitempty"`
	CatalogSchemaVersion  string                        `json:"catalog_schema_version,omitempty"`
	CatalogCurrentVersion int                           `json:"catalog_current_version,omitempty"`
	CatalogSourcePath     string                        `json:"catalog_source_path,omitempty"`
	DefinitionOrigin      string                        `json:"definition_origin,omitempty"`
	ReadinessStage        string                        `json:"readiness_stage,omitempty"`
	ValidationGrade       string                        `json:"validation_grade,omitempty"`
	Cataloged             bool                          `json:"cataloged"`
	Callable              bool                          `json:"callable"`
	IntegrationDepth      connectorIntegrationDepthView `json:"integration_depth,omitempty"`
}
type connectorCatalogRuntimeState struct {
	Status                 string `json:"status"`
	ConfiguredRuntimes     int    `json:"configured_runtimes"`
	HealthyRuntimes        int    `json:"healthy_runtimes"`
	NeedsAttentionRuntimes int    `json:"needs_attention_runtimes"`
}
type connectorCatalogSetupState struct {
	ConnectionMethods []connectorConnectionMethodView `json:"connection_methods,omitempty"`
	ScopeOptions      []connectorScopeOptionView      `json:"scope_options,omitempty"`
}
type connectorCatalogAccessState struct {
	AccessStatus        string `json:"access_status,omitempty"`
	AccessReason        string `json:"access_reason,omitempty"`
	SetupAllowed        bool   `json:"setup_allowed"`
	Requestable         bool   `json:"requestable,omitempty"`
	RequestableReason   string `json:"requestable_reason,omitempty"`
	RequestAccessURL    string `json:"request_access_url,omitempty"`
	RequestAccessAction string `json:"request_access_action,omitempty"`
}
type connectorIntegrationDepthView struct {
	Level               string `json:"level,omitempty"`
	Score               int    `json:"score"`
	AuthModel           string `json:"auth_model,omitempty"`
	ResourceFamilies    int    `json:"resource_families"`
	EmittedKinds        int    `json:"emitted_kinds"`
	CoverageDimensions  int    `json:"coverage_dimensions"`
	HighValueFamilies   int    `json:"high_value_families"`
	ProjectionTemplates int    `json:"projection_templates"`
	ScopeOptions        int    `json:"scope_options"`
	RuntimeExecutable   bool   `json:"runtime_executable"`
	SetupEnabled        bool   `json:"setup_enabled"`
}
type connectorLibraryResponse struct {
	Connectors          []connectorCatalogEntry `json:"connectors"`
	Counts              connectorLibraryCounts  `json:"counts"`
	GeneratedAt         string                  `json:"generated_at"`
	TenantID            string                  `json:"tenant_id,omitempty"`
	RuntimeStore        string                  `json:"runtime_store"`
	CatalogVersion      string                  `json:"catalog_version,omitempty"`
	CatalogSourceCommit string                  `json:"catalog_source_commit,omitempty"`
	CredentialTransport connectorTransportView  `json:"credential_transport"`
	CredentialVault     connectorVaultView      `json:"credential_vault"`
	CredentialStores    []connectorStoreView    `json:"credential_stores,omitempty"`
}
type connectorLibrarySummaryResponse struct {
	Connectors          []connectorCatalogSummaryEntry `json:"connectors"`
	Counts              connectorLibraryCounts         `json:"counts"`
	GeneratedAt         string                         `json:"generated_at"`
	View                string                         `json:"view"`
	TenantID            string                         `json:"tenant_id,omitempty"`
	RuntimeStore        string                         `json:"runtime_store"`
	CatalogVersion      string                         `json:"catalog_version,omitempty"`
	CatalogSourceCommit string                         `json:"catalog_source_commit,omitempty"`
}
type connectorCatalogSummaryEntry struct {
	SourceID               string   `json:"source_id"`
	DisplayName            string   `json:"display_name,omitempty"`
	Status                 string   `json:"status,omitempty"`
	ConfiguredRuntimes     int      `json:"configured_runtimes,omitempty"`
	HealthyRuntimes        int      `json:"healthy_runtimes,omitempty"`
	NeedsAttentionRuntimes int      `json:"needs_attention_runtimes,omitempty"`
	CatalogStatus          string   `json:"catalog_status,omitempty"`
	ClassifierOutput       string   `json:"classifier_output,omitempty"`
	AuthModel              string   `json:"auth_model,omitempty"`
	RuntimeExecutable      bool     `json:"runtime_executable,omitempty"`
	CatalogCategories      []string `json:"catalog_categories,omitempty"`
	DefinitionOrigin       string   `json:"definition_origin,omitempty"`
	ReadinessStage         string   `json:"readiness_stage,omitempty"`
	ValidationGrade        string   `json:"validation_grade,omitempty"`
	Cataloged              bool     `json:"cataloged"`
	Callable               bool     `json:"callable"`
	AccessStatus           string   `json:"access_status,omitempty"`
	SetupAllowed           bool     `json:"setup_allowed"`
	Requestable            bool     `json:"requestable,omitempty"`
	IntegrationLevel       string   `json:"integration_level,omitempty"`
	IntegrationScore       int      `json:"integration_score,omitempty"`
	ResourceFamilyCount    int      `json:"resource_family_count,omitempty"`
	EmittedKindCount       int      `json:"emitted_kind_count,omitempty"`
	ScopeOptionCount       int      `json:"scope_option_count,omitempty"`
}
type connectorLibraryCounts struct {
	Total        int `json:"total"`
	Cataloged    int `json:"cataloged"`
	Callable     int `json:"callable"`
	CatalogOnly  int `json:"catalog_only"`
	SetupEnabled int `json:"setup_enabled"`
}
type connectorDetailResponse struct {
	GeneratedAt        string                       `json:"generated_at"`
	TenantID           string                       `json:"tenant_id,omitempty"`
	Connector          connectorCatalogEntry        `json:"connector"`
	Summary            connectorOperationsSummary   `json:"summary"`
	Connections        []connectorConnectionView    `json:"connections"`
	Activity           []connectorActivityView      `json:"activity"`
	DiagnosticTimeline []connectordiagnostics.Entry `json:"diagnostic_timeline,omitempty"`
}
type connectorActivityResponse struct {
	GeneratedAt        string                       `json:"generated_at"`
	TenantID           string                       `json:"tenant_id,omitempty"`
	SourceID           string                       `json:"source_id"`
	Activity           []connectorActivityView      `json:"activity"`
	DiagnosticTimeline []connectordiagnostics.Entry `json:"diagnostic_timeline,omitempty"`
}
type connectorOperationsSummary struct {
	Status               string `json:"status"`
	StatusReason         string `json:"status_reason"`
	TopIssue             string `json:"top_issue,omitempty"`
	TotalConnections     int    `json:"total_connections"`
	HealthyConnections   int    `json:"healthy_connections"`
	NeedsAttention       int    `json:"needs_attention"`
	LastActivityAt       string `json:"last_activity_at,omitempty"`
	SyncFrequencySeconds *int64 `json:"sync_frequency_seconds,omitempty"`
	ResourceTypes        int    `json:"resource_types"`
	EmittedKinds         int    `json:"emitted_kinds"`
}
type connectorConnectionView struct {
	RuntimeID               string                `json:"runtime_id"`
	SourceID                string                `json:"source_id"`
	TenantID                string                `json:"tenant_id,omitempty"`
	Family                  string                `json:"family,omitempty"`
	Status                  string                `json:"status"`
	GraphStatus             string                `json:"graph_status"`
	ContractProbeState      string                `json:"contract_probe_state"`
	LastActivityAt          string                `json:"last_activity_at,omitempty"`
	CheckpointWatermark     string                `json:"checkpoint_watermark,omitempty"`
	WatermarkLagSeconds     *int64                `json:"watermark_lag_seconds,omitempty"`
	RecordsAccepted         uint32                `json:"records_accepted"`
	RecordsRejected         uint32                `json:"records_rejected"`
	EntitiesProjected       uint32                `json:"entities_projected"`
	LinksProjected          uint32                `json:"links_projected"`
	CursorPending           bool                  `json:"cursor_pending"`
	CheckpointCursorPresent bool                  `json:"checkpoint_cursor_present"`
	NextAction              string                `json:"next_action"`
	ScopePolicy             *resourcescope.Policy `json:"scope_policy,omitempty"`
}
type connectorActivityView struct {
	ID                string `json:"id"`
	RuntimeID         string `json:"runtime_id"`
	SourceID          string `json:"source_id"`
	TenantID          string `json:"tenant_id,omitempty"`
	Family            string `json:"family,omitempty"`
	Type              string `json:"type"`
	Status            string `json:"status"`
	Title             string `json:"title"`
	Description       string `json:"description,omitempty"`
	OccurredAt        string `json:"occurred_at,omitempty"`
	DurationSeconds   *int64 `json:"duration_seconds,omitempty"`
	RecordsAccepted   uint32 `json:"records_accepted,omitempty"`
	RecordsRejected   uint32 `json:"records_rejected,omitempty"`
	EntitiesProjected int64  `json:"entities_projected,omitempty"`
	LinksProjected    int64  `json:"links_projected,omitempty"`
	FailureClass      string `json:"failure_class,omitempty"`
}
type connectorTransportView struct {
	Available bool   `json:"available"`
	Algorithm string `json:"algorithm"`
	KeyURL    string `json:"key_url"`
}
type connectorVaultView struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}
type connectorStoreView struct {
	ID                         string                          `json:"id"`
	Label                      string                          `json:"label"`
	Provider                   string                          `json:"provider"`
	Available                  bool                            `json:"available"`
	Default                    bool                            `json:"default,omitempty"`
	Mode                       string                          `json:"mode"`
	Status                     string                          `json:"status,omitempty"`
	Detail                     string                          `json:"detail,omitempty"`
	Description                string                          `json:"description,omitempty"`
	ReferencePrefixes          []string                        `json:"reference_prefixes,omitempty"`
	ReferenceNamespaceTemplate string                          `json:"reference_namespace_template,omitempty"`
	ReferenceFieldTemplate     string                          `json:"reference_field_template,omitempty"`
	ReferencePlaceholder       string                          `json:"reference_placeholder,omitempty"`
	NativeResolutionAvailable  bool                            `json:"native_resolution_available,omitempty"`
	SetupSteps                 []connectorStoreSetupStepView   `json:"setup_steps,omitempty"`
	RequiredConfig             []connectorStoreConfigFieldView `json:"required_config,omitempty"`
}
type connectorStoreSetupStepView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Command     string `json:"command,omitempty"`
}
type connectorStoreConfigFieldView struct {
	Env         string `json:"env"`
	Label       string `json:"label"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}
type connectorFieldView struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	Required      bool   `json:"required,omitempty"`
	Secret        bool   `json:"secret,omitempty"`
	ReferenceOnly bool   `json:"reference_only,omitempty"`
	Placeholder   string `json:"placeholder,omitempty"`
	Help          string `json:"help,omitempty"`
}
type connectorConnectionMethodView struct {
	ID                string                         `json:"id"`
	Label             string                         `json:"label"`
	ShortLabel        string                         `json:"short_label,omitempty"`
	Category          string                         `json:"category,omitempty"`
	Description       string                         `json:"description"`
	CredentialStores  []string                       `json:"credential_stores,omitempty"`
	ConfigFields      []connectorFieldView           `json:"config_fields,omitempty"`
	CredentialFields  []connectorFieldView           `json:"credential_fields,omitempty"`
	RequiresSecrets   bool                           `json:"requires_secrets"`
	Recommended       bool                           `json:"recommended,omitempty"`
	Saveable          bool                           `json:"saveable"`
	UnavailableReason string                         `json:"unavailable_reason,omitempty"`
	Prerequisites     []connectorPrerequisiteView    `json:"prerequisites,omitempty"`
	Steps             []connectorSetupStepView       `json:"steps,omitempty"`
	Commands          []string                       `json:"commands,omitempty"`
	ProductGroups     []connectorProductGroupView    `json:"product_groups,omitempty"`
	DeploymentGuides  []connectorDeploymentGuideView `json:"deployment_guides,omitempty"`
	RegionGuidance    *connectorRegionGuidanceView   `json:"region_guidance,omitempty"`
	SecurityNotes     []string                       `json:"security_notes,omitempty"`
}
type connectorPrerequisiteView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}
type connectorSetupStepView struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description,omitempty"`
	Commands    []string `json:"commands,omitempty"`
}
type connectorProductGroupView struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	Description    string   `json:"description,omitempty"`
	Families       []string `json:"families,omitempty"`
	DefaultEnabled bool     `json:"default_enabled,omitempty"`
	Required       bool     `json:"required,omitempty"`
	PermissionNote string   `json:"permission_note,omitempty"`
	CostNote       string   `json:"cost_note,omitempty"`
}

type connectorDeploymentGuideView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Language    string `json:"language,omitempty"`
	Description string `json:"description,omitempty"`
	Body        string `json:"body,omitempty"`
}

type connectorRegionGuidanceView struct {
	DefaultRegion       string   `json:"default_region,omitempty"`
	Examples            []string `json:"examples,omitempty"`
	SupportsGlobal      bool     `json:"supports_global,omitempty"`
	SupportsMultiRegion bool     `json:"supports_multi_region,omitempty"`
	Description         string   `json:"description,omitempty"`
}

type connectorScopeOptionView = connectorpreview.ScopeOption

type connectorResourceFamilyView struct {
	ID                 string   `json:"id"`
	Label              string   `json:"label,omitempty"`
	Path               string   `json:"path,omitempty"`
	EventKind          string   `json:"event_kind,omitempty"`
	SchemaRef          string   `json:"schema_ref,omitempty"`
	ProjectionTemplate string   `json:"projection_template,omitempty"`
	Coverage           []string `json:"coverage,omitempty"`
	HighValue          bool     `json:"high_value,omitempty"`
}

type connectorConnectionRequest struct {
	RuntimeID            string                                `json:"runtime_id"`
	TenantID             string                                `json:"tenant_id"`
	CheckOnly            bool                                  `json:"check_only,omitempty"`
	AuthMethod           string                                `json:"auth_method,omitempty"`
	CredentialStoreID    string                                `json:"credential_store_id,omitempty"`
	Config               map[string]string                     `json:"config"`
	ScopePolicy          resourcescope.Policy                  `json:"scope_policy,omitempty"`
	CredentialReferences map[string]string                     `json:"credential_references,omitempty"`
	EncryptedCredentials connectorcredentials.EncryptedPayload `json:"encrypted_credentials"`
}

type connectorCredentialBrokerRequest struct {
	RuntimeID            string                                `json:"runtime_id"`
	TenantID             string                                `json:"tenant_id,omitempty"`
	CredentialStoreID    string                                `json:"credential_store_id,omitempty"`
	IdempotencyKey       string                                `json:"idempotency_key,omitempty"`
	EncryptedCredentials connectorcredentials.EncryptedPayload `json:"encrypted_credentials"`
}

type connectorCredentialRotateRequest struct {
	RuntimeID            string                                `json:"runtime_id,omitempty"`
	TenantID             string                                `json:"tenant_id,omitempty"`
	CredentialStoreID    string                                `json:"credential_store_id,omitempty"`
	IdempotencyKey       string                                `json:"idempotency_key,omitempty"`
	RevokePrevious       bool                                  `json:"revoke_previous,omitempty"`
	EncryptedCredentials connectorcredentials.EncryptedPayload `json:"encrypted_credentials"`
}

type connectorCredentialRevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

type connectorPreflightResponse struct {
	GeneratedAt        string                          `json:"generated_at"`
	SourceID           string                          `json:"source_id"`
	RuntimeID          string                          `json:"runtime_id,omitempty"`
	TenantID           string                          `json:"tenant_id,omitempty"`
	AuthMethod         string                          `json:"auth_method,omitempty"`
	CredentialStoreID  string                          `json:"credential_store_id,omitempty"`
	Status             string                          `json:"status"`
	Summary            string                          `json:"summary"`
	NextAction         string                          `json:"next_action"`
	Checks             []connectorPreflightCheckView   `json:"checks"`
	ScopePreview       connectorScopePreviewView       `json:"scope_preview"`
	CredentialBoundary connectorCredentialBoundaryView `json:"credential_boundary"`
	DiagnosticTimeline []connectordiagnostics.Entry    `json:"diagnostic_timeline,omitempty"`
}

type connectorPreflightCheckView struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail,omitempty"`
	NextAction string `json:"next_action,omitempty"`
	Blocking   bool   `json:"blocking,omitempty"`
}

type connectorScopePreviewView struct {
	Mode                   string   `json:"mode,omitempty"`
	AvailableResourceTypes int      `json:"available_resource_types"`
	DisabledResourceTypes  int      `json:"disabled_resource_types"`
	EnabledResourceTypes   int      `json:"enabled_resource_types"`
	ExcludedFamilies       []string `json:"excluded_families,omitempty"`
	ExactResourceCount     int      `json:"exact_resource_count"`
}

type connectorCredentialBoundaryView struct {
	Mode                      string                           `json:"mode,omitempty"`
	StoreID                   string                           `json:"credential_store_id,omitempty"`
	StoreStatus               string                           `json:"store_status,omitempty"`
	StoreDetail               string                           `json:"store_detail,omitempty"`
	SendsSecrets              bool                             `json:"sends_secrets"`
	ReferenceOnly             bool                             `json:"reference_only"`
	ReferenceNamespace        string                           `json:"reference_namespace,omitempty"`
	ReferencePrefixes         []string                         `json:"reference_prefixes,omitempty"`
	NativeResolutionAvailable bool                             `json:"native_resolution_available,omitempty"`
	FieldsAccepted            []string                         `json:"fields_accepted,omitempty"`
	ReferenceTemplates        []connectorReferenceTemplateView `json:"reference_templates,omitempty"`
}

type connectorReferenceTemplateView struct {
	Field       string `json:"field"`
	Label       string `json:"label,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Reference   string `json:"reference"`
	Description string `json:"description,omitempty"`
}

type connectorConnectionResponse struct {
	SourceID    string                  `json:"source_id"`
	Runtime     json.RawMessage         `json:"runtime"`
	Credential  connectorCredentialView `json:"credential"`
	ScopePolicy *resourcescope.Policy   `json:"scope_policy,omitempty"`
	Status      string                  `json:"status,omitempty"`
}

type connectorCredentialBrokerResponse struct {
	SourceID             string                  `json:"source_id"`
	TenantID             string                  `json:"tenant_id"`
	RuntimeID            string                  `json:"runtime_id"`
	Status               string                  `json:"status"`
	Credential           connectorCredentialView `json:"credential"`
	CredentialReferences map[string]string       `json:"credential_references"`
}

type connectorCredentialView struct {
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id"`
	SourceID             string   `json:"source_id"`
	RuntimeID            string   `json:"runtime_id"`
	StoreID              string   `json:"credential_store_id"`
	AuthMethod           string   `json:"auth_method"`
	Status               string   `json:"status"`
	KeyID                string   `json:"key_id"`
	Fields               []string `json:"fields"`
	CreatedBy            string   `json:"created_by,omitempty"`
	UpdatedBy            string   `json:"updated_by,omitempty"`
	RevokedBy            string   `json:"revoked_by,omitempty"`
	PreviousCredentialID string   `json:"previous_credential_id,omitempty"`
	CreatedAt            string   `json:"created_at,omitempty"`
	UpdatedAt            string   `json:"updated_at,omitempty"`
	RevokedAt            string   `json:"revoked_at,omitempty"`
	LastUsedAt           string   `json:"last_used_at,omitempty"`
	LastValidatedAt      string   `json:"last_validated_at,omitempty"`
}

type connectorCredentialListResponse struct {
	SourceID    string                    `json:"source_id"`
	TenantID    string                    `json:"tenant_id"`
	RuntimeID   string                    `json:"runtime_id,omitempty"`
	Credentials []connectorCredentialView `json:"credentials"`
}

type connectorCredentialDetailResponse struct {
	SourceID   string                         `json:"source_id"`
	Credential connectorCredentialView        `json:"credential"`
	Audit      []connectorCredentialAuditView `json:"audit,omitempty"`
}

type connectorCredentialAuditView struct {
	ID           string `json:"id"`
	CredentialID string `json:"credential_id"`
	TenantID     string `json:"tenant_id"`
	SourceID     string `json:"source_id"`
	RuntimeID    string `json:"runtime_id"`
	EventType    string `json:"event_type"`
	Actor        string `json:"actor,omitempty"`
	Status       string `json:"status,omitempty"`
	Detail       string `json:"detail,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

func (a *App) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	view, err := connectorLibraryView(r)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	response := a.connectorLibrary(r, tenantID)
	if view == connectorLibraryViewSummary {
		writeJSON(w, http.StatusOK, summarizeConnectorLibrary(response))
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func connectorLibraryView(r *http.Request) (string, error) {
	if r == nil || r.URL == nil {
		return connectorLibraryViewFull, nil
	}
	view := strings.TrimSpace(r.URL.Query().Get("view"))
	if view == "" {
		return connectorLibraryViewFull, nil
	}
	switch view {
	case connectorLibraryViewFull, connectorLibraryViewSummary:
		return view, nil
	default:
		return "", fmt.Errorf("%w: connector library view must be full or summary", connectorcredentials.ErrInvalidRequest)
	}
}

func summarizeConnectorLibrary(response connectorLibraryResponse) connectorLibrarySummaryResponse {
	summary := connectorLibrarySummaryResponse{
		Connectors:          make([]connectorCatalogSummaryEntry, 0, len(response.Connectors)),
		Counts:              response.Counts,
		GeneratedAt:         response.GeneratedAt,
		View:                connectorLibraryViewSummary,
		TenantID:            response.TenantID,
		RuntimeStore:        response.RuntimeStore,
		CatalogVersion:      response.CatalogVersion,
		CatalogSourceCommit: response.CatalogSourceCommit,
	}
	for _, entry := range response.Connectors {
		summary.Connectors = append(summary.Connectors, summarizeConnectorCatalogEntry(entry))
	}
	return summary
}

func summarizeConnectorCatalogEntry(entry connectorCatalogEntry) connectorCatalogSummaryEntry {
	return connectorCatalogSummaryEntry{
		SourceID:               entry.SourceID,
		DisplayName:            entry.DisplayName,
		Status:                 entry.Status,
		ConfiguredRuntimes:     entry.ConfiguredRuntimes,
		HealthyRuntimes:        entry.HealthyRuntimes,
		NeedsAttentionRuntimes: entry.NeedsAttentionRuntimes,
		CatalogStatus:          entry.CatalogStatus,
		ClassifierOutput:       entry.ClassifierOutput,
		AuthModel:              entry.AuthModel,
		RuntimeExecutable:      entry.RuntimeExecutable,
		CatalogCategories:      append([]string{}, entry.CatalogCategories...),
		DefinitionOrigin:       entry.DefinitionOrigin,
		ReadinessStage:         entry.ReadinessStage,
		ValidationGrade:        entry.ValidationGrade,
		Cataloged:              entry.Cataloged,
		Callable:               entry.Callable,
		AccessStatus:           entry.AccessStatus,
		SetupAllowed:           entry.SetupAllowed,
		Requestable:            entry.Requestable,
		IntegrationLevel:       entry.IntegrationDepth.Level,
		IntegrationScore:       entry.IntegrationDepth.Score,
		ResourceFamilyCount:    entry.IntegrationDepth.ResourceFamilies,
		EmittedKindCount:       entry.IntegrationDepth.EmittedKinds,
		ScopeOptionCount:       entry.IntegrationDepth.ScopeOptions,
	}
}

func (a *App) connectorLibrary(r *http.Request, tenantID string) connectorLibraryResponse {
	runtimes, runtimeStoreStatus := a.connectorRuntimeCatalog(r, tenantID)
	counts := connectorRuntimeCounts(runtimes)
	sources := a.sourceService().List().GetSources()
	transport := connectorTransportView{
		Available: a.connectorTransitKey != nil,
		KeyURL:    "/connectors/credential-key",
	}
	if a.connectorTransitKey != nil {
		transport.Algorithm = a.connectorTransitKey.PublicKey().Algorithm
	}
	vaultStatus := connectorVaultStatus(a.cfg.ConnectorCredentials, a.deps.StateStore)
	stores := connectorStoreViews(vaultStatus, transport, a.cfg.ConnectorSecretStores)
	definitionCatalog := a.connectorDefinitionCatalog()
	definitionsBySourceID := connectorDefinitionCatalogBySourceID(definitionCatalog)
	seen := map[string]struct{}{}
	entries := make([]connectorCatalogEntry, 0, len(sources))
	for _, source := range sources {
		entry := connectorCatalogEntry{
			connectorCatalogIdentity: connectorCatalogIdentity{
				SourceID:    source.GetId(),
				Name:        source.GetName(),
				DisplayName: connectorDisplayName(source.GetId(), source.GetName()),
				Description: source.GetDescription(),
			},
			connectorCatalogDefinitionState: connectorCatalogDefinitionState{
				EmittedKinds:     append([]string{}, source.GetEmittedKinds()...),
				DefinitionOrigin: connectorDefinitionOriginCompiled,
			},
			connectorCatalogRuntimeState: connectorCatalogRuntimeState{
				Status: "available",
			},
			connectorCatalogSetupState: connectorCatalogSetupState{
				ConnectionMethods: connectorConnectionMethods(source.GetId(), stores),
				ScopeOptions:      a.connectorScopeOptions(source.GetId(), source.GetEmittedKinds()),
			},
		}
		if catalogEntry, ok := definitionsBySourceID[source.GetId()]; ok {
			applyConnectorCatalogMetadata(&entry, catalogEntry)
		}
		if !a.applyConnectorAccess(&entry, tenantID) {
			continue
		}
		if count := counts[source.GetId()]; count.total > 0 {
			entry.ConfiguredRuntimes = count.total
			entry.HealthyRuntimes = count.healthy
			entry.NeedsAttentionRuntimes = count.total - count.healthy
			switch {
			case count.healthy == count.total:
				entry.Status = "connected"
			case count.healthy > 0:
				entry.Status = "degraded"
			default:
				entry.Status = "needs_attention"
			}
		}
		entries = append(entries, entry)
		seen[source.GetId()] = struct{}{}
	}
	for _, definition := range a.connectorTenantDefinitions(r.Context(), tenantID) {
		sourceID := strings.TrimSpace(definition.SourceID)
		if sourceID == "" {
			continue
		}
		if _, ok := seen[sourceID]; ok {
			continue
		}
		entry := connectorCatalogEntry{
			connectorCatalogIdentity: connectorCatalogIdentity{
				SourceID:    sourceID,
				Name:        definition.DisplayName,
				DisplayName: connectorDisplayName(sourceID, definition.DisplayName),
				Description: definition.Description,
			},
			connectorCatalogDefinitionState: connectorCatalogDefinitionState{
				AuthModel:             definition.Auth.Model,
				EmittedKinds:          connectorDefinitionEmittedKinds(definition),
				CatalogSchemaVersion:  definition.SchemaVersion,
				CatalogCurrentVersion: definition.CurrentVersion,
				DefinitionOrigin:      connectorDefinitionOriginTenant,
				ResourceFamilies:      connectorDefinitionResourceFamilies(definition),
				ValidationGrade:       string(connectorvalidation.GradeGeneratedFromDocs),
				Cataloged:             true,
			},
			connectorCatalogRuntimeState: connectorCatalogRuntimeState{
				Status: "available",
			},
			connectorCatalogSetupState: connectorCatalogSetupState{
				ScopeOptions: connectorpreview.ScopeOptionsFromDefinition(definition),
			},
		}
		if _, err := sourceregistry.DynamicDefinitionSource(definition); err == nil && definition.Validation.Status != connectordefinitions.ValidationBlocked {
			entry.RuntimeExecutable = true
			entry.ConnectionMethods = connectorConnectionMethodsFromDefinition(definition, stores)
		} else {
			entry.Status = "definition_blocked"
		}
		if !a.applyConnectorAccess(&entry, tenantID) {
			continue
		}
		if count := counts[sourceID]; count.total > 0 {
			entry.ConfiguredRuntimes = count.total
			entry.HealthyRuntimes = count.healthy
			entry.NeedsAttentionRuntimes = count.total - count.healthy
			switch {
			case count.healthy == count.total:
				entry.Status = "connected"
			case count.healthy > 0:
				entry.Status = "degraded"
			default:
				entry.Status = "needs_attention"
			}
		}
		entries = append(entries, entry)
		seen[sourceID] = struct{}{}
	}
	for _, catalogEntry := range definitionCatalog {
		sourceID := catalogEntry.Definition.SourceID
		if _, ok := seen[sourceID]; ok {
			continue
		}
		entry := connectorCatalogEntry{
			connectorCatalogIdentity: connectorCatalogIdentity{
				SourceID:    sourceID,
				Name:        catalogEntry.Definition.DisplayName,
				DisplayName: connectorDisplayName(sourceID, catalogEntry.Definition.DisplayName),
				Description: catalogEntry.Definition.Description,
			},
			connectorCatalogDefinitionState: connectorCatalogDefinitionState{
				EmittedKinds:     connectorDefinitionEmittedKinds(catalogEntry.Definition),
				DefinitionOrigin: connectorDefinitionOriginCatalog,
			},
			connectorCatalogRuntimeState: connectorCatalogRuntimeState{
				Status: catalogEntry.Status,
			},
			connectorCatalogSetupState: connectorCatalogSetupState{
				ScopeOptions: connectorpreview.ScopeOptionsFromDefinition(catalogEntry.Definition),
			},
		}
		applyConnectorCatalogMetadata(&entry, catalogEntry)
		if !a.applyConnectorAccess(&entry, tenantID) {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return connectorLibraryResponse{
		Connectors:          entries,
		Counts:              connectorLibraryCountsFor(entries),
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		TenantID:            tenantID,
		RuntimeStore:        runtimeStoreStatus,
		CatalogVersion:      connectordefinitions.SchemaVersionIntegrationV1,
		CatalogSourceCommit: buildinfo.Commit,
		CredentialTransport: transport,
		CredentialVault:     vaultStatus,
		CredentialStores:    stores,
	}
}

func (a *App) handleGetConnector(w http.ResponseWriter, r *http.Request) {
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	library := a.connectorLibrary(r, tenantID)
	entry, ok := connectorEntryBySourceID(library.Connectors, sourceID)
	if !ok {
		writeConnectorError(w, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, sourceID))
		return
	}
	health := emptySourceRuntimeHealthResponse()
	if a.connectorSourceExistsForTenant(r.Context(), entry.SourceID, tenantID) {
		var err error
		health, err = a.connectorHealthForSource(r, entry.SourceID, tenantID)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
	}
	connections := connectorConnectionsFromHealth(health.Runtimes)
	activity := connectorActivityFromHealth(health.Runtimes)
	timeline := connectordiagnostics.FromHealth(health.Runtimes)
	writeJSON(w, http.StatusOK, connectorDetailResponse{
		GeneratedAt:        health.GeneratedAt,
		TenantID:           tenantID,
		Connector:          entry,
		Summary:            connectorOperationsSummaryFromHealth(entry, health.Runtimes),
		Connections:        connections,
		Activity:           activity,
		DiagnosticTimeline: timeline,
	})
}

func (a *App) handleListConnectorActivity(w http.ResponseWriter, r *http.Request) {
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	library := a.connectorLibrary(r, tenantID)
	entry, ok := connectorEntryBySourceID(library.Connectors, sourceID)
	if !ok {
		writeConnectorError(w, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, sourceID))
		return
	}
	activityLimit, err := connectorActivityLimit(r)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	health := emptySourceRuntimeHealthResponse()
	if a.connectorSourceExistsForTenant(r.Context(), entry.SourceID, tenantID) {
		var err error
		health, err = a.connectorHealthForSource(r, entry.SourceID, tenantID)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
	}
	activity := connectorActivityFromHealth(health.Runtimes)
	timeline := connectordiagnostics.FromHealth(health.Runtimes)
	writeJSON(w, http.StatusOK, connectorActivityResponse{
		GeneratedAt:        health.GeneratedAt,
		TenantID:           tenantID,
		SourceID:           entry.SourceID,
		Activity:           limitConnectorActivity(activity, activityLimit),
		DiagnosticTimeline: timeline,
	})
}

func (a *App) handleConnectorCredentialKey(w http.ResponseWriter, _ *http.Request) {
	if a == nil || a.connectorTransitKey == nil {
		writeConnectorError(w, connectorcredentials.ErrUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.connectorTransitKey.PublicKey())
}

func (a *App) handleCreateConnectorCredential(w http.ResponseWriter, r *http.Request) {
	request := connectorCredentialBrokerRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	if _, err := a.connectorSource(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		writeConnectorError(w, fmt.Errorf("%w: runtime_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if tenantID == "" {
		writeConnectorError(w, fmt.Errorf("%w: tenant_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.authorizeConnectorCredentialRuntime(r.Context(), sourceID, tenantID, runtimeID); err != nil {
		writeConnectorError(w, err)
		return
	}
	credentialStoreID, err := normalizeConnectorCredentialStoreID(request.CredentialStoreID, connectorAuthMethodEncryptedSubmission)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := a.validateConnectorCredentialStoreAvailable(credentialStoreID); err != nil {
		writeConnectorError(w, err)
		return
	}
	broker, err := connectorCredentialBroker(a.cfg.ConnectorCredentials, a.deps.StateStore, a.connectorTransitKey)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	result, err := broker.StoreEncrypted(r.Context(), connectorcredentials.StoreEncryptedRequest{
		TenantID:             tenantID,
		SourceID:             sourceID,
		RuntimeID:            runtimeID,
		CredentialStoreID:    credentialStoreID,
		AuthMethod:           connectorAuthMethodEncryptedSubmission,
		Actor:                connectorCredentialActor(r),
		IdempotencyKey:       connectorCredentialIdempotencyKey(r, request.IdempotencyKey),
		EncryptedCredentials: request.EncryptedCredentials,
		ValidateFields: func(fields map[string]string) error {
			return validateConnectorCredentialFields(sourceID, connectorAuthMethodEncryptedSubmission, fields)
		},
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	status := "stored"
	httpStatus := http.StatusCreated
	if !result.Created {
		status = "existing"
		httpStatus = http.StatusOK
	}
	writeJSON(w, httpStatus, connectorCredentialBrokerResponse{
		SourceID:  sourceID,
		TenantID:  tenantID,
		RuntimeID: runtimeID,
		Status:    status,
		Credential: func() connectorCredentialView {
			return connectorCredentialViewFromRecord(result.Record)
		}(),
		CredentialReferences: result.References,
	})
}

func (a *App) handleListConnectorCredentials(w http.ResponseWriter, r *http.Request) {
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	if _, err := a.connectorSource(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if tenantID == "" {
		writeConnectorError(w, fmt.Errorf("%w: tenant_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	limit, err := connectorQueryInt(r, "limit", 100, 1000)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	broker, err := connectorCredentialBroker(a.cfg.ConnectorCredentials, a.deps.StateStore, a.connectorTransitKey)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	records, err := broker.List(r.Context(), ports.ConnectorCredentialFilter{
		TenantID:  tenantID,
		SourceID:  sourceID,
		RuntimeID: r.URL.Query().Get("runtime_id"),
		Status:    r.URL.Query().Get("status"),
		Limit:     limit,
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	views := make([]connectorCredentialView, 0, len(records))
	for _, record := range records {
		if err := authorizeTenantID(r.Context(), record.TenantID); err != nil {
			writeConnectorError(w, err)
			return
		}
		views = append(views, connectorCredentialViewFromRecord(record))
	}
	writeJSON(w, http.StatusOK, connectorCredentialListResponse{
		SourceID:    sourceID,
		TenantID:    tenantID,
		RuntimeID:   strings.TrimSpace(r.URL.Query().Get("runtime_id")),
		Credentials: views,
	})
}

func (a *App) handleGetConnectorCredential(w http.ResponseWriter, r *http.Request) {
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	credentialID := strings.TrimSpace(r.PathValue("credentialID"))
	if sourceID == "" || credentialID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id and credential_id are required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	if _, err := a.connectorSource(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	broker, err := connectorCredentialBroker(a.cfg.ConnectorCredentials, a.deps.StateStore, a.connectorTransitKey)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	record, err := broker.Get(r.Context(), credentialID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if strings.TrimSpace(record.SourceID) != sourceID {
		writeConnectorError(w, ports.ErrConnectorCredentialNotFound)
		return
	}
	if err := authorizeTenantID(r.Context(), record.TenantID); err != nil {
		writeConnectorError(w, normalizeIDLookupError(err, ports.ErrConnectorCredentialNotFound))
		return
	}
	events, err := broker.AuditEvents(r.Context(), credentialID, 50)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorCredentialDetailResponse{
		SourceID:   sourceID,
		Credential: connectorCredentialViewFromRecord(record),
		Audit:      connectorCredentialAuditViews(events),
	})
}

func (a *App) handleRotateConnectorCredential(w http.ResponseWriter, r *http.Request) {
	request := connectorCredentialRotateRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	credentialID := strings.TrimSpace(r.PathValue("credentialID"))
	if sourceID == "" || credentialID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id and credential_id are required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	if _, err := a.connectorSource(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	broker, err := connectorCredentialBroker(a.cfg.ConnectorCredentials, a.deps.StateStore, a.connectorTransitKey)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	previous, err := broker.Get(r.Context(), credentialID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if strings.TrimSpace(previous.SourceID) != sourceID {
		writeConnectorError(w, ports.ErrConnectorCredentialNotFound)
		return
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(previous.TenantID)
	}
	tenantID, err = effectiveTenantFilter(r.Context(), tenantID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		runtimeID = strings.TrimSpace(previous.RuntimeID)
	}
	if tenantID != strings.TrimSpace(previous.TenantID) || runtimeID != strings.TrimSpace(previous.RuntimeID) {
		writeConnectorError(w, fmt.Errorf("%w: credential rotation must keep the existing tenant and runtime", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.authorizeConnectorCredentialRuntime(r.Context(), sourceID, tenantID, runtimeID); err != nil {
		writeConnectorError(w, err)
		return
	}
	credentialStoreID, err := normalizeConnectorCredentialStoreID(firstNonEmpty(request.CredentialStoreID, previous.CredentialStoreID), connectorAuthMethodEncryptedSubmission)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := a.validateConnectorCredentialStoreAvailable(credentialStoreID); err != nil {
		writeConnectorError(w, err)
		return
	}
	result, err := broker.StoreEncrypted(r.Context(), connectorcredentials.StoreEncryptedRequest{
		TenantID:             tenantID,
		SourceID:             sourceID,
		RuntimeID:            runtimeID,
		CredentialStoreID:    credentialStoreID,
		AuthMethod:           connectorAuthMethodEncryptedSubmission,
		Actor:                connectorCredentialActor(r),
		IdempotencyKey:       connectorCredentialIdempotencyKey(r, request.IdempotencyKey),
		PreviousCredentialID: credentialID,
		EncryptedCredentials: request.EncryptedCredentials,
		ValidateFields: func(fields map[string]string) error {
			return validateConnectorCredentialFields(sourceID, connectorAuthMethodEncryptedSubmission, fields)
		},
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if request.RevokePrevious {
		if _, err := broker.Revoke(r.Context(), connectorcredentials.RevokeRequest{
			CredentialID: credentialID,
			TenantID:     tenantID,
			SourceID:     sourceID,
			RuntimeID:    runtimeID,
			Actor:        connectorCredentialActor(r),
			Detail:       "rotated",
		}); err != nil {
			writeConnectorError(w, err)
			return
		}
	}
	status := "rotated"
	httpStatus := http.StatusCreated
	if !result.Created {
		status = "existing"
		httpStatus = http.StatusOK
	}
	writeJSON(w, httpStatus, connectorCredentialBrokerResponse{
		SourceID:             sourceID,
		TenantID:             tenantID,
		RuntimeID:            runtimeID,
		Status:               status,
		Credential:           connectorCredentialViewFromRecord(result.Record),
		CredentialReferences: result.References,
	})
}

func (a *App) handleRevokeConnectorCredential(w http.ResponseWriter, r *http.Request) {
	request := connectorCredentialRevokeRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	credentialID := strings.TrimSpace(r.PathValue("credentialID"))
	if sourceID == "" || credentialID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id and credential_id are required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	if _, err := a.connectorSource(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	broker, err := connectorCredentialBroker(a.cfg.ConnectorCredentials, a.deps.StateStore, a.connectorTransitKey)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	record, err := broker.Get(r.Context(), credentialID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if strings.TrimSpace(record.SourceID) != sourceID {
		writeConnectorError(w, ports.ErrConnectorCredentialNotFound)
		return
	}
	if err := authorizeTenantID(r.Context(), record.TenantID); err != nil {
		writeConnectorError(w, normalizeIDLookupError(err, ports.ErrConnectorCredentialNotFound))
		return
	}
	updated, err := broker.Revoke(r.Context(), connectorcredentials.RevokeRequest{
		CredentialID: credentialID,
		TenantID:     record.TenantID,
		SourceID:     sourceID,
		RuntimeID:    record.RuntimeID,
		Actor:        connectorCredentialActor(r),
		Detail:       request.Reason,
	})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorCredentialDetailResponse{
		SourceID:   sourceID,
		Credential: connectorCredentialViewFromRecord(updated),
	})
}

func (a *App) handlePreflightConnectorConnection(w http.ResponseWriter, r *http.Request) {
	request := connectorConnectionRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	response, err := a.connectorConnectionPreflight(r.Context(), sourceID, request)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleCreateConnectorConnection(w http.ResponseWriter, r *http.Request) {
	request := connectorConnectionRequest{}
	if err := readConnectorJSON(r, &request); err != nil {
		writeConnectorError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.PathValue("sourceID"))
	if sourceID == "" {
		writeConnectorError(w, fmt.Errorf("%w: source_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if err := a.requireConnectorSetupAccess(sourceID); err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if runtimeID == "" {
		writeConnectorError(w, fmt.Errorf("%w: runtime_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	if tenantID == "" {
		writeConnectorError(w, fmt.Errorf("%w: tenant_id is required", connectorcredentials.ErrInvalidRequest))
		return
	}
	authMethod := normalizeConnectorAuthMethod(request.AuthMethod)
	credentialStoreID, err := normalizeConnectorCredentialStoreID(request.CredentialStoreID, authMethod)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := a.validateConnectorCredentialStoreAvailable(credentialStoreID); err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimeConfig, err := connectorRuntimeConfig(request.Config)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := applyConnectorCredentialReferences(runtimeConfig, request.CredentialReferences); err != nil {
		writeConnectorError(w, err)
		return
	}
	scopePolicy, err := connectorScopePolicy(request.ScopePolicy)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	scopeConfigValue := ""
	if !scopePolicy.Empty() {
		scopeConfigValue, err = resourcescope.ConfigValue(scopePolicy)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		runtimeConfig[resourcescope.ConfigKey] = scopeConfigValue
	}
	if err := validateConnectorConnectionShape(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, runtimeConfig, request.CredentialReferences, request.EncryptedCredentials); err != nil {
		writeConnectorError(w, err)
		return
	}
	runtime := &cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: sourceID,
		TenantId: tenantID,
		Config:   runtimeConfig,
	}
	if err := authorizePutSourceRuntimeTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), runtime); err != nil {
		writeConnectorError(w, err)
		return
	}
	credential := connectorCredentialView{
		TenantID:   tenantID,
		SourceID:   sourceID,
		RuntimeID:  runtimeID,
		StoreID:    credentialStoreID,
		AuthMethod: authMethod,
	}
	var plaintextFields map[string]string
	if authMethod == connectorAuthMethodEncryptedSubmission {
		if a == nil || a.connectorTransitKey == nil {
			writeConnectorError(w, connectorcredentials.ErrUnavailable)
			return
		}
		decrypted, err := a.connectorTransitKey.DecryptWithExactAdditionalData(
			request.EncryptedCredentials,
			connectorCredentialAdditionalData(request.EncryptedCredentials.KeyID, sourceID, tenantID, runtimeID, credentialStoreID),
		)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		fields, err := connectorcredentials.ParseCredentialFields(decrypted)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		if err := validateConnectorCredentialFields(sourceID, authMethod, fields); err != nil {
			writeConnectorError(w, err)
			return
		}
		plaintextFields = fields
		credential.Fields = connectorcredentials.SortedFieldNames(fields)
	} else {
		credential.Fields = sortedStringKeys(request.CredentialReferences)
	}
	if err := a.checkConnectorRuntime(r.Context(), runtime, plaintextFields); err != nil {
		writeConnectorError(w, err)
		return
	}
	if request.CheckOnly {
		runtimePayload, err := connectorRuntimePayload(runtime)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, connectorConnectionResponse{
			SourceID:    sourceID,
			Runtime:     runtimePayload,
			Credential:  credential,
			ScopePolicy: connectorScopePolicyPtr(scopePolicy),
			Status:      "checked",
		})
		return
	}
	if authMethod == connectorAuthMethodEncryptedSubmission {
		broker, err := connectorCredentialBroker(a.cfg.ConnectorCredentials, a.deps.StateStore, a.connectorTransitKey)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		result, err := broker.StoreEncrypted(r.Context(), connectorcredentials.StoreEncryptedRequest{
			TenantID:             tenantID,
			SourceID:             sourceID,
			RuntimeID:            runtimeID,
			CredentialStoreID:    credentialStoreID,
			AuthMethod:           authMethod,
			Actor:                connectorCredentialActor(r),
			EncryptedCredentials: request.EncryptedCredentials,
			ValidateFields: func(fields map[string]string) error {
				return validateConnectorCredentialFields(sourceID, authMethod, fields)
			},
		})
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		validated, err := broker.MarkValidated(r.Context(), connectorcredentials.ValidateRequest{
			CredentialID: result.Record.ID,
			TenantID:     tenantID,
			SourceID:     sourceID,
			RuntimeID:    runtimeID,
			Actor:        connectorCredentialActor(r),
		})
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		result.Record = validated
		for field, reference := range result.References {
			runtime.Config[field] = reference
		}
		credential = connectorCredentialViewFromRecord(result.Record)
	}
	if scopeConfigValue != "" {
		runtime.Config[resourcescope.ConfigKey] = scopeConfigValue
	}
	response, err := a.runtimeService().Put(r.Context(), &cerebrov1.PutSourceRuntimeRequest{Runtime: runtime})
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	runtimePayload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(response.GetRuntime())
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorConnectionResponse{
		SourceID:    sourceID,
		Runtime:     json.RawMessage(runtimePayload),
		Credential:  credential,
		ScopePolicy: connectorScopePolicyPtr(scopePolicy),
	})
}

func (a *App) connectorConnectionPreflight(ctx context.Context, sourceID string, request connectorConnectionRequest) (connectorPreflightResponse, error) {
	sourceID = strings.TrimSpace(sourceID)
	runtimeID := strings.TrimSpace(request.RuntimeID)
	tenantID, tenantErr := effectiveTenantFilter(ctx, request.TenantID)
	response := connectorPreflightResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SourceID:    sourceID,
		RuntimeID:   runtimeID,
		TenantID:    tenantID,
		Status:      "blocked",
		Summary:     "Preflight has not completed.",
		NextAction:  "fix_blocking_checks",
	}
	if tenantErr != nil {
		return response, tenantErr
	}
	response.TenantID = tenantID
	source, err := a.connectorSourceForTenant(ctx, sourceID, tenantID)
	if err != nil {
		return response, err
	}
	response.addPreflightCheck(connectorPreflightCheckView{
		ID:       "source",
		Label:    "Connector source",
		Status:   "passed",
		Severity: "success",
		Detail:   "Source is registered and can run the standard check contract.",
	})
	if runtimeID == "" || tenantID == "" {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "runtime_identity",
			Label:      "Runtime identity",
			Status:     "blocked",
			Severity:   "error",
			Detail:     "Runtime ID and tenant ID are required before preflight can validate access.",
			NextAction: "set_runtime_and_tenant",
			Blocking:   true,
		})
		response.finalizePreflight()
		return response, nil
	}
	response.addPreflightCheck(connectorPreflightCheckView{
		ID:       "runtime_identity",
		Label:    "Runtime identity",
		Status:   "passed",
		Severity: "success",
		Detail:   "Runtime ID and tenant scope are present.",
	})

	authMethod := normalizeConnectorAuthMethod(request.AuthMethod)
	response.AuthMethod = authMethod
	credentialStoreID, credentialStoreIssue := normalizeConnectorCredentialStoreID(request.CredentialStoreID, authMethod)
	if credentialStoreIssue != nil {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "auth_method",
			Label:      "Authentication method",
			Status:     "blocked",
			Severity:   "error",
			Detail:     connectorPreflightValidationDetail(credentialStoreIssue, "Selected authentication method and credential store are not compatible."),
			NextAction: "choose_supported_method",
			Blocking:   true,
		})
		response.finalizePreflight()
		return response, nil
	}
	response.CredentialStoreID = credentialStoreID
	response.addPreflightCheck(connectorPreflightCheckView{
		ID:       "auth_method",
		Label:    "Authentication method",
		Status:   "passed",
		Severity: "success",
		Detail:   "Selected method is supported for this connector.",
	})
	store, storeOK := a.connectorPreflightStore(credentialStoreID)
	if !storeOK || !store.Available {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "credential_store",
			Label:      "Credential store",
			Status:     "blocked",
			Severity:   "error",
			Detail:     "Selected credential store is not available in this deployment.",
			NextAction: "choose_ready_store",
			Blocking:   true,
		})
		response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, nil)
		response.finalizePreflight()
		return response, nil
	}
	response.addPreflightCheck(connectorPreflightCheckView{
		ID:       "credential_store",
		Label:    "Credential store",
		Status:   "passed",
		Severity: "success",
		Detail:   store.Label + " is available.",
	})

	runtimeConfig, configIssue := connectorRuntimeConfig(request.Config)
	if configIssue != nil {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "config_shape",
			Label:      "Config and secret boundary",
			Status:     "blocked",
			Severity:   "error",
			Detail:     connectorPreflightValidationDetail(configIssue, "Runtime config contains unsupported internal or sensitive plaintext fields."),
			NextAction: "fix_config_fields",
			Blocking:   true,
		})
		response.finalizePreflight()
		return response, nil
	}
	if referenceIssue := applyConnectorCredentialReferences(runtimeConfig, request.CredentialReferences); referenceIssue != nil {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "config_shape",
			Label:      "Config and secret boundary",
			Status:     "blocked",
			Severity:   "error",
			Detail:     connectorPreflightValidationDetail(referenceIssue, "Credential references must point to server-resolvable secret references."),
			NextAction: "fix_credential_references",
			Blocking:   true,
		})
		response.finalizePreflight()
		return response, nil
	}
	scopePolicy, scopeIssue := connectorScopePolicy(request.ScopePolicy)
	if scopeIssue != nil {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "scope_policy",
			Label:      "Resource scope policy",
			Status:     "blocked",
			Severity:   "error",
			Detail:     connectorPreflightValidationDetail(scopeIssue, "Resource scope policy is not valid."),
			NextAction: "fix_scope_policy",
			Blocking:   true,
		})
		response.finalizePreflight()
		return response, nil
	}
	response.ScopePreview = a.connectorScopePreview(sourceID, source, scopePolicy)
	response.addPreflightCheck(connectorPreflightScopeCheck(response.ScopePreview))
	if !scopePolicy.Empty() {
		scopeConfigValue, scopeConfigIssue := resourcescope.ConfigValue(scopePolicy)
		if scopeConfigIssue != nil {
			response.addPreflightCheck(connectorPreflightCheckView{
				ID:         "scope_policy",
				Label:      "Resource scope policy",
				Status:     "blocked",
				Severity:   "error",
				Detail:     connectorPreflightValidationDetail(scopeConfigIssue, "Resource scope policy cannot be stored on the runtime."),
				NextAction: "fix_scope_policy",
				Blocking:   true,
			})
			response.finalizePreflight()
			return response, nil
		}
		runtimeConfig[resourcescope.ConfigKey] = scopeConfigValue
	}
	if connectorAuthMethodUsesCredentialReferences(authMethod) && len(request.CredentialReferences) > 0 {
		if referenceScopeIssue := validateConnectorCredentialReferencesForRuntime(credentialStoreID, sourceID, tenantID, runtimeID, request.CredentialReferences); referenceScopeIssue != nil {
			response.addPreflightCheck(connectorPreflightCheckView{
				ID:         "credential_boundary",
				Label:      "Credential boundary",
				Status:     "blocked",
				Severity:   "error",
				Detail:     connectorPreflightValidationDetail(referenceScopeIssue, "Credential references must stay inside the selected runtime secret namespace."),
				NextAction: "fix_credential_references",
				Blocking:   true,
			})
			response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, connectorReferenceTemplateFields(sourceID, authMethod, request.CredentialReferences))
			response.finalizePreflight()
			return response, nil
		}
	}
	if shapeIssue := validateConnectorConnectionShape(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, runtimeConfig, request.CredentialReferences, request.EncryptedCredentials); shapeIssue != nil {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "config_shape",
			Label:      "Config and secret boundary",
			Status:     "blocked",
			Severity:   "error",
			Detail:     connectorPreflightValidationDetail(shapeIssue, "Required config, credentials, or references are missing or unsupported."),
			NextAction: "fix_required_fields",
			Blocking:   true,
		})
		response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, connectorReferenceTemplateFields(sourceID, authMethod, request.CredentialReferences))
		response.finalizePreflight()
		return response, nil
	}
	response.addPreflightCheck(connectorPreflightCheckView{
		ID:       "config_shape",
		Label:    "Config and secret boundary",
		Status:   "passed",
		Severity: "success",
		Detail:   "Config fields match the connector contract and secret material stays out of runtime config.",
	})
	runtime := &cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: sourceID,
		TenantId: tenantID,
		Config:   runtimeConfig,
	}
	if err := authorizePutSourceRuntimeTenant(ctx, sourceRuntimeStore(a.deps.StateStore), runtime); err != nil {
		return response, err
	}
	plaintextFields := map[string]string(nil)
	fieldNames := connectorReferenceTemplateFields(sourceID, authMethod, request.CredentialReferences)
	if authMethod == connectorAuthMethodEncryptedSubmission {
		if a == nil || a.connectorTransitKey == nil {
			response.addPreflightCheck(connectorPreflightCheckView{
				ID:         "credential_transport",
				Label:      "Credential encryption",
				Status:     "blocked",
				Severity:   "error",
				Detail:     "Credential transit key is unavailable.",
				NextAction: "configure_credential_transport",
				Blocking:   true,
			})
			response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, nil)
			response.finalizePreflight()
			return response, nil
		}
		decrypted, decryptIssue := a.connectorTransitKey.DecryptWithExactAdditionalData(
			request.EncryptedCredentials,
			connectorCredentialAdditionalData(request.EncryptedCredentials.KeyID, sourceID, tenantID, runtimeID, credentialStoreID),
		)
		if decryptIssue != nil {
			response.addPreflightCheck(connectorPreflightCredentialCheck(connectorPreflightValidationDetail(decryptIssue, "Encrypted credential payload could not be opened."), "fix_encrypted_payload"))
			response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, nil)
			response.finalizePreflight()
			return response, nil
		}
		fields, parseIssue := connectorcredentials.ParseCredentialFields(decrypted)
		if parseIssue != nil {
			response.addPreflightCheck(connectorPreflightCredentialCheck(connectorPreflightValidationDetail(parseIssue, "Encrypted credential payload is not a valid credential field map."), "fix_encrypted_payload"))
			response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, nil)
			response.finalizePreflight()
			return response, nil
		}
		if credentialIssue := validateConnectorCredentialFields(sourceID, authMethod, fields); credentialIssue != nil {
			response.addPreflightCheck(connectorPreflightCredentialCheck(connectorPreflightValidationDetail(credentialIssue, "Credential fields do not match the connector contract."), "fix_credential_fields"))
			response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, connectorcredentials.SortedFieldNames(fields))
			response.finalizePreflight()
			return response, nil
		}
		plaintextFields = fields
		fieldNames = connectorcredentials.SortedFieldNames(fields)
	}
	response.CredentialBoundary = a.connectorPreflightCredentialBoundary(sourceID, tenantID, runtimeID, authMethod, credentialStoreID, fieldNames)
	response.addPreflightCheck(connectorPreflightCredentialPassed(authMethod))
	for _, check := range connectorProviderPreflightChecks(sourceID, authMethod, runtimeConfig, scopePolicy) {
		response.addPreflightCheck(check)
	}
	if sourceCheckIssue := a.checkConnectorRuntime(ctx, runtime, plaintextFields); sourceCheckIssue != nil {
		response.addPreflightCheck(connectorPreflightCheckView{
			ID:         "source_check",
			Label:      "Source validation",
			Status:     "blocked",
			Severity:   "error",
			Detail:     connectorPreflightErrorDetail(sourceCheckIssue),
			NextAction: "fix_source_access",
			Blocking:   true,
		})
		response.finalizePreflight()
		return response, nil
	}
	response.addPreflightCheck(connectorPreflightCheckView{
		ID:       "source_check",
		Label:    "Source validation",
		Status:   "passed",
		Severity: "success",
		Detail:   "Source check passed with the resolved runtime configuration.",
	})
	response.finalizePreflight()
	return response, nil
}

func (a *App) connectorRuntimeCatalog(r *http.Request, tenantID string) ([]*cerebrov1.SourceRuntime, string) {
	if a == nil || sourceRuntimeStore(a.deps.StateStore) == nil {
		return nil, "unavailable"
	}
	runtimes, err := a.runtimeService().List(r.Context(), ports.SourceRuntimeFilter{TenantID: tenantID, Limit: 500})
	if err != nil {
		return nil, "unavailable"
	}
	return runtimes, "ready"
}

type connectorRuntimeCount struct {
	total   int
	healthy int
}

type connectorSchema struct {
	ConfigKeys          map[string]struct{}
	CredentialKeys      map[string]struct{}
	RequiredConfig      []string
	RequiredCredentials []string
}

var connectorSchemas = map[string]connectorSchema{
	"anthropic": {
		ConfigKeys: stringSet(
			"activity_types",
			"actor_ids",
			"api_key_ids",
			"auth_model",
			"bucket_width",
			"context_windows",
			"created_at_gt",
			"created_at_gte",
			"created_at_lt",
			"created_at_lte",
			"credential_kind",
			"credential_scopes",
			"ending_at",
			"family",
			"group_id",
			"group_by",
			"include_archived",
			"inference_geos",
			"model",
			"models",
			"organization_uuid",
			"organization_ids",
			"per_page",
			"periods",
			"project_id",
			"role_id",
			"service_tiers",
			"speeds",
			"starting_at",
			"status",
			"terminal_types",
			"user_ids",
			"workspace_id",
			"workspace_ids",
		),
		CredentialKeys:      stringSet("api_key", "token"),
		RequiredCredentials: []string{"api_key"},
	},
	"aws": {
		ConfigKeys:          stringSet("account_id", "region", "family", "include_global", "role_arn", "external_id"),
		CredentialKeys:      stringSet("access_key_id", "secret_access_key", "session_token"),
		RequiredConfig:      []string{"account_id"},
		RequiredCredentials: []string{"access_key_id", "secret_access_key"},
	},
	"gcp": {
		ConfigKeys:     stringSet("project_id", "family", "wif_audience", "wif_service_account_email", "customer_id", "group_key", "service_account_email"),
		CredentialKeys: stringSet("token"),
		RequiredConfig: []string{"project_id"},
	},
	"github": {
		ConfigKeys:          stringSet("owner", "repo", "family", "phrase"),
		CredentialKeys:      stringSet("token"),
		RequiredCredentials: []string{"token"},
	},
	"google_workspace": {
		ConfigKeys:     stringSet("domain", "family", "customer_id", "group_key", "service_account_email", "delegated_admin_email", "subject_email", "client_id"),
		CredentialKeys: stringSet("token", "private_key", "service_account_private_key", "client_secret", "refresh_token"),
		RequiredConfig: []string{"domain"},
	},
	"okta": {
		ConfigKeys:          stringSet("domain", "family"),
		CredentialKeys:      stringSet("token"),
		RequiredConfig:      []string{"domain"},
		RequiredCredentials: []string{"token"},
	},
	"openai": {
		ConfigKeys: stringSet(
			"actor_emails",
			"actor_ids",
			"api_key_ids",
			"base_url",
			"batch",
			"bucket_width",
			"credential_kind",
			"credential_scopes",
			"effective_at_gt",
			"effective_at_gte",
			"effective_at_lt",
			"effective_at_lte",
			"end_time",
			"event_types",
			"family",
			"group_by",
			"group_id",
			"models",
			"per_page",
			"project_id",
			"project_ids",
			"start_time",
			"user_id",
			"user_ids",
		),
		CredentialKeys:      stringSet("api_key", "token"),
		RequiredCredentials: []string{"api_key"},
	},
	"bootstrap_token": {
		ConfigKeys:          stringSet("family"),
		CredentialKeys:      stringSet("token"),
		RequiredCredentials: []string{"token"},
	},
}

func connectorSchemaForSource(sourceID string) (connectorSchema, bool) {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return connectorSchema{}, false
	}
	if schema, ok := connectorSchemas[sourceID]; ok {
		return schema, true
	}
	entry, ok, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil || !ok || !sourceregistry.EntryRuntimeExecutable(entry) {
		return connectorSchema{}, false
	}
	return connectorSchemaFromDefinition(entry.Definition), true
}

func connectorSchemaFromDefinition(definition connectordefinitions.Definition) connectorSchema {
	schema := connectorSchema{
		ConfigKeys:     stringSet("family", "health_path", "base_url", "failure_modes", "expected_cadence_seconds", "stale_after_seconds"),
		CredentialKeys: map[string]struct{}{},
	}
	for _, field := range definition.ConfigFields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			continue
		}
		schema.ConfigKeys[key] = struct{}{}
		if field.Required {
			schema.RequiredConfig = append(schema.RequiredConfig, key)
		}
	}
	for _, field := range definition.Auth.CredentialFields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			continue
		}
		schema.CredentialKeys[key] = struct{}{}
		schema.RequiredCredentials = append(schema.RequiredCredentials, key)
	}
	for _, family := range definition.ResourceFamilies {
		if family.Pagination == nil {
			continue
		}
		addConnectorSchemaConfigKey(schema.ConfigKeys, family.Pagination.PageParam)
		addConnectorSchemaConfigKey(schema.ConfigKeys, family.Pagination.PageSizeParam)
		addConnectorSchemaConfigKey(schema.ConfigKeys, family.Pagination.OffsetParam)
		addConnectorSchemaConfigKey(schema.ConfigKeys, family.Pagination.LimitParam)
		addConnectorSchemaConfigKey(schema.ConfigKeys, family.Pagination.CursorParam)
	}
	schema.RequiredConfig = sortedUniqueStrings(schema.RequiredConfig)
	schema.RequiredCredentials = sortedUniqueStrings(schema.RequiredCredentials)
	return schema
}

func addConnectorSchemaConfigKey(keys map[string]struct{}, key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	keys[key] = struct{}{}
}

func connectorRuntimeCounts(runtimes []*cerebrov1.SourceRuntime) map[string]connectorRuntimeCount {
	counts := make(map[string]connectorRuntimeCount)
	for _, runtime := range runtimes {
		sourceID := strings.TrimSpace(runtime.GetSourceId())
		if sourceID == "" {
			continue
		}
		count := counts[sourceID]
		count.total++
		if connectorRuntimeHealthy(runtime) {
			count.healthy++
		}
		counts[sourceID] = count
	}
	return counts
}

func connectorEntryBySourceID(entries []connectorCatalogEntry, sourceID string) (connectorCatalogEntry, bool) {
	normalized := strings.TrimSpace(sourceID)
	for _, entry := range entries {
		if entry.SourceID == normalized {
			return entry, true
		}
	}
	return connectorCatalogEntry{}, false
}

func (a *App) connectorDefinitionCatalog() []connectorcatalog.Entry {
	if a == nil || a.sources == nil || !a.sources.IncludesBuiltinDefinitionCatalog() {
		return nil
	}
	analysis, err := connectorcatalog.Builtin()
	if err != nil {
		return nil
	}
	return analysis.Entries
}

func connectorDefinitionCatalogBySourceID(entries []connectorcatalog.Entry) map[string]connectorcatalog.Entry {
	out := make(map[string]connectorcatalog.Entry, len(entries))
	for _, entry := range entries {
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if sourceID == "" {
			continue
		}
		out[sourceID] = entry
	}
	return out
}

func applyConnectorCatalogMetadata(entry *connectorCatalogEntry, catalogEntry connectorcatalog.Entry) {
	if entry == nil {
		return
	}
	entry.CatalogStatus = catalogEntry.Status
	entry.ClassifierOutput = catalogEntry.ClassifierOutput
	entry.AuthModel = catalogEntry.Definition.Auth.Model
	entry.RuntimeExecutable = sourceregistry.EntryRuntimeExecutable(catalogEntry)
	entry.ValidationGrade = string(connectorvalidation.BuiltinValidationForSource(catalogEntry.Definition.SourceID).Grade)
	entry.Cataloged = true
	entry.CatalogSchemaVersion = catalogEntry.Definition.SchemaVersion
	entry.CatalogCurrentVersion = catalogEntry.Definition.CurrentVersion
	entry.CatalogSourcePath = catalogEntry.Path
	entry.MissingFeatures = append([]string{}, catalogEntry.Report.MissingFeatures...)
	entry.CatalogCategories = append([]string{}, catalogEntry.Definition.Categories...)
	entry.VerificationEndpoint = catalogEntry.VerificationPath
	entry.ResourceFamilies = connectorDefinitionResourceFamilies(catalogEntry.Definition)
	if entry.Description == "" {
		entry.Description = catalogEntry.Definition.Description
	}
	if entry.Name == "" {
		entry.Name = catalogEntry.Definition.DisplayName
	}
	if entry.DisplayName == "" {
		entry.DisplayName = connectorDisplayName(catalogEntry.Definition.SourceID, catalogEntry.Definition.DisplayName)
	}
	if len(entry.EmittedKinds) == 0 {
		entry.EmittedKinds = connectorDefinitionEmittedKinds(catalogEntry.Definition)
	}
	if len(entry.ScopeOptions) == 0 {
		entry.ScopeOptions = connectorpreview.ScopeOptionsFromDefinition(catalogEntry.Definition)
	}
}

func (a *App) applyConnectorAccess(entry *connectorCatalogEntry, tenantID string) bool {
	if entry == nil {
		return false
	}
	sourceID := strings.TrimSpace(entry.SourceID)
	if sourceID == "" || connectorSourceListed(a.cfg.ConnectorAccess.HiddenSources, sourceID) {
		return false
	}
	hasSetup := len(entry.ConnectionMethods) > 0
	switch {
	case connectorSourceListed(a.cfg.ConnectorAccess.RestrictedSources, sourceID):
		entry.AccessStatus = connectorAccessRestricted
		entry.AccessReason = firstNonEmpty(a.cfg.ConnectorAccess.RestrictionReason, "Connector setup is restricted by this deployment.")
		entry.SetupAllowed = false
		entry.Requestable = true
		entry.RequestableReason = entry.AccessReason
		entry.ConnectionMethods = nil
	case hasSetup:
		entry.AccessStatus = connectorAccessAvailable
		entry.SetupAllowed = true
	case entry.CatalogStatus != "":
		entry.AccessStatus = connectorAccessCatalogOnly
		entry.AccessReason = connectorCatalogOnlyReason(entry.CatalogStatus)
		entry.SetupAllowed = false
		entry.Requestable = true
		entry.RequestableReason = entry.AccessReason
	default:
		entry.AccessStatus = connectorAccessAvailable
		entry.SetupAllowed = hasSetup
	}
	if entry.Requestable {
		entry.RequestAccessAction = connectorRequestAccessAction(a.cfg.ConnectorAccess.RequestAccessAction, entry)
		entry.RequestAccessURL = connectorRequestAccessURL(a.cfg.ConnectorAccess.RequestAccessURL, entry, tenantID)
	}
	entry.ReadinessStage = connectorReadinessStage(*entry)
	entry.Callable = entry.RuntimeExecutable && strings.TrimSpace(entry.AuthModel) != "" &&
		connectorvalidation.GradeAtLeast(connectorvalidation.Grade(entry.ValidationGrade), connectorvalidation.GradeFixtureValidated)
	entry.IntegrationDepth = connectorIntegrationDepth(*entry)
	return true
}

func connectorLibraryCountsFor(entries []connectorCatalogEntry) connectorLibraryCounts {
	counts := connectorLibraryCounts{Total: len(entries)}
	for _, entry := range entries {
		if entry.Cataloged {
			counts.Cataloged++
		}
		if entry.Callable {
			counts.Callable++
		}
		if entry.AccessStatus == connectorAccessCatalogOnly {
			counts.CatalogOnly++
		}
		if entry.SetupAllowed {
			counts.SetupEnabled++
		}
	}
	return counts
}

func (a *App) requireConnectorSetupAccess(sourceID string) error {
	if connectorSourceListed(a.cfg.ConnectorAccess.HiddenSources, sourceID) {
		return fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, strings.TrimSpace(sourceID))
	}
	if connectorSourceListed(a.cfg.ConnectorAccess.RestrictedSources, sourceID) {
		return fmt.Errorf("%w: %s", errConnectorAccessRestricted, strings.TrimSpace(sourceID))
	}
	return nil
}

func connectorSourceListed(values []string, sourceID string) bool {
	normalized := strings.TrimSpace(sourceID)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), normalized) {
			return true
		}
	}
	return false
}

func connectorCatalogOnlyReason(status string) string {
	switch strings.TrimSpace(status) {
	case connectorcatalog.StatusGenerateable:
		return "Catalog definition is sourcegen-ready, but setup is not enabled by this API."
	case connectorcatalog.StatusNeedsAuthExtension:
		return "Catalog definition needs an auth extension before setup can be enabled."
	case connectorcatalog.StatusNeedsBespokeRuntime:
		return "Catalog definition needs a bespoke runtime before setup can be enabled."
	case connectorcatalog.StatusCatalogReady:
		return "Catalog definition is available, but setup is not enabled by this API."
	default:
		return "Catalog metadata is available, but setup is not enabled by this API."
	}
}

func connectorRequestAccessAction(configured string, entry *connectorCatalogEntry) string {
	if action := strings.TrimSpace(configured); action != "" {
		return action
	}
	if entry != nil && entry.AccessStatus == connectorAccessCatalogOnly {
		return "Request connector"
	}
	return "Request access"
}

func connectorRequestAccessURL(template string, entry *connectorCatalogEntry, tenantID string) string {
	template = strings.TrimSpace(template)
	if template == "" || entry == nil {
		return ""
	}
	replacements := map[string]string{
		"{source_id}":    url.QueryEscape(strings.TrimSpace(entry.SourceID)),
		"{tenant_id}":    url.QueryEscape(strings.TrimSpace(tenantID)),
		"{display_name}": url.QueryEscape(strings.TrimSpace(firstNonEmpty(entry.DisplayName, entry.Name, entry.SourceID))),
	}
	out := template
	for token, value := range replacements {
		out = strings.ReplaceAll(out, token, value)
	}
	return out
}

func connectorReadinessStage(entry connectorCatalogEntry) string {
	switch {
	case entry.SetupAllowed:
		return connectorReadinessStageSetupEnabled
	case entry.AccessStatus == connectorAccessRestricted:
		return connectorReadinessStageAPIRestricted
	case entry.RuntimeExecutable && entry.CatalogStatus == connectorcatalog.StatusNeedsBespokeRuntime:
		return connectorReadinessStageRuntimeBacked
	case entry.CatalogStatus == connectorcatalog.StatusGenerateable:
		return connectorReadinessStageSourcegenReady
	case entry.CatalogStatus == connectorcatalog.StatusNeedsAuthExtension:
		return connectorReadinessStageAuthExtensionNeeded
	case entry.CatalogStatus == connectorcatalog.StatusNeedsBespokeRuntime:
		return connectorReadinessStageRuntimeNeeded
	case entry.CatalogStatus == connectorcatalog.StatusCatalogReady:
		return connectorReadinessStageCatalogReady
	case entry.RuntimeExecutable:
		return connectorReadinessStageSourcegenReady
	default:
		return connectorReadinessStageRuntimeUnknown
	}
}

func connectorIntegrationDepth(entry connectorCatalogEntry) connectorIntegrationDepthView {
	depth := connectorIntegrationDepthView{
		AuthModel:          strings.TrimSpace(entry.AuthModel),
		ResourceFamilies:   len(entry.ResourceFamilies),
		EmittedKinds:       len(entry.EmittedKinds),
		ScopeOptions:       len(entry.ScopeOptions),
		RuntimeExecutable:  entry.RuntimeExecutable,
		SetupEnabled:       entry.SetupAllowed,
		CoverageDimensions: 0,
	}
	for _, family := range entry.ResourceFamilies {
		depth.CoverageDimensions += len(family.Coverage)
		if family.HighValue {
			depth.HighValueFamilies++
		}
		if strings.TrimSpace(family.ProjectionTemplate) != "" {
			depth.ProjectionTemplates++
		}
	}
	score := 0
	score += minInt(depth.ResourceFamilies, 4) * 10
	score += minInt(depth.CoverageDimensions, 8) * 3
	score += minInt(depth.HighValueFamilies, 4) * 5
	score += minInt(depth.ProjectionTemplates, 4) * 4
	if depth.AuthModel != "" {
		score += 8
	}
	if depth.RuntimeExecutable {
		score += 12
	}
	if depth.SetupEnabled {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	depth.Score = score
	switch {
	case score >= 80:
		depth.Level = "deep"
	case score >= 50:
		depth.Level = "ready"
	case score >= 25:
		depth.Level = "cataloged"
	default:
		depth.Level = "basic"
	}
	return depth
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func connectorDefinitionEmittedKinds(definition connectordefinitions.Definition) []string {
	kinds := make([]string, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		kind := strings.TrimSpace(family.Event.Kind)
		if kind == "" {
			continue
		}
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

func connectorDefinitionResourceFamilies(definition connectordefinitions.Definition) []connectorResourceFamilyView {
	families := make([]connectorResourceFamilyView, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		view := connectorResourceFamilyView{
			ID:                 family.ID,
			Label:              firstNonEmpty(family.Label, connectorFieldLabel(family.ID)),
			Path:               family.Path,
			EventKind:          family.Event.Kind,
			SchemaRef:          family.Event.SchemaRef,
			ProjectionTemplate: connectorProjectionTemplate(family),
		}
		for _, dimension := range family.Coverage {
			if dimension.Type != "" {
				view.Coverage = append(view.Coverage, dimension.Type)
			}
			if dimension.HighValue {
				view.HighValue = true
			}
		}
		sort.Strings(view.Coverage)
		families = append(families, view)
	}
	sort.Slice(families, func(i, j int) bool { return families[i].ID < families[j].ID })
	return families
}

func connectorProjectionTemplate(family connectordefinitions.ResourceFamily) string {
	if family.Projection == nil {
		return ""
	}
	return strings.TrimSpace(family.Projection.Template)
}

func (a *App) connectorSourceExists(sourceID string) bool {
	if a == nil || a.sources == nil {
		return false
	}
	_, ok := a.sources.Get(strings.TrimSpace(sourceID))
	return ok
}

func (a *App) connectorScopeOptions(sourceID string, emittedKinds []string) []connectorScopeOptionView {
	sourceID = strings.TrimSpace(sourceID)
	if a != nil && a.sources != nil {
		if source, ok := a.sources.Get(sourceID); ok {
			if provider, ok := source.(sourcecdk.CoverageContractProvider); ok {
				options := connectorpreview.ScopeOptionsFromCoverage(provider.CoverageContract())
				if len(options) > 0 {
					return options
				}
			}
		}
	}
	return connectorpreview.ScopeOptionsFromKinds(emittedKinds)
}

func connectorScopePolicy(policy resourcescope.Policy) (resourcescope.Policy, error) {
	normalized, err := resourcescope.Normalize(policy)
	if err != nil {
		return resourcescope.Policy{}, fmt.Errorf("%w: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	return normalized, nil
}

func connectorScopePolicyPtr(policy resourcescope.Policy) *resourcescope.Policy {
	if policy.Empty() {
		return nil
	}
	cloned := policy
	return &cloned
}

func (r *connectorPreflightResponse) addPreflightCheck(check connectorPreflightCheckView) {
	if check.Status == "" {
		check.Status = "passed"
	}
	if check.Severity == "" {
		switch check.Status {
		case "blocked":
			check.Severity = "error"
		case "warning":
			check.Severity = "warning"
		default:
			check.Severity = "info"
		}
	}
	if check.Status == "blocked" {
		check.Blocking = true
	}
	r.Checks = append(r.Checks, check)
}

func (r *connectorPreflightResponse) finalizePreflight() {
	blocked := 0
	warnings := 0
	for _, check := range r.Checks {
		switch check.Status {
		case "blocked":
			blocked++
		case "warning":
			warnings++
		}
	}
	switch {
	case blocked > 0:
		r.Status = "blocked"
		r.Summary = "Preflight found blocking setup issues."
		r.NextAction = "fix_blocking_checks"
	case warnings > 0:
		r.Status = "warning"
		r.Summary = "Preflight passed with warnings to review."
		r.NextAction = "review_warnings_then_save"
	default:
		r.Status = "ready"
		r.Summary = "Preflight passed. This connection is ready to save."
		r.NextAction = "save_connection"
	}
	r.DiagnosticTimeline = connectordiagnostics.FromPreflight(connectordiagnostics.Preflight{
		GeneratedAt: r.GeneratedAt,
		SourceID:    r.SourceID,
		RuntimeID:   r.RuntimeID,
		TenantID:    r.TenantID,
		Status:      r.Status,
		Summary:     r.Summary,
		NextAction:  r.NextAction,
		Checks:      connectorPreflightDiagnosticChecks(r.Checks),
	})
}

func connectorPreflightDiagnosticChecks(checks []connectorPreflightCheckView) []connectordiagnostics.PreflightCheck {
	diagnostics := make([]connectordiagnostics.PreflightCheck, 0, len(checks))
	for _, check := range checks {
		diagnostics = append(diagnostics, connectordiagnostics.PreflightCheck{
			ID:         check.ID,
			Label:      check.Label,
			Status:     check.Status,
			Detail:     check.Detail,
			NextAction: check.NextAction,
		})
	}
	return diagnostics
}

func (a *App) connectorPreflightStore(storeID string) (connectorStoreView, bool) {
	transport := connectorTransportView{Available: a != nil && a.connectorTransitKey != nil}
	if a != nil && a.connectorTransitKey != nil {
		transport.Algorithm = a.connectorTransitKey.PublicKey().Algorithm
		transport.KeyURL = "/connectors/credential-key"
	}
	vaultStatus := connectorVaultStatus(config.ConnectorCredentialConfig{}, nil)
	if a != nil {
		vaultStatus = connectorVaultStatus(a.cfg.ConnectorCredentials, a.deps.StateStore)
	}
	secretStoreConfig := config.ConnectorSecretStoreConfig{}
	if a != nil {
		secretStoreConfig = a.cfg.ConnectorSecretStores
	}
	for _, store := range connectorStoreViews(vaultStatus, transport, secretStoreConfig) {
		if store.ID == strings.TrimSpace(storeID) {
			return store, true
		}
	}
	return connectorStoreView{}, false
}

func (a *App) validateConnectorCredentialStoreAvailable(storeID string) error {
	store, ok := a.connectorPreflightStore(storeID)
	if !ok {
		return fmt.Errorf("%w: credential store %q is not supported", connectorcredentials.ErrInvalidRequest, strings.TrimSpace(storeID))
	}
	if !store.Available {
		if strings.TrimSpace(storeID) == defaultConnectorCredentialStoreID {
			return fmt.Errorf("%w: credential store %q is not available in this deployment", connectorcredentials.ErrUnavailable, strings.TrimSpace(storeID))
		}
		return fmt.Errorf("%w: credential store %q is not available in this deployment", connectorcredentials.ErrInvalidRequest, strings.TrimSpace(storeID))
	}
	return nil
}

func (a *App) connectorScopePreview(sourceID string, source sourcecdk.Source, policy resourcescope.Policy) connectorScopePreviewView {
	kinds := []string{}
	if source != nil && source.Spec() != nil {
		kinds = source.Spec().GetEmittedKinds()
	}
	options := a.connectorScopeOptions(sourceID, kinds)
	disabled := 0
	for _, option := range options {
		for _, family := range option.Families {
			if connectorScopePreviewFamilyExcluded(sourceID, family, policy) {
				disabled++
				break
			}
		}
	}
	preview := connectorScopePreviewView{
		AvailableResourceTypes: len(options),
		DisabledResourceTypes:  disabled,
		EnabledResourceTypes:   len(options) - disabled,
		ExactResourceCount:     len(policy.ExcludedResourceURNs) + len(policy.ExcludedResources),
	}
	if !policy.Empty() {
		preview.Mode = resourcescope.ModeExclude
		preview.ExcludedFamilies = append([]string{}, policy.ExcludedFamilies...)
	}
	return preview
}

func connectorScopePreviewFamilyExcluded(sourceID string, family string, policy resourcescope.Policy) bool {
	if policy.ExcludesFamily(sourceID, family) {
		return true
	}
	normalized := strings.ToLower(strings.TrimSpace(family))
	for _, values := range [][]string{policy.ExcludedFamilies, policy.ExcludedAssetClasses, policy.ExcludedKinds} {
		for _, value := range values {
			if strings.EqualFold(value, normalized) {
				return true
			}
		}
	}
	return false
}

func connectorPreflightScopeCheck(preview connectorScopePreviewView) connectorPreflightCheckView {
	if preview.DisabledResourceTypes == 0 && preview.ExactResourceCount == 0 {
		return connectorPreflightCheckView{
			ID:       "scope_policy",
			Label:    "Resource scope policy",
			Status:   "passed",
			Severity: "success",
			Detail:   "All advertised resource types remain in scope.",
		}
	}
	return connectorPreflightCheckView{
		ID:       "scope_policy",
		Label:    "Resource scope policy",
		Status:   "warning",
		Severity: "warning",
		Detail:   "Some resource types or exact resources are excluded before collection or projection.",
	}
}

func (a *App) connectorPreflightCredentialBoundary(sourceID string, tenantID string, runtimeID string, authMethod string, storeID string, fields []string) connectorCredentialBoundaryView {
	authMethod = normalizeConnectorAuthMethod(authMethod)
	storeID = strings.TrimSpace(storeID)
	boundary := connectorCredentialBoundaryView{
		Mode:           authMethod,
		StoreID:        storeID,
		SendsSecrets:   authMethod == connectorAuthMethodEncryptedSubmission,
		ReferenceOnly:  authMethod != connectorAuthMethodEncryptedSubmission,
		FieldsAccepted: append([]string{}, fields...),
	}
	if store, ok := a.connectorPreflightStore(storeID); ok {
		boundary.StoreStatus = store.Status
		boundary.StoreDetail = store.Detail
		boundary.ReferencePrefixes = append([]string{}, store.ReferencePrefixes...)
		boundary.NativeResolutionAvailable = store.NativeResolutionAvailable
	}
	if boundary.ReferenceOnly {
		if len(boundary.ReferencePrefixes) == 0 {
			boundary.ReferencePrefixes = connectorsecretstores.ReferencePrefixes(storeID)
		}
		boundary.ReferenceNamespace = a.connectorReferenceNamespace(storeID, tenantID, sourceID, runtimeID)
		boundary.ReferenceTemplates = a.connectorReferenceTemplates(sourceID, tenantID, runtimeID, storeID, fields)
	}
	return boundary
}

func (a *App) connectorReferenceTemplates(sourceID string, tenantID string, runtimeID string, storeID string, fields []string) []connectorReferenceTemplateView {
	if len(fields) == 0 {
		return nil
	}
	required := map[string]struct{}{}
	if schema, ok := connectorSchemaForSource(sourceID); ok {
		required = stringSet(schema.RequiredCredentials...)
	}
	templates := make([]connectorReferenceTemplateView, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		templates = append(templates, connectorReferenceTemplateView{
			Field:       field,
			Label:       connectorFieldLabel(field),
			Required:    setContains(required, field),
			Reference:   a.connectorReferenceForField(storeID, tenantID, sourceID, runtimeID, field),
			Description: a.connectorReferenceTemplateDescription(storeID),
		})
	}
	return templates
}

func (a *App) connectorReferenceForField(storeID string, tenantID string, sourceID string, runtimeID string, field string) string {
	switch strings.TrimSpace(storeID) {
	case connectorStoreAWSSecretsManager:
		if !connectorsecretstores.NativeResolutionAvailable(a.cfg.ConnectorSecretStores, storeID) {
			return "env:" + connectorSuggestedEnvName(sourceID, field)
		}
		namespace := a.connectorReferenceNamespace(storeID, tenantID, sourceID, runtimeID)
		if namespace == "" {
			namespace = connectorStoreReferenceNamespaceTemplate(storeID, true)
		}
		region := strings.TrimSpace(a.cfg.ConnectorSecretStores.AWSSecretsManager.Region)
		return "aws-sm:" + region + ":" + namespace + "#" + strings.TrimSpace(field)
	default:
		return "env:" + connectorSuggestedEnvName(sourceID, field)
	}
}

func (a *App) connectorReferenceNamespace(storeID string, tenantID string, sourceID string, runtimeID string) string {
	switch strings.TrimSpace(storeID) {
	case connectorStoreAWSSecretsManager:
		if connectorsecretstores.NativeResolutionAvailable(a.cfg.ConnectorSecretStores, storeID) {
			return connectorsecretstores.RuntimeCredentialSecretName(tenantID, sourceID, runtimeID)
		}
		return "CEREBRO_SOURCE_" + connectorEnvComponent(sourceID) + "_*"
	case connectorStoreEnvironmentManaged, connectorStoreInfisical, connectorStoreGoogleSecretMgr, connectorStoreAzureKeyVault, connectorStoreHashiCorpVault:
		return "CEREBRO_SOURCE_" + connectorEnvComponent(sourceID) + "_*"
	default:
		return ""
	}
}

func (a *App) connectorReferenceTemplateDescription(storeID string) string {
	switch strings.TrimSpace(storeID) {
	case connectorStoreAWSSecretsManager:
		if !connectorsecretstores.NativeResolutionAvailable(a.cfg.ConnectorSecretStores, storeID) {
			return "Environment projection reference resolved inside the Cerebro backend runtime."
		}
		return "Scoped to this tenant, source, and runtime; unscoped aws-sm references are rejected before resolution."
	default:
		return "Environment projection reference resolved inside the Cerebro backend runtime."
	}
}

func connectorPreflightCredentialCheck(detail string, nextAction string) connectorPreflightCheckView {
	return connectorPreflightCheckView{
		ID:         "credential_boundary",
		Label:      "Credential boundary",
		Status:     "blocked",
		Severity:   "error",
		Detail:     detail,
		NextAction: nextAction,
		Blocking:   true,
	}
}

func connectorPreflightCredentialPassed(authMethod string) connectorPreflightCheckView {
	if normalizeConnectorAuthMethod(authMethod) == connectorAuthMethodEncryptedSubmission {
		return connectorPreflightCheckView{
			ID:       "credential_boundary",
			Label:    "Credential boundary",
			Status:   "passed",
			Severity: "success",
			Detail:   "Encrypted credential payload opened successfully and will not be returned by connector reads.",
		}
	}
	return connectorPreflightCheckView{
		ID:       "credential_boundary",
		Label:    "Credential boundary",
		Status:   "passed",
		Severity: "success",
		Detail:   "Only server-resolvable credential references are submitted for this method.",
	}
}

func connectorProviderPreflightChecks(sourceID string, authMethod string, config map[string]string, policy resourcescope.Policy) []connectorPreflightCheckView {
	checks := connectorpreflight.ProviderChecks(sourceID, authMethod, config, policy)
	if len(checks) == 0 {
		return nil
	}
	views := make([]connectorPreflightCheckView, 0, len(checks))
	for _, check := range checks {
		views = append(views, connectorPreflightCheckView{
			ID:         check.ID,
			Label:      check.Label,
			Status:     check.Status,
			Severity:   check.Severity,
			Detail:     check.Detail,
			NextAction: check.NextAction,
			Blocking:   check.Blocking,
		})
	}
	return views
}

func connectorPreflightErrorDetail(err error) string {
	switch {
	case errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, sourcecdk.ErrInvalidConfig),
		errors.Is(err, connectorcredentials.ErrInvalidRequest):
		return "Source rejected the resolved runtime configuration."
	case errors.Is(err, connectorcredentials.ErrUnavailable),
		errors.Is(err, sourceruntime.ErrRuntimeUnavailable):
		return "A backend dependency needed for source validation is unavailable."
	default:
		return "Source validation did not pass."
	}
}

func connectorPreflightValidationDetail(issue error, fallback string) string {
	switch {
	case issue == nil:
		return fallback
	case errors.Is(issue, connectorcredentials.ErrUnavailable),
		errors.Is(issue, sourceruntime.ErrRuntimeUnavailable):
		return fallback + " A backend dependency needed for validation is unavailable."
	default:
		return fallback
	}
}

func (a *App) connectorHealthForSource(r *http.Request, sourceID string, tenantID string) (sourceRuntimeHealthResponse, error) {
	clone := r.Clone(r.Context())
	clonedURL := *r.URL
	query := clonedURL.Query()
	query.Set("source_id", strings.TrimSpace(sourceID))
	if strings.TrimSpace(tenantID) != "" {
		query.Set("tenant_id", strings.TrimSpace(tenantID))
	}
	query.Set("limit", strconv.Itoa(connectorActivityMaxLimit))
	clonedURL.RawQuery = query.Encode()
	clone.URL = &clonedURL
	health, err := a.listSourceRuntimeHealth(clone)
	if errors.Is(err, sourceruntime.ErrRuntimeUnavailable) {
		return emptySourceRuntimeHealthResponse(), nil
	}
	return health, err
}

func connectorActivityLimit(r *http.Request) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get("limit"))
	if value == "" {
		return connectorActivityDefaultLimit, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid limit", connectorcredentials.ErrInvalidRequest)
	}
	if parsed == 0 || parsed > connectorActivityMaxLimit {
		return 0, fmt.Errorf("%w: limit must be between 1 and %d", connectorcredentials.ErrInvalidRequest, connectorActivityMaxLimit)
	}
	return int(parsed), nil
}

func connectorOperationsSummaryFromHealth(entry connectorCatalogEntry, records []sourceRuntimeHealthRecord) connectorOperationsSummary {
	total := len(records)
	healthy := 0
	needsAttention := 0
	var syncFrequency *int64
	var lastActivity time.Time
	status := "not_configured"
	reason := "No active connection is configured."
	topIssue := reason
	for _, record := range records {
		if strings.EqualFold(record.Status, "healthy") && sourceRuntimeGraphState(record) == "current" {
			healthy++
		} else {
			needsAttention++
		}
		if record.ExpectedCadenceSeconds != nil && (syncFrequency == nil || *record.ExpectedCadenceSeconds < *syncFrequency) {
			value := *record.ExpectedCadenceSeconds
			syncFrequency = &value
		}
		if observedAt, ok := connectorRecordLastActivityTime(record); ok && observedAt.After(lastActivity) {
			lastActivity = observedAt
		}
	}
	if total > 0 {
		switch {
		case connectorAnyRecordFailing(records):
			status = "bad"
			reason = "At least one connection has a failing sync, graph, or probe signal."
			topIssue = "Fix failing connection signal."
		case connectorAnyRecordRefreshNeeded(records):
			status = "needs_refresh"
			reason = "At least one connection is stale or missing graph freshness."
			topIssue = "Refresh sync or graph projection."
		case needsAttention > 0:
			status = "poor"
			reason = "Connection telemetry is incomplete."
			topIssue = "Inspect incomplete connection telemetry."
		default:
			status = "healthy"
			reason = "Sync and graph signals are current."
			topIssue = ""
		}
	}
	lastActivityAt := ""
	if !lastActivity.IsZero() {
		lastActivityAt = lastActivity.UTC().Format(time.RFC3339Nano)
	}
	return connectorOperationsSummary{
		Status:               status,
		StatusReason:         reason,
		TopIssue:             topIssue,
		TotalConnections:     total,
		HealthyConnections:   healthy,
		NeedsAttention:       needsAttention,
		LastActivityAt:       lastActivityAt,
		SyncFrequencySeconds: syncFrequency,
		ResourceTypes:        len(entry.EmittedKinds),
		EmittedKinds:         len(entry.EmittedKinds),
	}
}

func connectorConnectionsFromHealth(records []sourceRuntimeHealthRecord) []connectorConnectionView {
	connections := make([]connectorConnectionView, 0, len(records))
	for _, record := range records {
		status := connectorConnectionReadiness(record)
		connections = append(connections, connectorConnectionView{
			RuntimeID:               record.RuntimeID,
			SourceID:                record.SourceID,
			TenantID:                record.TenantID,
			Family:                  record.Family,
			Status:                  status,
			GraphStatus:             sourceRuntimeGraphState(record),
			ContractProbeState:      record.ContractProbeState,
			LastActivityAt:          connectorRecordLastActivity(record),
			CheckpointWatermark:     record.CheckpointWatermark,
			WatermarkLagSeconds:     record.WatermarkLagSeconds,
			RecordsAccepted:         record.RecentSync.RecordsAccepted,
			RecordsRejected:         record.RecentSync.RecordsRejected,
			EntitiesProjected:       record.RecentSync.EntitiesProjected,
			LinksProjected:          record.RecentSync.LinksProjected,
			CursorPending:           record.CursorPending,
			CheckpointCursorPresent: record.CheckpointCursorPresent,
			NextAction:              connectorConnectionNextAction(status, record),
			ScopePolicy:             record.ScopePolicy,
		})
	}
	sort.Slice(connections, func(i, j int) bool {
		return connections[i].LastActivityAt > connections[j].LastActivityAt
	})
	return connections
}

func connectorActivityFromHealth(records []sourceRuntimeHealthRecord) []connectorActivityView {
	activity := make([]connectorActivityView, 0, len(records)*2)
	for _, record := range records {
		syncStatus := connectorSyncActivityStatus(record)
		activity = append(activity, connectorActivityView{
			ID:              connectorActivityID(record.RuntimeID, "sync", connectorRecordLastActivity(record)),
			RuntimeID:       record.RuntimeID,
			SourceID:        record.SourceID,
			TenantID:        record.TenantID,
			Family:          record.Family,
			Type:            "sync",
			Status:          syncStatus,
			Title:           connectorSyncActivityTitle(syncStatus),
			Description:     connectorSyncActivityDescription(record),
			OccurredAt:      connectorRecordLastActivity(record),
			RecordsAccepted: record.RecentSync.RecordsAccepted,
			RecordsRejected: record.RecentSync.RecordsRejected,
			FailureClass:    connectorFailureClass(record),
		})
		if record.LatestGraphRun != nil {
			graphStatus := connectorGraphActivityStatus(record.LatestGraphRun.Status)
			activity = append(activity, connectorActivityView{
				ID:                connectorActivityID(record.RuntimeID, "graph", connectorGraphActivityTime(record.LatestGraphRun)),
				RuntimeID:         record.RuntimeID,
				SourceID:          record.SourceID,
				TenantID:          record.TenantID,
				Family:            record.Family,
				Type:              "graph",
				Status:            graphStatus,
				Title:             connectorGraphActivityTitle(graphStatus),
				Description:       "Graph projection activity for this connection.",
				OccurredAt:        connectorGraphActivityTime(record.LatestGraphRun),
				DurationSeconds:   record.LatestGraphRun.DurationSeconds,
				EntitiesProjected: record.LatestGraphRun.EntitiesProjected,
				LinksProjected:    record.LatestGraphRun.LinksProjected,
				FailureClass:      connectorGraphFailureClass(record.LatestGraphRun.Status),
			})
		}
	}
	sort.Slice(activity, func(i, j int) bool {
		return activity[i].OccurredAt > activity[j].OccurredAt
	})
	return activity
}

func limitConnectorActivity(activity []connectorActivityView, limit int) []connectorActivityView {
	if limit <= 0 || len(activity) <= limit {
		return activity
	}
	return activity[:limit]
}

func connectorAnyRecordFailing(records []sourceRuntimeHealthRecord) bool {
	for _, record := range records {
		if strings.EqualFold(record.Status, "failing") || sourceRuntimeGraphState(record) == "failed" || strings.EqualFold(record.ContractProbeState, "failure") {
			return true
		}
	}
	return false
}

func connectorAnyRecordRefreshNeeded(records []sourceRuntimeHealthRecord) bool {
	for _, record := range records {
		if strings.EqualFold(record.Status, "stale") || record.CursorPending {
			return true
		}
		switch sourceRuntimeGraphState(record) {
		case "behind", "not_observed":
			return true
		}
	}
	return false
}

func connectorConnectionReadiness(record sourceRuntimeHealthRecord) string {
	if strings.EqualFold(record.Status, "failing") || sourceRuntimeGraphState(record) == "failed" || strings.EqualFold(record.ContractProbeState, "failure") {
		return "bad"
	}
	if strings.EqualFold(record.Status, "stale") || record.CursorPending || sourceRuntimeGraphState(record) == "behind" || sourceRuntimeGraphState(record) == "not_observed" {
		return "needs_refresh"
	}
	if strings.EqualFold(record.Status, "healthy") && sourceRuntimeGraphState(record) == "current" {
		return "healthy"
	}
	return "poor"
}

func connectorConnectionNextAction(status string, record sourceRuntimeHealthRecord) string {
	switch status {
	case "bad":
		return "fix_connection"
	case "needs_refresh":
		if sourceRuntimeGraphState(record) == "not_observed" || sourceRuntimeGraphState(record) == "behind" {
			return "run_graph_ingest"
		}
		return "run_sync"
	case "healthy":
		return "monitor"
	default:
		return "inspect_connection"
	}
}

func connectorRecordLastActivity(record sourceRuntimeHealthRecord) string {
	if observedAt, ok := connectorRecordLastActivityTime(record); ok {
		return observedAt.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

func connectorRecordLastActivityTime(record sourceRuntimeHealthRecord) (time.Time, bool) {
	var latest time.Time
	for _, value := range []string{
		record.LastSyncedAt,
		record.CheckpointWatermark,
		connectorGraphActivityTime(record.LatestGraphRun),
	} {
		parsed, ok := parseRFC3339(value)
		if !ok {
			continue
		}
		if parsed.After(latest) {
			latest = parsed
		}
	}
	if latest.IsZero() {
		return time.Time{}, false
	}
	return latest, true
}

func connectorSyncActivityStatus(record sourceRuntimeHealthRecord) string {
	switch connectorConnectionReadiness(record) {
	case "healthy":
		return "success"
	case "bad":
		return "failed"
	case "needs_refresh":
		return "needs_refresh"
	default:
		return "incomplete"
	}
}

func connectorSyncActivityTitle(status string) string {
	switch status {
	case "success":
		return "Successful sync"
	case "failed":
		return "Sync needs attention"
	case "needs_refresh":
		return "Sync refresh needed"
	default:
		return "Sync signal incomplete"
	}
}

func connectorSyncActivityDescription(record sourceRuntimeHealthRecord) string {
	switch connectorSyncActivityStatus(record) {
	case "success":
		return "Runtime sync completed with current source telemetry."
	case "failed":
		return "Runtime sync or validation is failing."
	case "needs_refresh":
		return "Runtime sync, cursor, or graph projection is behind."
	default:
		return "Runtime telemetry has not produced enough signal yet."
	}
}

func connectorGraphActivityStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if strings.Contains(normalized, "fail") || strings.Contains(normalized, "error") || strings.Contains(normalized, "cancel") {
		return "failed"
	}
	if strings.Contains(normalized, "running") || strings.Contains(normalized, "pending") {
		return "running"
	}
	if normalized == "" {
		return "not_observed"
	}
	return "success"
}

func connectorGraphActivityTitle(status string) string {
	switch status {
	case "success":
		return "Graph projection complete"
	case "failed":
		return "Graph projection failed"
	case "running":
		return "Graph projection running"
	default:
		return "Graph projection not observed"
	}
}

func connectorGraphActivityTime(run *sourceRuntimeHealthGraphRun) string {
	if run == nil {
		return ""
	}
	if strings.TrimSpace(run.FinishedAt) != "" {
		return strings.TrimSpace(run.FinishedAt)
	}
	return strings.TrimSpace(run.StartedAt)
}

func connectorFailureClass(record sourceRuntimeHealthRecord) string {
	if value := strings.TrimSpace(record.LastFailureCategory); value != "" {
		return value
	}
	if strings.EqualFold(record.ContractProbeState, "failure") {
		return "contract_probe_failure"
	}
	if connectorConnectionReadiness(record) == "needs_refresh" {
		return "freshness"
	}
	return ""
}

func connectorGraphFailureClass(status string) string {
	if connectorGraphActivityStatus(status) == "failed" {
		return "graph_ingest_failed"
	}
	return ""
}

func connectorActivityID(runtimeID string, kind string, occurredAt string) string {
	parts := []string{strings.TrimSpace(runtimeID), strings.TrimSpace(kind), strings.TrimSpace(occurredAt)}
	return strings.Trim(strings.Join(parts, ":"), ":")
}

func connectorRuntimeHealthy(runtime *cerebrov1.SourceRuntime) bool {
	if runtime == nil {
		return false
	}
	status := strings.TrimSpace(runtime.GetConfig()["__cerebro_runtime_status"])
	if status != "" {
		return status == "completed" || status == "healthy"
	}
	return runtime.GetLastSyncedAt() != nil
}

func (a *App) checkConnectorRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime, plaintextFields map[string]string) error {
	if runtime == nil {
		return fmt.Errorf("%w: source runtime is required", connectorcredentials.ErrInvalidRequest)
	}
	source, err := a.connectorSourceForTenant(ctx, runtime.GetSourceId(), runtime.GetTenantId())
	if err != nil {
		return err
	}
	values := copyStringMap(runtime.GetConfig())
	for key, value := range plaintextFields {
		values[key] = value
	}
	values = sourceconfig.WithRuntimeContext(values, runtime.GetTenantId(), runtime.GetId())
	resolved, err := resolveRuntimeSourceConfigWithStore(ctx, a.cfg.ConnectorCredentials, a.cfg.ConnectorSecretStores, a.deps.StateStore, runtime.GetSourceId(), values)
	if err != nil {
		return err
	}
	if err := source.Check(ctx, sourcecdk.NewConfig(resolved)); err != nil {
		if errors.Is(err, sourcecdk.ErrInvalidConfig) {
			return fmt.Errorf("%w: %w", sourceruntime.ErrInvalidRequest, err)
		}
		return err
	}
	return nil
}

func (a *App) connectorSource(sourceID string) (sourcecdk.Source, error) {
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return nil, fmt.Errorf("%w: source id is required", connectorcredentials.ErrInvalidRequest)
	}
	if a == nil || a.sources == nil {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	source, ok := a.sources.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	return source, nil
}

func (a *App) connectorSourceForTenant(ctx context.Context, sourceID string, tenantID string) (sourcecdk.Source, error) {
	if source, err := a.connectorSource(sourceID); err == nil {
		return source, nil
	}
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return nil, fmt.Errorf("%w: source id is required", connectorcredentials.ErrInvalidRequest)
	}
	definition, ok := a.connectorTenantDefinitionBySourceID(ctx, tenantID, id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, id)
	}
	source, err := sourceregistry.DynamicDefinitionSource(definition)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", connectorcredentials.ErrInvalidRequest, id, err)
	}
	return source, nil
}

func (a *App) connectorSourceExistsForTenant(ctx context.Context, sourceID string, tenantID string) bool {
	if a.connectorSourceExists(sourceID) {
		return true
	}
	definition, ok := a.connectorTenantDefinitionBySourceID(ctx, tenantID, sourceID)
	if !ok || definition.Validation.Status == connectordefinitions.ValidationBlocked {
		return false
	}
	_, err := sourceregistry.DynamicDefinitionSource(definition)
	return err == nil
}

func connectorRuntimePayload(runtime *cerebrov1.SourceRuntime) (json.RawMessage, error) {
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(redactSourceRuntime(runtime))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(payload), nil
}

func connectorDisplayName(sourceID string, fallback string) string {
	switch strings.TrimSpace(sourceID) {
	case "aws":
		return "Amazon Web Services"
	case "gcp":
		return "Google Cloud Platform"
	case "google_workspace":
		return "Google Workspace"
	case "github":
		return "GitHub"
	case "okta":
		return "Okta"
	case "openai":
		return "OpenAI"
	case "anthropic":
		return "Anthropic"
	case "azure":
		return "Microsoft Azure"
	default:
		if name := strings.TrimSpace(fallback); name != "" {
			return name
		}
		return strings.TrimSpace(sourceID)
	}
}

func connectorConfigFields(sourceID string, authMethod string) []connectorFieldView {
	schema, ok := connectorSchemaForSource(sourceID)
	if !ok {
		return nil
	}
	keys := sortedSetKeys(schema.ConfigKeys)
	if authMethod == connectorAuthMethodAWSSSOProfile && strings.TrimSpace(sourceID) == "aws" {
		keys = append(keys, "profile")
		sort.Strings(keys)
	}
	required := stringSet(schema.RequiredConfig...)
	if authMethod == connectorAuthMethodAWSSSOProfile {
		required["profile"] = struct{}{}
	}
	fields := make([]connectorFieldView, 0, len(keys))
	for _, key := range keys {
		if authMethod != connectorAuthMethodAWSSSOProfile && key == "profile" {
			continue
		}
		field := connectorFieldView{
			Key:         key,
			Label:       connectorFieldLabel(key),
			Required:    setContains(required, key),
			Placeholder: connectorFieldPlaceholder(sourceID, key, false),
			Help:        connectorFieldHelp(sourceID, authMethod, key),
		}
		fields = append(fields, field)
	}
	return fields
}

func connectorCredentialFields(sourceID string, authMethod string) []connectorFieldView {
	if authMethod == connectorAuthMethodAWSSSOProfile {
		return nil
	}
	schema, ok := connectorSchemaForSource(sourceID)
	if !ok {
		return nil
	}
	required := stringSet(schema.RequiredCredentials...)
	keys := sortedSetKeys(schema.CredentialKeys)
	fields := make([]connectorFieldView, 0, len(keys))
	for _, key := range keys {
		field := connectorFieldView{
			Key:           key,
			Label:         connectorFieldLabel(key),
			Required:      setContains(required, key),
			Secret:        authMethod == connectorAuthMethodEncryptedSubmission,
			ReferenceOnly: authMethod != connectorAuthMethodEncryptedSubmission,
			Placeholder:   connectorFieldPlaceholder(sourceID, key, authMethod != connectorAuthMethodEncryptedSubmission),
			Help:          connectorFieldHelp(sourceID, authMethod, key),
		}
		fields = append(fields, field)
	}
	return fields
}

func connectorFieldLabel(key string) string {
	words := strings.Fields(strings.ReplaceAll(strings.TrimSpace(key), "_", " "))
	for i, word := range words {
		switch strings.ToLower(word) {
		case "id", "iam", "sso", "api", "arn", "url", "wif", "gcp", "aws":
			words[i] = strings.ToUpper(word)
		default:
			if word != "" {
				words[i] = strings.ToUpper(word[:1]) + word[1:]
			}
		}
	}
	return strings.Join(words, " ")
}

func connectorFieldPlaceholder(sourceID string, key string, referenceOnly bool) string {
	if referenceOnly {
		return "env:" + connectorSuggestedEnvName(sourceID, key)
	}
	switch key {
	case "profile":
		return "cerebro-readonly"
	case "region":
		return "us-east-1"
	case "family":
		return "audit"
	case "include_global":
		return "true"
	default:
		return ""
	}
}

func connectorFieldHelp(sourceID string, authMethod string, key string) string {
	if authMethod == connectorAuthMethodAWSSSOProfile && key == "profile" {
		return "AWS SDK shared config profile already authenticated on the server."
	}
	if authMethod != connectorAuthMethodEncryptedSubmission && sourceconfig.SensitiveKey(key) {
		return "Server-resolvable reference; the browser never receives the secret value."
	}
	if strings.TrimSpace(sourceID) == "aws" && key == "role_arn" {
		return "Optional IAM role; server-side allowlist validation still applies."
	}
	return ""
}

func connectorSuggestedEnvName(sourceID string, key string) string {
	return "CEREBRO_SOURCE_" + connectorEnvComponent(sourceID) + "_" + connectorEnvComponent(key)
}

func connectorEnvComponent(value string) string {
	var builder strings.Builder
	for _, char := range strings.TrimSpace(value) {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char - 'a' + 'A')
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	component := strings.Trim(builder.String(), "_")
	if component == "" {
		return "CONFIG"
	}
	return component
}

func connectorStoreViews(vaultStatus connectorVaultView, transport connectorTransportView, secretStoreConfig config.ConnectorSecretStoreConfig) []connectorStoreView {
	available := vaultStatus.Available && transport.Available
	detail := strings.TrimSpace(vaultStatus.Detail)
	status := "unavailable"
	if available {
		detail = "ready"
		status = "ready"
	}
	return []connectorStoreView{
		{
			ID:          defaultConnectorCredentialStoreID,
			Label:       "Cerebro Vault",
			Provider:    "Cerebro",
			Available:   available,
			Default:     true,
			Mode:        "encrypted_submission",
			Status:      status,
			Detail:      detail,
			Description: "Cerebro stores one sealed credential envelope in its state store. The browser submits secrets only after encrypting them to the backend transit key.",
			SetupSteps:  cerebroVaultStoreSetupSteps(),
			RequiredConfig: []connectorStoreConfigFieldView{
				{
					Env:         "CEREBRO_CONNECTOR_CREDENTIAL_KEY",
					Label:       "Credential envelope key",
					Required:    true,
					Description: "Symmetric key material used to seal connector credentials at rest.",
				},
				{
					Env:         "CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY",
					Label:       "Browser transit private key",
					Required:    true,
					Description: "Private key matching /connectors/credential-key for encrypted browser submissions.",
				},
			},
		},
		{
			ID:                         connectorStoreEnvironmentManaged,
			Label:                      "Environment managed",
			Provider:                   "Deployment",
			Available:                  true,
			Mode:                       "environment_managed",
			Status:                     "ready",
			Detail:                     "ready",
			Description:                "Cerebro stores env: references and resolves them inside the backend process. The browser never receives the secret value.",
			ReferencePrefixes:          []string{"env:"},
			ReferenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
			ReferenceFieldTemplate:     "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
			ReferencePlaceholder:       "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
			SetupSteps: []connectorStoreSetupStepView{
				{
					ID:          "project_env",
					Label:       "Project secrets into the Cerebro runtime",
					Description: "Set source-scoped CEREBRO_SOURCE_<SOURCE>_<FIELD> variables or allow explicit shared env names with CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST.",
				},
			},
		},
		connectorExternalStoreView(secretStoreConfig, connectorStoreInfisical, "Infisical", "Infisical"),
		connectorExternalStoreView(secretStoreConfig, connectorStoreGoogleSecretMgr, "Google Secret Manager", "Google Cloud Platform"),
		connectorExternalStoreView(secretStoreConfig, connectorStoreAWSSecretsManager, "AWS Secrets Manager", "Amazon Web Services"),
		connectorExternalStoreView(secretStoreConfig, connectorStoreAzureKeyVault, "Azure Key Vault", "Microsoft Azure"),
		connectorExternalStoreView(secretStoreConfig, connectorStoreHashiCorpVault, "HashiCorp Vault", "HashiCorp"),
	}
}

func connectorExternalStoreView(secretStoreConfig config.ConnectorSecretStoreConfig, id string, label string, provider string) connectorStoreView {
	enabled := connectorsecretstores.StoreEnabled(secretStoreConfig, id)
	native := connectorsecretstores.NativeResolutionAvailable(secretStoreConfig, id)
	status := "needs_configuration"
	detail := "enable with CEREBRO_CONNECTOR_SECRET_STORES"
	if enabled {
		status = "ready"
		detail = "ready via env projection"
	}
	if native {
		detail = "native resolver ready"
	}
	referencePrefixes := connectorsecretstores.ReferencePrefixes(id)
	if id == connectorStoreAWSSecretsManager && !native {
		referencePrefixes = []string{"env:"}
	}
	return connectorStoreView{
		ID:                         id,
		Label:                      label,
		Provider:                   provider,
		Available:                  enabled,
		Mode:                       connectorCredentialStoreModeRefs,
		Status:                     status,
		Detail:                     detail,
		Description:                connectorExternalStoreDescription(id, label),
		ReferencePrefixes:          referencePrefixes,
		ReferenceNamespaceTemplate: connectorStoreReferenceNamespaceTemplate(id, native),
		ReferenceFieldTemplate:     connectorStoreReferenceFieldTemplate(id, native),
		ReferencePlaceholder:       connectorStoreReferencePlaceholder(id, native),
		NativeResolutionAvailable:  native,
		SetupSteps:                 connectorExternalStoreSetupSteps(id, native),
		RequiredConfig:             connectorExternalStoreRequiredConfig(id),
	}
}

func cerebroVaultStoreSetupSteps() []connectorStoreSetupStepView {
	return []connectorStoreSetupStepView{
		{
			ID:          "configure_state_store",
			Label:       "Use a credential-capable state store",
			Description: "The configured state store must implement connector credential persistence.",
		},
		{
			ID:          "publish_transit_key",
			Label:       "Publish the credential transit key",
			Description: "/connectors/credential-key must return the public key used by the browser before encrypted submission.",
		},
	}
}

func connectorExternalStoreDescription(id string, label string) string {
	switch id {
	case connectorStoreAWSSecretsManager:
		return "Cerebro can resolve aws-sm: references natively when AWS resolver config is present, or consume env: references projected by deployment automation."
	default:
		return label + " references are saved as non-secret pointers. Configure deployment-side projection to env: references until a native backend resolver is enabled for this store."
	}
}

func connectorStoreReferencePlaceholder(id string, native bool) string {
	switch id {
	case connectorStoreAWSSecretsManager:
		if !native {
			return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>"
		}
		return "aws-sm:us-east-1:cerebro/<tenant>/<source>/<runtime>/credentials#<field>"
	default:
		return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>"
	}
}

func connectorStoreReferenceNamespaceTemplate(id string, native bool) string {
	switch strings.TrimSpace(id) {
	case connectorStoreAWSSecretsManager:
		if !native {
			return "CEREBRO_SOURCE_<SOURCE>_*"
		}
		return "cerebro/<tenant>/<source>/<runtime>/credentials"
	case connectorStoreEnvironmentManaged, connectorStoreInfisical, connectorStoreGoogleSecretMgr, connectorStoreAzureKeyVault, connectorStoreHashiCorpVault:
		return "CEREBRO_SOURCE_<SOURCE>_*"
	default:
		return ""
	}
}

func connectorStoreReferenceFieldTemplate(id string, native bool) string {
	switch strings.TrimSpace(id) {
	case connectorStoreAWSSecretsManager:
		if !native {
			return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>"
		}
		return "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>"
	case connectorStoreEnvironmentManaged, connectorStoreInfisical, connectorStoreGoogleSecretMgr, connectorStoreAzureKeyVault, connectorStoreHashiCorpVault:
		return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>"
	default:
		return ""
	}
}

func connectorExternalStoreSetupSteps(id string, native bool) []connectorStoreSetupStepView {
	steps := []connectorStoreSetupStepView{
		{
			ID:          "enable_store",
			Label:       "Enable the store for connector references",
			Description: "Add the store id to CEREBRO_CONNECTOR_SECRET_STORES before saving references that target it.",
			Command:     "CEREBRO_CONNECTOR_SECRET_STORES=" + id,
		},
		{
			ID:          "keep_browser_secretless",
			Label:       "Submit references, not secret values",
			Description: "The UI should send credential_references only. Secret material is resolved by the backend or projected into the runtime environment.",
		},
	}
	if id == connectorStoreAWSSecretsManager {
		description := "Set CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION to enable native aws-sm: resolution with the AWS SDK."
		if native {
			description = "Native aws-sm: resolution is enabled for this deployment."
		}
		steps = append(steps, connectorStoreSetupStepView{
			ID:          "configure_native_resolver",
			Label:       "Configure native AWS resolution",
			Description: description,
			Command:     "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION=us-east-1",
		})
	}
	return steps
}

func connectorExternalStoreRequiredConfig(id string) []connectorStoreConfigFieldView {
	fields := []connectorStoreConfigFieldView{
		{
			Env:         "CEREBRO_CONNECTOR_SECRET_STORES",
			Label:       "Enabled connector secret stores",
			Required:    true,
			Description: "Comma-separated store ids that this deployment accepts for connector credential references.",
		},
	}
	if id == connectorStoreAWSSecretsManager {
		fields = append(fields,
			connectorStoreConfigFieldView{
				Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION",
				Label:       "AWS resolver region",
				Description: "Default region used when aws-sm: references do not include a region.",
			},
			connectorStoreConfigFieldView{
				Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_PROFILE",
				Label:       "AWS shared config profile",
				Description: "Optional shared AWS config profile used by the backend resolver.",
			},
			connectorStoreConfigFieldView{
				Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ROLE_ARN",
				Label:       "AWS resolver role",
				Description: "Optional role the backend assumes before reading secrets.",
			},
			connectorStoreConfigFieldView{
				Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_EXTERNAL_ID",
				Label:       "AWS external ID",
				Description: "Optional external ID used with the resolver role.",
			},
		)
	}
	return fields
}

func connectorConnectionMethods(sourceID string, stores []connectorStoreView) []connectorConnectionMethodView {
	vaultAvailable := connectorStoreAvailable(stores, defaultConnectorCredentialStoreID)
	environmentAvailable := connectorStoreAvailable(stores, connectorStoreEnvironmentManaged)
	externalStores := []string{connectorStoreInfisical, connectorStoreGoogleSecretMgr, connectorStoreAWSSecretsManager, connectorStoreAzureKeyVault, connectorStoreHashiCorpVault}
	externalAvailable := connectorAnyStoreAvailable(stores, externalStores...)
	methods := []connectorConnectionMethodView{
		{
			ID:                connectorAuthMethodEncryptedSubmission,
			Label:             "Encrypted browser submission",
			ShortLabel:        "Manual",
			Category:          "Direct",
			Description:       "Submit one encrypted credential payload to Cerebro Vault, then store only a sealed credential reference on the runtime.",
			CredentialStores:  []string{defaultConnectorCredentialStoreID},
			ConfigFields:      connectorConfigFields(sourceID, connectorAuthMethodEncryptedSubmission),
			CredentialFields:  connectorCredentialFields(sourceID, connectorAuthMethodEncryptedSubmission),
			RequiresSecrets:   true,
			Saveable:          vaultAvailable,
			UnavailableReason: connectorUnavailableReason(vaultAvailable, "Cerebro Vault or the credential transit key is unavailable."),
		},
		{
			ID:                connectorAuthMethodEnvironmentManaged,
			Label:             "Environment-managed reference",
			ShortLabel:        "Env",
			Category:          "Reference",
			Description:       "Store env-backed credential references for deployment-side resolution.",
			CredentialStores:  []string{connectorStoreEnvironmentManaged},
			ConfigFields:      connectorConfigFields(sourceID, connectorAuthMethodEnvironmentManaged),
			CredentialFields:  connectorCredentialFields(sourceID, connectorAuthMethodEnvironmentManaged),
			Saveable:          environmentAvailable,
			UnavailableReason: connectorUnavailableReason(environmentAvailable, "Environment-managed references are unavailable."),
		},
		{
			ID:                connectorAuthMethodInfisicalCLI,
			Label:             "Infisical CLI handoff",
			ShortLabel:        "Infisical",
			Category:          "SSO handoff",
			Description:       "Use Infisical SSO/CLI to populate deployment env references consumed by Cerebro.",
			CredentialStores:  []string{connectorStoreEnvironmentManaged},
			ConfigFields:      connectorConfigFields(sourceID, connectorAuthMethodInfisicalCLI),
			CredentialFields:  connectorCredentialFields(sourceID, connectorAuthMethodInfisicalCLI),
			Saveable:          environmentAvailable,
			UnavailableReason: connectorUnavailableReason(environmentAvailable, "Environment-managed references are unavailable."),
		},
		{
			ID:                connectorAuthMethodExternalReference,
			Label:             "External secret-store reference",
			ShortLabel:        "Store ref",
			Category:          "Reference",
			Description:       "Select an operator-managed secret store and save only server-resolvable references.",
			CredentialStores:  externalStores,
			ConfigFields:      connectorConfigFields(sourceID, connectorAuthMethodExternalReference),
			CredentialFields:  connectorCredentialFields(sourceID, connectorAuthMethodExternalReference),
			Saveable:          externalAvailable,
			UnavailableReason: connectorUnavailableReason(externalAvailable, "External secret-store references are unavailable."),
		},
	}
	if strings.TrimSpace(sourceID) == "aws" {
		methods = append([]connectorConnectionMethodView{{
			ID:                connectorAuthMethodAWSSSOProfile,
			Label:             "AWS IAM Identity Center profile",
			ShortLabel:        "AWS SSO",
			Category:          "Recommended",
			Description:       "Use AWS CLI SSO and save a deployment-managed profile/role runtime. No long-lived AWS key is entered in the browser.",
			CredentialStores:  []string{connectorStoreEnvironmentManaged},
			ConfigFields:      connectorConfigFields(sourceID, connectorAuthMethodAWSSSOProfile),
			Recommended:       true,
			Saveable:          environmentAvailable,
			UnavailableReason: connectorUnavailableReason(environmentAvailable, "Environment-managed AWS profiles are unavailable."),
		}}, methods...)
	}
	for index := range methods {
		methods[index] = connectorMethodWithGuidance(sourceID, methods[index])
	}
	return methods
}

func connectorConnectionMethodsFromDefinition(definition connectordefinitions.Definition, stores []connectorStoreView) []connectorConnectionMethodView {
	sourceID := strings.TrimSpace(definition.SourceID)
	configFields := connectorDefinitionFields(definition.ConfigFields)
	credentialFields := connectorDefinitionFields(definition.Auth.CredentialFields)
	hasCredentials := len(credentialFields) > 0 && strings.TrimSpace(definition.Auth.Model) != "none"
	environmentAvailable := connectorStoreAvailable(stores, connectorStoreEnvironmentManaged)
	externalStores := []string{connectorStoreInfisical, connectorStoreGoogleSecretMgr, connectorStoreAWSSecretsManager, connectorStoreAzureKeyVault, connectorStoreHashiCorpVault}
	externalAvailable := connectorAnyStoreAvailable(stores, externalStores...)
	methods := []connectorConnectionMethodView{
		{
			ID:                connectorAuthMethodEnvironmentManaged,
			Label:             "Environment-managed reference",
			ShortLabel:        "Env",
			Category:          "Reference",
			Description:       "Store deployment-side config and credential references for this custom connector.",
			CredentialStores:  []string{connectorStoreEnvironmentManaged},
			ConfigFields:      configFields,
			CredentialFields:  credentialFields,
			RequiresSecrets:   false,
			Recommended:       !hasCredentials,
			Saveable:          environmentAvailable,
			UnavailableReason: connectorUnavailableReason(environmentAvailable, "Environment-managed references are unavailable."),
		},
	}
	if hasCredentials {
		vaultAvailable := connectorStoreAvailable(stores, defaultConnectorCredentialStoreID)
		methods = append([]connectorConnectionMethodView{{
			ID:                connectorAuthMethodEncryptedSubmission,
			Label:             "Encrypted browser submission",
			ShortLabel:        "Manual",
			Category:          "Direct",
			Description:       "Submit one encrypted credential payload to Cerebro Vault, then store only sealed references on the runtime.",
			CredentialStores:  []string{defaultConnectorCredentialStoreID},
			ConfigFields:      configFields,
			CredentialFields:  credentialFields,
			RequiresSecrets:   true,
			Recommended:       true,
			Saveable:          vaultAvailable,
			UnavailableReason: connectorUnavailableReason(vaultAvailable, "Cerebro Vault or the credential transit key is unavailable."),
		}}, methods...)
		methods = append(methods, connectorConnectionMethodView{
			ID:                connectorAuthMethodExternalReference,
			Label:             "External secret-store reference",
			ShortLabel:        "Store ref",
			Category:          "Reference",
			Description:       "Save only operator-managed secret-store references for this custom connector.",
			CredentialStores:  externalStores,
			ConfigFields:      configFields,
			CredentialFields:  credentialFields,
			RequiresSecrets:   false,
			Saveable:          externalAvailable,
			UnavailableReason: connectorUnavailableReason(externalAvailable, "External secret-store references are unavailable."),
		})
	}
	for index := range methods {
		methods[index] = connectorMethodWithGuidance(sourceID, methods[index])
	}
	return methods
}

func connectorDefinitionFields(fields []connectordefinitions.Field) []connectorFieldView {
	views := make([]connectorFieldView, 0, len(fields))
	for _, field := range fields {
		key := strings.TrimSpace(field.Key)
		if key == "" {
			continue
		}
		views = append(views, connectorFieldView{
			Key:           key,
			Label:         firstNonEmpty(field.Label, connectorFieldLabel(key)),
			Required:      field.Required,
			Secret:        field.Secret,
			ReferenceOnly: field.ReferenceOnly,
			Placeholder:   field.Placeholder,
			Help:          field.Help,
		})
	}
	return views
}

func connectorMethodWithGuidance(sourceID string, method connectorConnectionMethodView) connectorConnectionMethodView {
	normalizedSourceID := strings.TrimSpace(sourceID)
	if method.ShortLabel == "" {
		method.ShortLabel = connectorMethodShortLabel(method.ID)
	}
	if method.Category == "" {
		method.Category = "Connection"
	}
	method.Prerequisites = connectorPrerequisites(normalizedSourceID)
	method.Steps = connectorSetupSteps(normalizedSourceID, method.ID)
	method.Commands = connectorSetupCommands(normalizedSourceID, method.ID)
	method.ProductGroups = connectorProductGroups(normalizedSourceID)
	method.DeploymentGuides = connectorDeploymentGuides(normalizedSourceID, method.ID)
	method.RegionGuidance = connectorRegionGuidance(normalizedSourceID)
	method.SecurityNotes = connectorSecurityNotes(normalizedSourceID, method.ID)
	return method
}

func connectorMethodShortLabel(methodID string) string {
	switch methodID {
	case connectorAuthMethodAWSSSOProfile:
		return "AWS SSO"
	case connectorAuthMethodInfisicalCLI:
		return "Infisical"
	case connectorAuthMethodEnvironmentManaged:
		return "Env"
	case connectorAuthMethodExternalReference:
		return "Store ref"
	default:
		return "Manual"
	}
}

func connectorPrerequisites(sourceID string) []connectorPrerequisiteView {
	common := []connectorPrerequisiteView{
		{
			ID:          "backend_store",
			Label:       "Backend credential store selected",
			Description: "The selected store is resolved by Cerebro on the server side.",
			Required:    true,
		},
		{
			ID:          "source_validation",
			Label:       "Source check passes before save",
			Description: "Cerebro validates the source config and credential path before persisting the runtime.",
			Required:    true,
		},
	}
	switch sourceID {
	case "aws":
		return append([]connectorPrerequisiteView{
			{
				ID:          "aws_admin",
				Label:       "AWS IAM permissions available",
				Description: "An AWS administrator or automation role can create the read-only role and attach required policies.",
				Required:    true,
			},
			{
				ID:          "aws_role",
				Label:       "Read-only role can be assumed",
				Description: "The runtime role allows the Cerebro deployment principal and optional external ID.",
				Required:    true,
			},
			{
				ID:          "aws_regions",
				Label:       "Regions selected",
				Description: "Global IAM and Organizations data is handled separately from regional service families.",
				Required:    true,
			},
		}, common...)
	case "gcp":
		return append([]connectorPrerequisiteView{
			{
				ID:          "gcp_project",
				Label:       "Project or scanner project selected",
				Description: "The source requires a project ID for project-scoped families.",
				Required:    true,
			},
			{
				ID:          "gcp_identity",
				Label:       "Service account or workload identity configured",
				Description: "Use a token or workload identity federation reference resolved outside the browser.",
				Required:    true,
			},
		}, common...)
	default:
		return common
	}
}

func connectorSetupSteps(sourceID string, methodID string) []connectorSetupStepView {
	switch sourceID {
	case "aws":
		return awsConnectorSetupSteps(methodID)
	case "gcp":
		return gcpConnectorSetupSteps(methodID)
	default:
		return []connectorSetupStepView{
			{
				ID:          "choose_method",
				Label:       "Choose authentication path",
				Description: "Select a backend-advertised method and credential store.",
			},
			{
				ID:          "enter_config",
				Label:       "Add non-secret runtime config",
				Description: "Submit required identifiers and references only.",
			},
			{
				ID:          "validate",
				Label:       "Test and save",
				Description: "Run a check-only validation before saving the runtime.",
			},
		}
	}
}

func awsConnectorSetupSteps(methodID string) []connectorSetupStepView {
	steps := []connectorSetupStepView{
		{
			ID:          "account",
			Label:       "Choose account model",
			Description: "Connect one AWS account per runtime. Organization families can be enabled when this account has Organizations read permissions.",
		},
		{
			ID:          "products",
			Label:       "Select resource groups",
			Description: "Resource groups map to runtime families and can be scoped out before source reads.",
		},
		{
			ID:          "permissions",
			Label:       "Create read-only access",
			Description: "Attach AWS SecurityAudit and the additional read actions required by enabled families.",
		},
		{
			ID:          "regions",
			Label:       "Choose regions",
			Description: "Set the default region and keep global families explicit with include_global.",
		},
		{
			ID:          "validate",
			Label:       "Validate, then save",
			Description: "Cerebro runs the source Check path with resolved credentials before storing the runtime.",
		},
	}
	if methodID == connectorAuthMethodAWSSSOProfile {
		steps[2].Commands = []string{
			"aws configure sso --profile cerebro-aws",
			"aws sso login --profile cerebro-aws",
			"aws sts get-caller-identity --profile cerebro-aws",
		}
	}
	return steps
}

func gcpConnectorSetupSteps(methodID string) []connectorSetupStepView {
	steps := []connectorSetupStepView{
		{
			ID:          "project",
			Label:       "Choose project scope",
			Description: "Provide the project ID used for project-scoped GCP families.",
		},
		{
			ID:          "identity",
			Label:       "Configure identity",
			Description: "Use workload identity federation, a service account reference, or a short-lived token resolved server-side.",
		},
		{
			ID:          "apis",
			Label:       "Enable required APIs",
			Description: "Enable IAM, Cloud Asset, STS, IAM Credentials, and the product APIs for selected families.",
		},
		{
			ID:          "scope",
			Label:       "Select resource groups",
			Description: "Turn off resource classes that should not be fetched for this runtime.",
		},
		{
			ID:          "validate",
			Label:       "Validate, then save",
			Description: "Cerebro verifies the selected source family before persisting the runtime.",
		},
	}
	if methodID == connectorAuthMethodInfisicalCLI {
		steps[1].Commands = []string{
			"infisical login",
			"infisical run --env=<env> --path=/cerebro/connectors/gcp -- <start-cerebro>",
		}
	}
	return steps
}

func connectorSetupCommands(sourceID string, methodID string) []string {
	switch methodID {
	case connectorAuthMethodAWSSSOProfile:
		return []string{
			"aws configure sso --profile cerebro-aws",
			"aws sso login --profile cerebro-aws",
			"aws sts get-caller-identity --profile cerebro-aws",
		}
	case connectorAuthMethodInfisicalCLI:
		return []string{
			"infisical login status --json",
			"infisical login",
			"infisical run --env=<env> --path=/cerebro/connectors/" + connectorEnvComponentLower(sourceID) + " -- <start-cerebro>",
		}
	default:
		return nil
	}
}

func connectorProductGroups(sourceID string) []connectorProductGroupView {
	switch sourceID {
	case "aws":
		return []connectorProductGroupView{
			{
				ID:             "core",
				Label:          "Core AWS inventory",
				Description:    "IAM, networking, compute, storage, database, logging, and exposure families.",
				Families:       []string{"cloudtrail", "iam_role", "iam_user", "ec2_instance", "s3_bucket", "security_group", "rds_instance", "kms_key"},
				DefaultEnabled: true,
				Required:       true,
				PermissionNote: "Start with AWS SecurityAudit and add read-only actions for enabled families that are not covered by the managed policy.",
			},
			{
				ID:             "identity_center",
				Label:          "IAM Identity Center",
				Description:    "Identity Center users, groups, permission sets, and account assignments.",
				Families:       []string{"identity_center_account_assignment", "identity_center_permission_set", "identitystore_user", "identitystore_group", "identitystore_group_membership", "sso_instance", "sso_permission_set", "sso_account_assignment"},
				DefaultEnabled: false,
				PermissionNote: "Requires sso-admin, identitystore, and Organizations read permissions.",
			},
			{
				ID:             "organization",
				Label:          "AWS Organizations",
				Description:    "Accounts, organizational units, roots, and policies visible to the configured account.",
				Families:       []string{"organizations_account", "organizations_organizational_unit", "organizations_policy", "organizations_root"},
				DefaultEnabled: false,
				PermissionNote: "Requires Organizations read access from the management or delegated administrator account.",
			},
			{
				ID:             "security_findings",
				Label:          "Security and vulnerability findings",
				Description:    "Inspector, GuardDuty, Security Hub, and Macie finding families.",
				Families:       []string{"inspector2_finding", "guardduty_finding", "securityhub_finding", "macie2_finding"},
				DefaultEnabled: false,
				PermissionNote: "Requires the provider services to be enabled and readable in the selected account and region.",
				CostNote:       "Provider-side scanning services may have their own cost and enablement model.",
			},
		}
	case "gcp":
		return []connectorProductGroupView{
			{
				ID:             "core",
				Label:          "Core GCP inventory",
				Description:    "Compute, storage, IAM, network, project, and service account families.",
				Families:       []string{"resourcemanager_project", "compute_instance", "compute_firewall", "gcs_bucket", "service_account", "iam_role_assignment"},
				DefaultEnabled: true,
				Required:       true,
				PermissionNote: "Grant least-privilege read roles to the scanner service account or workload identity principal.",
			},
			{
				ID:             "audit",
				Label:          "Cloud audit logs",
				Description:    "Cloud Audit log records scoped to the configured project.",
				Families:       []string{"audit"},
				DefaultEnabled: true,
				PermissionNote: "Requires logging read access and audit log retention in the project.",
			},
			{
				ID:             "container_security",
				Label:          "Container and artifact security",
				Description:    "Artifact Registry, Container Registry, GKE, and container vulnerability families.",
				Families:       []string{"artifact_registry_repository", "artifact_registry_image", "container_registry", "container_vulnerability", "gke_cluster", "gke_node_pool"},
				DefaultEnabled: false,
				PermissionNote: "Requires Artifact Registry, Container Analysis, and Kubernetes Engine read permissions.",
			},
		}
	default:
		return nil
	}
}

func connectorDeploymentGuides(sourceID string, methodID string) []connectorDeploymentGuideView {
	switch sourceID {
	case "aws":
		return []connectorDeploymentGuideView{
			{
				ID:          "aws_cli",
				Label:       "AWS CLI validation",
				Language:    "shell",
				Description: "Use after the role/profile exists to confirm the caller identity.",
				Body: strings.Join([]string{
					"aws sts get-caller-identity --profile <profile>",
					"aws iam get-account-summary --profile <profile>",
					"aws cloudtrail describe-trails --region <region> --profile <profile>",
				}, "\n"),
			},
			{
				ID:          "aws_trust_policy",
				Label:       "Role trust policy shape",
				Language:    "json",
				Description: "Create a role that can be assumed by the Cerebro deployment principal. Replace placeholders outside this UI.",
				Body:        awsTrustPolicyGuide(),
			},
			{
				ID:          "aws_role_commands",
				Label:       "Role setup commands",
				Language:    "shell",
				Description: "Attach AWS SecurityAudit and any additional read-only policy needed by selected resource groups.",
				Body: strings.Join([]string{
					"aws iam create-role --role-name CerebroConnectorReadOnly --assume-role-policy-document file://trust-policy.json",
					"aws iam attach-role-policy --role-name CerebroConnectorReadOnly --policy-arn arn:aws:iam::aws:policy/SecurityAudit",
					"aws iam attach-role-policy --role-name CerebroConnectorReadOnly --policy-arn arn:aws:iam::<account-id>:policy/CerebroAdditionalReadOnly",
				}, "\n"),
			},
		}
	case "gcp":
		return []connectorDeploymentGuideView{
			{
				ID:          "gcp_api_enablement",
				Label:       "API enablement",
				Language:    "shell",
				Description: "Enable the baseline APIs before validating a project-scoped runtime.",
				Body: strings.Join([]string{
					"gcloud services enable cloudasset.googleapis.com iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com",
					"gcloud services enable logging.googleapis.com cloudresourcemanager.googleapis.com serviceusage.googleapis.com",
				}, "\n"),
			},
			{
				ID:          "gcp_wif",
				Label:       "Workload identity handoff",
				Language:    "shell",
				Description: "Use deployment automation to create the pool/provider and inject only references into Cerebro.",
				Body: strings.Join([]string{
					"gcloud iam workload-identity-pools create cerebro-connectors --location=global --display-name=\"Cerebro connectors\"",
					"gcloud iam service-accounts create cerebro-connector --display-name=\"Cerebro connector reader\"",
					"gcloud projects add-iam-policy-binding <project-id> --member=serviceAccount:<service-account-email> --role=roles/viewer",
				}, "\n"),
			},
		}
	default:
		if methodID == connectorAuthMethodInfisicalCLI {
			return []connectorDeploymentGuideView{{
				ID:          "infisical",
				Label:       "Infisical environment handoff",
				Language:    "shell",
				Description: "Authenticate outside the browser and inject secret values into the server process.",
				Body: strings.Join([]string{
					"infisical login",
					"infisical run --env=<env> --path=/cerebro/connectors/<source> -- <start-cerebro>",
				}, "\n"),
			}}
		}
		return nil
	}
}

func awsTrustPolicyGuide() string {
	return `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "<cerebro-deployment-principal-arn>"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<external-id>"
        }
      }
    }
  ]
}`
}

func connectorRegionGuidance(sourceID string) *connectorRegionGuidanceView {
	switch sourceID {
	case "aws":
		return &connectorRegionGuidanceView{
			DefaultRegion:       "us-east-1",
			Examples:            []string{"us-east-1", "us-west-2", "eu-west-1"},
			SupportsGlobal:      true,
			SupportsMultiRegion: true,
			Description:         "Create one runtime per account/family/region set as needed. Global IAM and Organizations families should keep include_global enabled unless intentionally scoped out.",
		}
	case "gcp":
		return &connectorRegionGuidanceView{
			DefaultRegion:       "global",
			Examples:            []string{"global", "us-central1", "europe-west1"},
			SupportsGlobal:      true,
			SupportsMultiRegion: true,
			Description:         "Most GCP families are project-scoped. Location-specific families can use location config when required by the source family.",
		}
	default:
		return nil
	}
}

func connectorSecurityNotes(sourceID string, methodID string) []string {
	notes := []string{
		"Connection checks run before save and do not return secret values.",
		"Credential fields are redacted from runtime responses.",
		"Resource scope policy is non-secret and can skip families before source reads.",
	}
	if methodID != connectorAuthMethodEncryptedSubmission {
		notes = append(notes, "Reference-backed methods save only server-resolvable references, not secret material.")
	}
	switch sourceID {
	case "aws":
		notes = append(notes, "Prefer role assumption or AWS SSO over long-lived access keys.")
	case "gcp":
		notes = append(notes, "Prefer workload identity federation or service account references over browser-submitted tokens.")
	}
	return notes
}

func connectorEnvComponentLower(value string) string {
	component := strings.ToLower(connectorEnvComponent(value))
	return strings.ReplaceAll(component, "_", "-")
}

func connectorUnavailableReason(available bool, reason string) string {
	if available {
		return ""
	}
	return reason
}

func connectorStoreAvailable(stores []connectorStoreView, id string) bool {
	for _, store := range stores {
		if store.ID == id {
			return store.Available
		}
	}
	return false
}

func connectorAnyStoreAvailable(stores []connectorStoreView, ids ...string) bool {
	for _, id := range ids {
		if connectorStoreAvailable(stores, id) {
			return true
		}
	}
	return false
}

func normalizeConnectorAuthMethod(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return connectorAuthMethodEncryptedSubmission
	}
	return trimmed
}

func normalizeConnectorCredentialStoreID(value string, authMethod string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		switch authMethod {
		case connectorAuthMethodEncryptedSubmission:
			return defaultConnectorCredentialStoreID, nil
		case connectorAuthMethodExternalReference:
			return "", fmt.Errorf("%w: credential_store_id is required for external references", connectorcredentials.ErrInvalidRequest)
		default:
			return connectorStoreEnvironmentManaged, nil
		}
	}
	switch authMethod {
	case connectorAuthMethodEncryptedSubmission:
		if trimmed != defaultConnectorCredentialStoreID {
			return "", fmt.Errorf("%w: credential store is not available for encrypted submission", connectorcredentials.ErrInvalidRequest)
		}
	case connectorAuthMethodAWSSSOProfile, connectorAuthMethodInfisicalCLI, connectorAuthMethodEnvironmentManaged:
		if trimmed != connectorStoreEnvironmentManaged {
			return "", fmt.Errorf("%w: credential store is not available for environment-managed references", connectorcredentials.ErrInvalidRequest)
		}
	case connectorAuthMethodExternalReference:
		if !connectorExternalReferenceStore(trimmed) {
			return "", fmt.Errorf("%w: credential store is not available for external references", connectorcredentials.ErrInvalidRequest)
		}
	default:
		return "", fmt.Errorf("%w: credential store is not available", connectorcredentials.ErrInvalidRequest)
	}
	return trimmed, nil
}

func connectorExternalReferenceStore(id string) bool {
	switch strings.TrimSpace(id) {
	case connectorStoreInfisical, connectorStoreGoogleSecretMgr, connectorStoreAWSSecretsManager, connectorStoreAzureKeyVault, connectorStoreHashiCorpVault:
		return true
	default:
		return false
	}
}

func connectorCredentialAdditionalData(keyID string, sourceID string, tenantID string, runtimeID string, credentialStoreID string) []byte {
	return connectorcredentials.TransitAdditionalData(keyID, sourceID, tenantID, runtimeID, credentialStoreID)
}

func (a *App) authorizeConnectorCredentialRuntime(ctx context.Context, sourceID string, tenantID string, runtimeID string) error {
	if err := authorizeTenantScopeRequired(ctx, tenantID); err != nil {
		return err
	}
	store := sourceRuntimeStore(a.deps.StateStore)
	if store == nil {
		return nil
	}
	existing, err := store.GetSourceRuntime(ctx, runtimeID)
	switch {
	case err == nil:
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return nil
	default:
		return err
	}
	if strings.TrimSpace(existing.GetTenantId()) != strings.TrimSpace(tenantID) {
		return errTenantForbidden
	}
	if err := authorizeTenantScopeRequired(ctx, existing.GetTenantId()); err != nil {
		return err
	}
	if strings.TrimSpace(existing.GetSourceId()) != strings.TrimSpace(sourceID) {
		return fmt.Errorf("%w: runtime belongs to a different connector source", connectorcredentials.ErrInvalidRequest)
	}
	return nil
}

func connectorRuntimeConfig(input map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(input))
	for key, value := range input {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if sourceconfig.InternalKey(trimmedKey) || trimmedKey == resourcescope.ConfigKey {
			return nil, fmt.Errorf("%w: internal config %q cannot be supplied by connector requests", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		if sourceconfig.SensitiveKey(trimmedKey) && strings.TrimSpace(value) != "" && !sourceconfig.IsCredentialReference(value) {
			return nil, fmt.Errorf("%w: sensitive config %q must be supplied in encrypted_credentials", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		config[trimmedKey] = value
	}
	return config, nil
}

func applyConnectorCredentialReferences(config map[string]string, references map[string]string) error {
	for key, value := range references {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" {
			return fmt.Errorf("%w: credential reference key and value are required", connectorcredentials.ErrInvalidRequest)
		}
		if sourceconfig.InternalKey(trimmedKey) || trimmedKey == resourcescope.ConfigKey {
			return fmt.Errorf("%w: internal config %q cannot be supplied by connector references", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		if !connectorsecretstores.IsReference(trimmedValue) {
			return fmt.Errorf("%w: credential reference %q must use an env or connector secret-store reference", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		config[trimmedKey] = trimmedValue
	}
	return nil
}

func validateConnectorConnectionShape(sourceID string, tenantID string, runtimeID string, authMethod string, credentialStoreID string, config map[string]string, references map[string]string, encrypted connectorcredentials.EncryptedPayload) error {
	switch authMethod {
	case connectorAuthMethodEncryptedSubmission:
		if credentialStoreID != defaultConnectorCredentialStoreID {
			return fmt.Errorf("%w: encrypted submission requires Cerebro Vault", connectorcredentials.ErrInvalidRequest)
		}
		if len(references) > 0 {
			return fmt.Errorf("%w: encrypted submission cannot include credential references", connectorcredentials.ErrInvalidRequest)
		}
		if !connectorEncryptedPayloadPresent(encrypted) {
			return fmt.Errorf("%w: encrypted_credentials is required", connectorcredentials.ErrInvalidRequest)
		}
	case connectorAuthMethodAWSSSOProfile:
		if strings.TrimSpace(sourceID) != "aws" {
			return fmt.Errorf("%w: aws_sso_profile is only available for aws", connectorcredentials.ErrInvalidRequest)
		}
		if credentialStoreID != connectorStoreEnvironmentManaged {
			return fmt.Errorf("%w: aws_sso_profile requires environment-managed storage", connectorcredentials.ErrInvalidRequest)
		}
		if connectorEncryptedPayloadPresent(encrypted) {
			return fmt.Errorf("%w: aws_sso_profile cannot include encrypted credentials", connectorcredentials.ErrInvalidRequest)
		}
		if len(references) > 0 {
			return fmt.Errorf("%w: aws_sso_profile cannot include credential references", connectorcredentials.ErrInvalidRequest)
		}
		if strings.TrimSpace(config["profile"]) == "" {
			return fmt.Errorf("%w: aws_sso_profile requires profile", connectorcredentials.ErrInvalidRequest)
		}
	case connectorAuthMethodInfisicalCLI, connectorAuthMethodEnvironmentManaged:
		if credentialStoreID != connectorStoreEnvironmentManaged {
			return fmt.Errorf("%w: environment-managed auth requires environment-managed storage", connectorcredentials.ErrInvalidRequest)
		}
		if connectorEncryptedPayloadPresent(encrypted) {
			return fmt.Errorf("%w: environment-managed auth cannot include encrypted credentials", connectorcredentials.ErrInvalidRequest)
		}
		if authMethod == connectorAuthMethodInfisicalCLI && len(references) == 0 {
			return fmt.Errorf("%w: infisical_cli requires credential references", connectorcredentials.ErrInvalidRequest)
		}
		if err := validateConnectorCredentialReferencesForRuntime(connectorStoreEnvironmentManaged, sourceID, tenantID, runtimeID, references); err != nil {
			return err
		}
	case connectorAuthMethodExternalReference:
		if !connectorExternalReferenceStore(credentialStoreID) {
			return fmt.Errorf("%w: external_reference requires an external credential store", connectorcredentials.ErrInvalidRequest)
		}
		if connectorEncryptedPayloadPresent(encrypted) {
			return fmt.Errorf("%w: external_reference cannot include encrypted credentials", connectorcredentials.ErrInvalidRequest)
		}
		if len(references) == 0 {
			return fmt.Errorf("%w: external_reference requires credential references", connectorcredentials.ErrInvalidRequest)
		}
		if err := validateConnectorCredentialReferencesForRuntime(credentialStoreID, sourceID, tenantID, runtimeID, references); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported auth method", connectorcredentials.ErrInvalidRequest)
	}
	if err := validateConnectorConfigFields(sourceID, authMethod, config, references); err != nil {
		return err
	}
	return nil
}

func validateConnectorCredentialReferencesForRuntime(storeID string, sourceID string, tenantID string, runtimeID string, references map[string]string) error {
	for key, value := range references {
		if err := connectorsecretstores.ValidateReferenceForStore(storeID, value); err != nil {
			return fmt.Errorf("%w: credential reference %q is not valid for %s", connectorcredentials.ErrInvalidRequest, strings.TrimSpace(key), strings.TrimSpace(storeID))
		}
		if err := connectorsecretstores.AuthorizeRuntimeReferences(sourceID, tenantID, runtimeID, map[string]string{key: value}); err != nil {
			return fmt.Errorf("%w: credential reference %q is not scoped to this runtime: %w", connectorcredentials.ErrInvalidRequest, strings.TrimSpace(key), err)
		}
	}
	return nil
}

func connectorAuthMethodUsesCredentialReferences(authMethod string) bool {
	switch normalizeConnectorAuthMethod(authMethod) {
	case connectorAuthMethodEnvironmentManaged, connectorAuthMethodInfisicalCLI, connectorAuthMethodExternalReference:
		return true
	default:
		return false
	}
}

func connectorReferenceTemplateFields(sourceID string, authMethod string, references map[string]string) []string {
	if normalizeConnectorAuthMethod(authMethod) == connectorAuthMethodEncryptedSubmission {
		return sortedStringKeys(references)
	}
	schema, ok := connectorSchemaForSource(sourceID)
	if !ok || len(schema.CredentialKeys) == 0 {
		return sortedStringKeys(references)
	}
	return sortedSetKeys(schema.CredentialKeys)
}

func validateConnectorConfigFields(sourceID string, authMethod string, config map[string]string, references map[string]string) error {
	schema, ok := connectorSchemaForSource(sourceID)
	if !ok {
		return nil
	}
	for key := range config {
		if sourceconfig.InternalKey(key) || key == resourcescope.ConfigKey {
			continue
		}
		if authMethod == connectorAuthMethodAWSSSOProfile && key == "profile" {
			continue
		}
		if _, ok := schema.ConfigKeys[key]; ok {
			continue
		}
		if _, ok := references[key]; ok {
			if _, credentialOK := schema.CredentialKeys[key]; credentialOK {
				continue
			}
		}
		return fmt.Errorf("%w: unsupported connector config %q", connectorcredentials.ErrInvalidRequest, key)
	}
	for _, key := range schema.RequiredConfig {
		if strings.TrimSpace(config[key]) == "" {
			return fmt.Errorf("%w: connector config %q is required", connectorcredentials.ErrInvalidRequest, key)
		}
	}
	if authMethod == connectorAuthMethodEncryptedSubmission || authMethod == connectorAuthMethodAWSSSOProfile {
		return nil
	}
	for _, key := range schema.RequiredCredentials {
		if strings.TrimSpace(config[key]) == "" {
			return fmt.Errorf("%w: credential reference %q is required", connectorcredentials.ErrInvalidRequest, key)
		}
	}
	return nil
}

func validateConnectorCredentialFields(sourceID string, authMethod string, fields map[string]string) error {
	if authMethod != connectorAuthMethodEncryptedSubmission {
		return nil
	}
	schema, ok := connectorSchemaForSource(sourceID)
	if !ok {
		return nil
	}
	for key := range fields {
		if _, ok := schema.CredentialKeys[key]; !ok {
			return fmt.Errorf("%w: unsupported credential field %q", connectorcredentials.ErrInvalidRequest, key)
		}
	}
	for _, key := range schema.RequiredCredentials {
		if strings.TrimSpace(fields[key]) == "" {
			return fmt.Errorf("%w: credential field %q is required", connectorcredentials.ErrInvalidRequest, key)
		}
	}
	return nil
}

func connectorEncryptedPayloadPresent(payload connectorcredentials.EncryptedPayload) bool {
	return strings.TrimSpace(payload.KeyID) != "" ||
		strings.TrimSpace(payload.Algorithm) != "" ||
		strings.TrimSpace(payload.WrappedKey) != "" ||
		strings.TrimSpace(payload.Nonce) != "" ||
		strings.TrimSpace(payload.Ciphertext) != ""
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return sortedSetKeys(set)
}

func copyStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func setContains(values map[string]struct{}, key string) bool {
	_, ok := values[key]
	return ok
}

func connectorCredentialViewFromRecord(record *ports.ConnectorCredentialRecord) connectorCredentialView {
	if record == nil {
		return connectorCredentialView{}
	}
	return connectorCredentialView{
		ID:                   record.ID,
		TenantID:             record.TenantID,
		SourceID:             record.SourceID,
		RuntimeID:            record.RuntimeID,
		StoreID:              firstNonEmpty(record.CredentialStoreID, defaultConnectorCredentialStoreID),
		AuthMethod:           firstNonEmpty(record.AuthMethod, connectorAuthMethodEncryptedSubmission),
		Status:               firstNonEmpty(record.Status, connectorcredentials.StatusValid),
		KeyID:                record.KeyID,
		Fields:               append([]string{}, record.Fields...),
		CreatedBy:            record.CreatedBy,
		UpdatedBy:            record.UpdatedBy,
		RevokedBy:            record.RevokedBy,
		PreviousCredentialID: record.PreviousCredentialID,
		CreatedAt:            connectorcredentials.TimestampOrZero(record.CreatedAt),
		UpdatedAt:            connectorcredentials.TimestampOrZero(record.UpdatedAt),
		RevokedAt:            connectorcredentials.TimestampOrZero(record.RevokedAt),
		LastUsedAt:           connectorcredentials.TimestampOrZero(record.LastUsedAt),
		LastValidatedAt:      connectorcredentials.TimestampOrZero(record.LastValidatedAt),
	}
}

func connectorCredentialAuditViews(events []*ports.ConnectorCredentialAuditRecord) []connectorCredentialAuditView {
	views := make([]connectorCredentialAuditView, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		views = append(views, connectorCredentialAuditView{
			ID:           event.ID,
			CredentialID: event.CredentialID,
			TenantID:     event.TenantID,
			SourceID:     event.SourceID,
			RuntimeID:    event.RuntimeID,
			EventType:    event.EventType,
			Actor:        event.Actor,
			Status:       event.Status,
			Detail:       event.Detail,
			CreatedAt:    connectorcredentials.TimestampOrZero(event.CreatedAt),
		})
	}
	return views
}

func connectorCredentialActor(r *http.Request) string {
	if r == nil {
		return ""
	}
	if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
		if name := strings.TrimSpace(auth.principal.Name); name != "" {
			return name
		}
		if clientID := strings.TrimSpace(auth.principal.ClientID); clientID != "" {
			return clientID
		}
		if credentialID := strings.TrimSpace(auth.principal.CredentialID); credentialID != "" {
			return credentialID
		}
	}
	return ""
}

func connectorCredentialIdempotencyKey(r *http.Request, bodyValue string) string {
	if value := strings.TrimSpace(bodyValue); value != "" {
		return value
	}
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("Idempotency-Key"))
}

func connectorQueryInt(r *http.Request, key string, defaultValue int, maxValue int) (int, error) {
	if r == nil || r.URL == nil {
		return defaultValue, nil
	}
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%w: query parameter %q must be a non-negative integer", connectorcredentials.ErrInvalidRequest, key)
	}
	if maxValue > 0 && parsed > maxValue {
		return maxValue, nil
	}
	return parsed, nil
}

func connectorCredentialBroker(credentialConfig config.ConnectorCredentialConfig, store ports.StateStore, transit *connectorcredentials.TransitKey) (*connectorcredentials.Broker, error) {
	vault, err := connectorCredentialVault(credentialConfig, store)
	if err != nil {
		return nil, err
	}
	return connectorcredentials.NewBroker(vault, transit), nil
}

func connectorCredentialVault(credentialConfig config.ConnectorCredentialConfig, store ports.StateStore) (*connectorcredentials.Vault, error) {
	credentialStore := connectorCredentialStore(store)
	if credentialStore == nil {
		return nil, connectorcredentials.ErrUnavailable
	}
	return connectorcredentials.NewVault(credentialStore, credentialConfig.Key)
}

func connectorCredentialStore(store ports.StateStore) ports.ConnectorCredentialStore {
	credentialStore, ok := store.(ports.ConnectorCredentialStore)
	if !ok || isNilInterface(credentialStore) {
		return nil
	}
	return credentialStore
}

func connectorVaultStatus(credentialConfig config.ConnectorCredentialConfig, store ports.StateStore) connectorVaultView {
	if connectorCredentialStore(store) == nil {
		return connectorVaultView{Available: false, Detail: "state store unavailable"}
	}
	if strings.TrimSpace(credentialConfig.Key) == "" {
		return connectorVaultView{Available: false, Detail: "credential key unavailable"}
	}
	return connectorVaultView{Available: true}
}

func readConnectorJSON(r *http.Request, value any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("%w: request body is required", connectorcredentials.ErrInvalidRequest)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProtoJSONBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read request body: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	if len(body) > maxProtoJSONBodyBytes {
		return fmt.Errorf("%w: request JSON body exceeds maximum size", connectorcredentials.ErrInvalidRequest)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("%w: request body is required", connectorcredentials.ErrInvalidRequest)
	}
	if err := json.Unmarshal(body, value); err != nil {
		return fmt.Errorf("%w: decode request JSON: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	return nil
}

func writeConnectorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ports.ErrConnectorCredentialNotFound),
		errors.Is(err, ports.ErrConnectorDefinitionNotFound),
		errors.Is(err, ports.ErrSourceRuntimeNotFound),
		errors.Is(err, sourceops.ErrSourceNotFound):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case errors.Is(err, connectorcredentials.ErrInvalidRequest),
		errors.Is(err, sourceops.ErrInvalidRequest),
		errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, errInvalidHTTPRequest):
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case errors.Is(err, connectorcredentials.ErrUnavailable),
		errors.Is(err, sourceruntime.ErrRuntimeUnavailable):
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	case errors.Is(err, errTenantForbidden),
		errors.Is(err, errConnectorAccessRestricted):
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
