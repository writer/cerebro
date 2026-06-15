package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const (
	defaultConnectorCredentialStoreID = "cerebro_vault"
	connectorStoreEnvironmentManaged  = "environment_managed"

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
)

type connectorCatalogEntry struct {
	SourceID               string                          `json:"source_id"`
	Name                   string                          `json:"name"`
	DisplayName            string                          `json:"display_name"`
	Description            string                          `json:"description"`
	EmittedKinds           []string                        `json:"emitted_kinds"`
	Status                 string                          `json:"status"`
	ConfiguredRuntimes     int                             `json:"configured_runtimes"`
	HealthyRuntimes        int                             `json:"healthy_runtimes"`
	NeedsAttentionRuntimes int                             `json:"needs_attention_runtimes"`
	ConnectionMethods      []connectorConnectionMethodView `json:"connection_methods,omitempty"`
}

type connectorLibraryResponse struct {
	Connectors          []connectorCatalogEntry `json:"connectors"`
	TenantID            string                  `json:"tenant_id,omitempty"`
	RuntimeStore        string                  `json:"runtime_store"`
	CredentialTransport connectorTransportView  `json:"credential_transport"`
	CredentialVault     connectorVaultView      `json:"credential_vault"`
	CredentialStores    []connectorStoreView    `json:"credential_stores,omitempty"`
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
	ID        string `json:"id"`
	Label     string `json:"label"`
	Provider  string `json:"provider"`
	Available bool   `json:"available"`
	Default   bool   `json:"default,omitempty"`
	Mode      string `json:"mode"`
	Detail    string `json:"detail,omitempty"`
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
	ID                string               `json:"id"`
	Label             string               `json:"label"`
	Description       string               `json:"description"`
	CredentialStores  []string             `json:"credential_stores,omitempty"`
	ConfigFields      []connectorFieldView `json:"config_fields,omitempty"`
	CredentialFields  []connectorFieldView `json:"credential_fields,omitempty"`
	RequiresSecrets   bool                 `json:"requires_secrets"`
	Saveable          bool                 `json:"saveable"`
	UnavailableReason string               `json:"unavailable_reason,omitempty"`
}

type connectorConnectionRequest struct {
	RuntimeID            string                                `json:"runtime_id"`
	TenantID             string                                `json:"tenant_id"`
	CheckOnly            bool                                  `json:"check_only,omitempty"`
	AuthMethod           string                                `json:"auth_method,omitempty"`
	CredentialStoreID    string                                `json:"credential_store_id,omitempty"`
	Config               map[string]string                     `json:"config"`
	CredentialReferences map[string]string                     `json:"credential_references,omitempty"`
	EncryptedCredentials connectorcredentials.EncryptedPayload `json:"encrypted_credentials"`
}

type connectorConnectionResponse struct {
	SourceID   string                  `json:"source_id"`
	Runtime    json.RawMessage         `json:"runtime"`
	Credential connectorCredentialView `json:"credential"`
	Status     string                  `json:"status,omitempty"`
}

type connectorCredentialView struct {
	ID         string   `json:"id"`
	TenantID   string   `json:"tenant_id"`
	SourceID   string   `json:"source_id"`
	RuntimeID  string   `json:"runtime_id"`
	StoreID    string   `json:"credential_store_id"`
	AuthMethod string   `json:"auth_method"`
	KeyID      string   `json:"key_id"`
	Fields     []string `json:"fields"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

func (a *App) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeConnectorError(w, err)
		return
	}
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
	stores := connectorStoreViews(vaultStatus, transport)
	entries := make([]connectorCatalogEntry, 0, len(sources))
	for _, source := range sources {
		entry := connectorCatalogEntry{
			SourceID:          source.GetId(),
			Name:              source.GetName(),
			DisplayName:       connectorDisplayName(source.GetId(), source.GetName()),
			Description:       source.GetDescription(),
			EmittedKinds:      append([]string{}, source.GetEmittedKinds()...),
			Status:            "available",
			ConnectionMethods: connectorConnectionMethods(source.GetId(), stores),
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
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	writeJSON(w, http.StatusOK, connectorLibraryResponse{
		Connectors:          entries,
		TenantID:            tenantID,
		RuntimeStore:        runtimeStoreStatus,
		CredentialTransport: transport,
		CredentialVault:     vaultStatus,
		CredentialStores:    stores,
	})
}

func (a *App) handleConnectorCredentialKey(w http.ResponseWriter, _ *http.Request) {
	if a == nil || a.connectorTransitKey == nil {
		writeConnectorError(w, connectorcredentials.ErrUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, a.connectorTransitKey.PublicKey())
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
	runtimeID := strings.TrimSpace(request.RuntimeID)
	tenantID := strings.TrimSpace(request.TenantID)
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
	runtimeConfig, err := connectorRuntimeConfig(request.Config)
	if err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := applyConnectorCredentialReferences(runtimeConfig, request.CredentialReferences); err != nil {
		writeConnectorError(w, err)
		return
	}
	if err := validateConnectorConnectionShape(sourceID, authMethod, credentialStoreID, runtimeConfig, request.CredentialReferences, request.EncryptedCredentials); err != nil {
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
			SourceID:   sourceID,
			Runtime:    runtimePayload,
			Credential: credential,
			Status:     "checked",
		})
		return
	}
	if authMethod == connectorAuthMethodEncryptedSubmission {
		vault, err := connectorCredentialVault(a.cfg.ConnectorCredentials, a.deps.StateStore)
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		record, err := vault.Put(r.Context(), connectorcredentials.PlainCredential{
			TenantID:  tenantID,
			SourceID:  sourceID,
			RuntimeID: runtimeID,
			Fields:    plaintextFields,
		})
		if err != nil {
			writeConnectorError(w, err)
			return
		}
		for _, field := range connectorcredentials.SortedFieldNames(plaintextFields) {
			runtime.Config[field] = connectorcredentials.Reference(record.ID, field)
		}
		credential.ID = record.ID
		credential.KeyID = record.KeyID
		credential.Fields = connectorcredentials.SortedFieldNames(plaintextFields)
		credential.CreatedAt = connectorcredentials.TimestampOrZero(record.CreatedAt)
		credential.UpdatedAt = connectorcredentials.TimestampOrZero(record.UpdatedAt)
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
		SourceID:   sourceID,
		Runtime:    json.RawMessage(runtimePayload),
		Credential: credential,
	})
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
		ConfigKeys:          stringSet("family"),
		CredentialKeys:      stringSet("api_key"),
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
		ConfigKeys:          stringSet("domain", "family", "customer_id", "group_key"),
		CredentialKeys:      stringSet("token"),
		RequiredConfig:      []string{"domain"},
		RequiredCredentials: []string{"token"},
	},
	"okta": {
		ConfigKeys:          stringSet("domain", "family"),
		CredentialKeys:      stringSet("token"),
		RequiredConfig:      []string{"domain"},
		RequiredCredentials: []string{"token"},
	},
	"openai": {
		ConfigKeys:          stringSet("family"),
		CredentialKeys:      stringSet("api_key"),
		RequiredCredentials: []string{"api_key"},
	},
	"bootstrap_token": {
		ConfigKeys:          stringSet("family"),
		CredentialKeys:      stringSet("token"),
		RequiredCredentials: []string{"token"},
	},
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
	source, err := a.connectorSource(runtime.GetSourceId())
	if err != nil {
		return err
	}
	values := copyStringMap(runtime.GetConfig())
	for key, value := range plaintextFields {
		values[key] = value
	}
	values = sourceconfig.WithRuntimeContext(values, runtime.GetTenantId(), runtime.GetId())
	resolved, err := resolveRuntimeSourceConfigWithStore(ctx, a.cfg.ConnectorCredentials, a.deps.StateStore, runtime.GetSourceId(), values)
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
	schema, ok := connectorSchemas[strings.TrimSpace(sourceID)]
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
	schema, ok := connectorSchemas[strings.TrimSpace(sourceID)]
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

func connectorStoreViews(vaultStatus connectorVaultView, transport connectorTransportView) []connectorStoreView {
	available := vaultStatus.Available && transport.Available
	detail := strings.TrimSpace(vaultStatus.Detail)
	if available {
		detail = "ready"
	}
	return []connectorStoreView{
		{
			ID:        defaultConnectorCredentialStoreID,
			Label:     "Cerebro Vault",
			Provider:  "Cerebro",
			Available: available,
			Default:   true,
			Mode:      "encrypted_submission",
			Detail:    detail,
		},
		{
			ID:        connectorStoreEnvironmentManaged,
			Label:     "Environment managed",
			Provider:  "Deployment",
			Available: true,
			Mode:      "environment_managed",
			Detail:    "ready",
		},
		{
			ID:        connectorStoreInfisical,
			Label:     "Infisical",
			Provider:  "Infisical",
			Available: true,
			Mode:      connectorCredentialStoreModeRefs,
			Detail:    "reference-backed",
		},
		{
			ID:        connectorStoreGoogleSecretMgr,
			Label:     "Google Secret Manager",
			Provider:  "Google Cloud Platform",
			Available: true,
			Mode:      connectorCredentialStoreModeRefs,
			Detail:    "reference-backed",
		},
		{
			ID:        connectorStoreAWSSecretsManager,
			Label:     "AWS Secrets Manager",
			Provider:  "Amazon Web Services",
			Available: true,
			Mode:      connectorCredentialStoreModeRefs,
			Detail:    "reference-backed",
		},
		{
			ID:        connectorStoreAzureKeyVault,
			Label:     "Azure Key Vault",
			Provider:  "Microsoft Azure",
			Available: true,
			Mode:      connectorCredentialStoreModeRefs,
			Detail:    "reference-backed",
		},
		{
			ID:        connectorStoreHashiCorpVault,
			Label:     "HashiCorp Vault",
			Provider:  "HashiCorp",
			Available: true,
			Mode:      connectorCredentialStoreModeRefs,
			Detail:    "reference-backed",
		},
	}
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
			Description:       "Submit one encrypted credential payload to Cerebro Vault.",
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
			Description:       "Use AWS CLI SSO and save a deployment-managed profile/role runtime.",
			CredentialStores:  []string{connectorStoreEnvironmentManaged},
			ConfigFields:      connectorConfigFields(sourceID, connectorAuthMethodAWSSSOProfile),
			Saveable:          environmentAvailable,
			UnavailableReason: connectorUnavailableReason(environmentAvailable, "Environment-managed AWS profiles are unavailable."),
		}}, methods...)
	}
	return methods
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
	parts := []string{
		"connector-credential",
		"v1",
		strings.TrimSpace(keyID),
		strings.TrimSpace(sourceID),
		strings.TrimSpace(tenantID),
		strings.TrimSpace(runtimeID),
		strings.TrimSpace(credentialStoreID),
	}
	return []byte(strings.Join(parts, "\x00"))
}

func connectorRuntimeConfig(input map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(input))
	for key, value := range input {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if sourceconfig.InternalKey(trimmedKey) {
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
		if sourceconfig.InternalKey(trimmedKey) {
			return fmt.Errorf("%w: internal config %q cannot be supplied by connector references", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		if !sourceconfig.IsSecretReference(trimmedValue) {
			return fmt.Errorf("%w: credential reference %q must use an env reference", connectorcredentials.ErrInvalidRequest, trimmedKey)
		}
		config[trimmedKey] = trimmedValue
	}
	return nil
}

func validateConnectorConnectionShape(sourceID string, authMethod string, credentialStoreID string, config map[string]string, references map[string]string, encrypted connectorcredentials.EncryptedPayload) error {
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
	default:
		return fmt.Errorf("%w: unsupported auth method", connectorcredentials.ErrInvalidRequest)
	}
	if err := validateConnectorConfigFields(sourceID, authMethod, config, references); err != nil {
		return err
	}
	return nil
}

func validateConnectorConfigFields(sourceID string, authMethod string, config map[string]string, references map[string]string) error {
	schema, ok := connectorSchemas[strings.TrimSpace(sourceID)]
	if !ok {
		return nil
	}
	for key := range config {
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
	schema, ok := connectorSchemas[strings.TrimSpace(sourceID)]
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
	case errors.Is(err, errTenantForbidden):
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
