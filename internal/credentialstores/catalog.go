package credentialstores

import (
	"strings"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/connectorsecretstores"
)

type CatalogInput struct {
	CredentialKeyConfigured  bool
	CredentialStoreAvailable bool
	CredentialStoreDetail    string
	TransitAvailable         bool
	SecretStoreConfiguration config.ConnectorSecretStoreConfig
}

func Catalog(input CatalogInput) []StoreMetadata {
	vaultAvailable := input.CredentialStoreAvailable && input.CredentialKeyConfigured && input.TransitAvailable
	vaultStatus := "unavailable"
	vaultDetail := strings.TrimSpace(input.CredentialStoreDetail)
	if vaultAvailable {
		vaultStatus = "ready"
		vaultDetail = "ready"
	}
	if vaultDetail == "" {
		switch {
		case !input.CredentialStoreAvailable:
			vaultDetail = "state store unavailable"
		case !input.CredentialKeyConfigured:
			vaultDetail = "credential key unavailable"
		case !input.TransitAvailable:
			vaultDetail = "credential transit key unavailable"
		}
	}
	return []StoreMetadata{
		{
			ID:          DefaultStoreID,
			Label:       "Cerebro Vault",
			Provider:    "Cerebro",
			Available:   vaultAvailable,
			Default:     true,
			Mode:        "encrypted_submission",
			Status:      vaultStatus,
			Detail:      vaultDetail,
			Description: "Cerebro stores one sealed credential envelope in its state store. The browser submits secrets only after encrypting them to the backend transit key.",
			SetupSteps: []SetupStep{
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
			},
			RequiredConfig: []ConfigField{
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
			ID:                         EnvironmentManagedID,
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
			SetupSteps: []SetupStep{
				{
					ID:          "project_env",
					Label:       "Project secrets into the Cerebro runtime",
					Description: "Set source-scoped CEREBRO_SOURCE_<SOURCE>_<FIELD> variables or allow explicit shared env names with CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST.",
				},
			},
		},
		externalStore(input.SecretStoreConfiguration, InfisicalID, "Infisical", "Infisical"),
		externalStore(input.SecretStoreConfiguration, GoogleSecretManagerID, "Google Secret Manager", "Google Cloud Platform"),
		externalStore(input.SecretStoreConfiguration, AWSSecretsManagerID, "AWS Secrets Manager", "Amazon Web Services"),
		externalStore(input.SecretStoreConfiguration, AzureKeyVaultID, "Azure Key Vault", "Microsoft Azure"),
		externalStore(input.SecretStoreConfiguration, HashiCorpVaultID, "HashiCorp Vault", "HashiCorp"),
	}
}

func externalStore(secretStoreConfig config.ConnectorSecretStoreConfig, id string, label string, provider string) StoreMetadata {
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
	if id == AWSSecretsManagerID && !native {
		referencePrefixes = []string{"env:"}
	}
	return StoreMetadata{
		ID:                         id,
		Label:                      label,
		Provider:                   provider,
		Available:                  enabled,
		Mode:                       "reference",
		Status:                     status,
		Detail:                     detail,
		Description:                externalStoreDescription(id, label),
		ReferencePrefixes:          referencePrefixes,
		ReferenceNamespaceTemplate: referenceNamespaceTemplate(id, native),
		ReferenceFieldTemplate:     referenceFieldTemplate(id, native),
		ReferencePlaceholder:       referencePlaceholder(id, native),
		NativeResolutionAvailable:  native,
		SetupSteps:                 externalStoreSetupSteps(id, native),
		RequiredConfig:             externalStoreRequiredConfig(id),
	}
}

func externalStoreDescription(id string, label string) string {
	if id == AWSSecretsManagerID {
		return "Cerebro can resolve aws-sm: references natively when AWS resolver config is present, or consume env: references projected by deployment automation."
	}
	return label + " references are saved as non-secret pointers. Configure deployment-side projection to env: references until a native backend resolver is enabled for this store."
}

func referencePlaceholder(id string, native bool) string {
	if id == AWSSecretsManagerID && native {
		return "aws-sm:us-east-1:cerebro/<tenant>/<source>/<runtime>/credentials#<field>"
	}
	return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>"
}

func referenceNamespaceTemplate(id string, native bool) string {
	if id == AWSSecretsManagerID && native {
		return "cerebro/<tenant>/<source>/<runtime>/credentials"
	}
	return "CEREBRO_SOURCE_<SOURCE>_*"
}

func referenceFieldTemplate(id string, native bool) string {
	if id == AWSSecretsManagerID && native {
		return "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>"
	}
	return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>"
}

func externalStoreSetupSteps(id string, native bool) []SetupStep {
	steps := []SetupStep{
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
	if id == AWSSecretsManagerID {
		description := "Set CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION to enable native aws-sm: resolution with the AWS SDK."
		if native {
			description = "Native aws-sm: resolution is enabled for this deployment."
		}
		steps = append(steps, SetupStep{
			ID:          "configure_native_resolver",
			Label:       "Configure native AWS resolution",
			Description: description,
			Command:     "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION=us-east-1",
		})
	}
	return steps
}

func externalStoreRequiredConfig(id string) []ConfigField {
	fields := []ConfigField{
		{
			Env:         "CEREBRO_CONNECTOR_SECRET_STORES",
			Label:       "Enabled connector secret stores",
			Required:    true,
			Description: "Comma-separated store ids that this deployment accepts for connector credential references.",
		},
	}
	if id != AWSSecretsManagerID {
		return fields
	}
	return append(fields,
		ConfigField{
			Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_REGION",
			Label:       "AWS resolver region",
			Description: "Default region used when aws-sm: references do not include a region.",
		},
		ConfigField{
			Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_PROFILE",
			Label:       "AWS shared config profile",
			Description: "Optional shared AWS config profile used by the backend resolver.",
		},
		ConfigField{
			Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_ROLE_ARN",
			Label:       "AWS resolver role",
			Description: "Optional role the backend assumes before reading secrets.",
		},
		ConfigField{
			Env:         "CEREBRO_CONNECTOR_AWS_SECRETS_MANAGER_EXTERNAL_ID",
			Label:       "AWS external ID",
			Description: "Optional external ID used with the resolver role.",
		},
	)
}
