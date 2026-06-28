package sourcedeploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

const ContractSchemaVersion = "cerebro.runtime-deploy-contract/v1"

type ContractOptions struct {
	Environment string
	TenantID    string
	ImageTag    string
}

type Contract struct {
	SchemaVersion           string                   `json:"schema_version"`
	ImageTag                string                   `json:"image_tag,omitempty"`
	Environment             string                   `json:"environment"`
	TenantID                string                   `json:"tenant_id"`
	RequiredSecrets         []string                 `json:"required_secrets"`
	RuntimeProfiles         []ContractRuntimeProfile `json:"runtime_profiles"`
	RequiredEnvVars         []ContractEnvVar         `json:"required_env_vars"`
	RequiredBackingServices []ContractBackingService `json:"required_backing_services"`
	OptionalCapabilities    []ContractCapability     `json:"optional_capabilities"`
	PostDeployHealthChecks  []ContractHealthCheck    `json:"post_deploy_health_checks"`
	CompatibilityNotes      []string                 `json:"compatibility_notes"`
	Sources                 []ContractSource         `json:"sources"`
}

type ContractSource struct {
	SourceID                 string                      `json:"source_id"`
	EmittedKinds             []string                    `json:"emitted_kinds,omitempty"`
	SupportedFamilies        []string                    `json:"supported_families,omitempty"`
	RequiredSecrets          []string                    `json:"required_secrets,omitempty"`
	RoleAssumptionConfigKeys []string                    `json:"role_assumption_config_keys,omitempty"`
	SourceHealthReceipt      map[string]any              `json:"source_health_receipt,omitempty"`
	CoverageContract         *sourcecdk.CoverageContract `json:"coverage_contract,omitempty"`
	Runtimes                 []ContractRuntime           `json:"runtimes,omitempty"`
}

type ContractRuntime struct {
	ID              string            `json:"id"`
	SourceID        string            `json:"source_id"`
	TenantID        string            `json:"tenant_id"`
	Family          string            `json:"family,omitempty"`
	RequiredSecrets []string          `json:"required_secrets,omitempty"`
	RoleAssumptions []RoleAssumption  `json:"role_assumptions,omitempty"`
	Config          map[string]string `json:"config"`
}

type RoleAssumption struct {
	ConfigKey string `json:"config_key"`
	RoleARN   string `json:"role_arn"`
}

type ContractRuntimeProfile struct {
	Name         string   `json:"name"`
	Requires     []string `json:"requires,omitempty"`
	Enables      []string `json:"enables,omitempty"`
	NotEnoughFor []string `json:"not_enough_for,omitempty"`
}

type ContractEnvVar struct {
	Name        string `json:"name"`
	RequiredFor string `json:"required_for"`
	Secret      bool   `json:"secret,omitempty"`
}

type ContractBackingService struct {
	Name        string   `json:"name"`
	RequiredFor string   `json:"required_for"`
	ConfigVars  []string `json:"config_vars"`
}

type ContractCapability struct {
	Name         string   `json:"name"`
	EnabledWhen  string   `json:"enabled_when"`
	Requires     []string `json:"requires,omitempty"`
	HealthChecks []string `json:"health_checks,omitempty"`
}

type ContractHealthCheck struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	RequiredFor string `json:"required_for"`
}

type contractCatalog struct {
	ID              string                     `yaml:"id"`
	EmittedKinds    []string                   `yaml:"emitted_kinds"`
	RuntimeFamilies []string                   `yaml:"runtime_families"`
	Coverage        sourcecdk.CoverageContract `yaml:"coverage_contract"`
}

func RenderContract(sourcesRoot string, manifests []Manifest, opts ContractOptions) (Contract, error) {
	fragment, err := Render(manifests, RenderOptions{Environment: opts.Environment, TenantID: opts.TenantID})
	if err != nil {
		return Contract{}, err
	}
	catalogs, err := discoverCatalogs(sourcesRoot)
	if err != nil {
		return Contract{}, err
	}

	manifestBySource := make(map[string]Manifest, len(manifests))
	for _, manifest := range manifests {
		manifestBySource[manifest.SourceID] = manifest
	}
	runtimesBySource := make(map[string][]ContractRuntime)
	for _, runtime := range fragment.SourceRuntimes {
		requiredSecrets := envRefs(runtime.Config)
		runtimesBySource[runtime.SourceID] = append(runtimesBySource[runtime.SourceID], ContractRuntime{
			ID:              runtime.ID,
			SourceID:        runtime.SourceID,
			TenantID:        runtime.TenantID,
			Family:          strings.TrimSpace(runtime.Config["family"]),
			RequiredSecrets: requiredSecrets,
			RoleAssumptions: roleAssumptions(runtime.Config),
			Config:          copyConfig(runtime.Config),
		})
	}

	sources := make([]ContractSource, 0, len(catalogs))
	for _, catalog := range catalogs {
		manifest := manifestBySource[catalog.ID]
		receipt, err := sourceHealthReceipt(sourcesRoot, catalog.ID)
		if err != nil {
			return Contract{}, err
		}
		coverage, err := sourceCoverageContract(catalog)
		if err != nil {
			return Contract{}, err
		}
		sources = append(sources, ContractSource{
			SourceID:                 catalog.ID,
			EmittedKinds:             sortedStrings(catalog.EmittedKinds),
			SupportedFamilies:        supportedFamilies(catalog.ID, catalog.EmittedKinds, catalog.RuntimeFamilies, runtimesBySource[catalog.ID]),
			RequiredSecrets:          sortedStrings(manifest.SecretKeys),
			RoleAssumptionConfigKeys: roleAssumptionConfigKeys(catalog.ID),
			SourceHealthReceipt:      receipt,
			CoverageContract:         coverage,
			Runtimes:                 runtimesBySource[catalog.ID],
		})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourceID < sources[j].SourceID })

	return Contract{
		SchemaVersion:           ContractSchemaVersion,
		ImageTag:                strings.TrimSpace(opts.ImageTag),
		Environment:             strings.TrimSpace(opts.Environment),
		TenantID:                strings.TrimSpace(opts.TenantID),
		RequiredSecrets:         sortedStrings(fragment.SourceSecretKeys),
		RuntimeProfiles:         contractRuntimeProfiles(),
		RequiredEnvVars:         contractRequiredEnvVars(),
		RequiredBackingServices: contractRequiredBackingServices(),
		OptionalCapabilities:    contractOptionalCapabilities(),
		PostDeployHealthChecks:  contractPostDeployHealthChecks(),
		CompatibilityNotes:      contractCompatibilityNotes(),
		Sources:                 sources,
	}, nil
}

func (c Contract) MarshalJSONStable() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func sourceHealthReceipt(sourcesRoot string, sourceID string) (map[string]any, error) {
	path := filepath.Join(sourcesRoot, sourceID, "source_health_receipt.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read source health receipt %s: %w", path, err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, fmt.Errorf("decode source health receipt %s: %w", path, err)
	}
	if len(receipt) == 0 {
		return nil, fmt.Errorf("decode source health receipt %s: receipt must be a JSON object", path)
	}
	if kind := strings.TrimSpace(fmt.Sprint(receipt["receipt_kind"])); kind != "source_health.receipt" {
		return nil, fmt.Errorf("decode source health receipt %s: receipt_kind must be source_health.receipt", path)
	}
	if rawSourceID, ok := receipt["source_id"].(string); ok && strings.TrimSpace(rawSourceID) != "" && strings.TrimSpace(rawSourceID) != sourceID {
		return nil, fmt.Errorf("decode source health receipt %s: source_id %q does not match catalog %q", path, rawSourceID, sourceID)
	}
	sourceType := strings.TrimSpace(fmt.Sprint(receipt["source_type"]))
	adapterHealthPath, _ := receipt["adapter_health_path"].(string)
	adapterHealthPath = strings.TrimSpace(adapterHealthPath)
	if sourceType == "json_api" && adapterHealthPath != "" && !strings.HasPrefix(adapterHealthPath, "/") {
		return nil, fmt.Errorf("decode source health receipt %s: json_api adapter_health_path must start with /", path)
	}
	receipt["source_id"] = sourceID
	return receipt, nil
}

func sourceCoverageContract(catalog contractCatalog) (*sourcecdk.CoverageContract, error) {
	contract, err := sourcecdk.NormalizeCoverageContract(catalog.ID, catalog.Coverage)
	if err != nil {
		return nil, err
	}
	if len(contract.Dimensions) == 0 {
		return nil, nil
	}
	return &contract, nil
}

func discoverCatalogs(sourcesRoot string) ([]contractCatalog, error) {
	entries, err := os.ReadDir(sourcesRoot)
	if err != nil {
		return nil, fmt.Errorf("read sources root %s: %w", sourcesRoot, err)
	}
	catalogs := make([]contractCatalog, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(sourcesRoot, entry.Name(), "catalog.yaml")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read source catalog %s: %w", path, err)
		}
		var catalog contractCatalog
		if err := yaml.Unmarshal(data, &catalog); err != nil {
			return nil, fmt.Errorf("decode source catalog %s: %w", path, err)
		}
		if strings.TrimSpace(catalog.ID) == "" {
			catalog.ID = entry.Name()
		}
		catalog.ID = strings.TrimSpace(catalog.ID)
		catalogs = append(catalogs, catalog)
	}
	sort.Slice(catalogs, func(i, j int) bool { return catalogs[i].ID < catalogs[j].ID })
	return catalogs, nil
}

func supportedFamilies(sourceID string, emittedKinds []string, runtimeFamilies []string, runtimes []ContractRuntime) []string {
	families := map[string]struct{}{}
	if len(runtimeFamilies) > 0 {
		for _, family := range runtimeFamilies {
			if family = strings.TrimSpace(family); family != "" {
				families[family] = struct{}{}
			}
		}
	} else {
		prefix := sourceID + "."
		for _, kind := range emittedKinds {
			kind = strings.TrimSpace(kind)
			if strings.HasPrefix(kind, prefix) {
				family := strings.TrimSpace(strings.TrimPrefix(kind, prefix))
				if family != "" {
					families[family] = struct{}{}
				}
			}
		}
	}
	for _, runtime := range runtimes {
		if runtime.Family != "" {
			families[runtime.Family] = struct{}{}
		}
	}
	out := make([]string, 0, len(families))
	for family := range families {
		out = append(out, family)
	}
	sort.Strings(out)
	return out
}

func envRefs(config map[string]string) []string {
	refs := map[string]struct{}{}
	for _, value := range config {
		if strings.HasPrefix(strings.TrimSpace(value), "env:") {
			refs[strings.TrimPrefix(strings.TrimSpace(value), "env:")] = struct{}{}
		}
	}
	return sortedStringSet(refs)
}

func roleAssumptions(config map[string]string) []RoleAssumption {
	var assumptions []RoleAssumption
	for key, value := range config {
		if strings.EqualFold(strings.TrimSpace(key), "role_arn") && strings.TrimSpace(value) != "" {
			assumptions = append(assumptions, RoleAssumption{ConfigKey: key, RoleARN: strings.TrimSpace(value)})
		}
	}
	sort.Slice(assumptions, func(i, j int) bool {
		if assumptions[i].ConfigKey == assumptions[j].ConfigKey {
			return assumptions[i].RoleARN < assumptions[j].RoleARN
		}
		return assumptions[i].ConfigKey < assumptions[j].ConfigKey
	})
	return assumptions
}

func roleAssumptionConfigKeys(sourceID string) []string {
	if sourceID == "aws" {
		return []string{"role_arn"}
	}
	return nil
}

func contractRuntimeProfiles() []ContractRuntimeProfile {
	return []ContractRuntimeProfile{
		{
			Name:         "lightweight-api",
			Enables:      []string{"liveness", "readiness", "OpenAPI metadata", "source catalog", "provider-free source previews"},
			NotEnoughFor: []string{"durable runtimes", "claims", "findings", "reports", "workflow replay", "graph operations"},
		},
		{
			Name:         "durable-api",
			Requires:     []string{"postgres"},
			Enables:      []string{"persisted source runtime state", "claims", "findings", "reports", "MCP OAuth", "device auth"},
			NotEnoughFor: []string{"append-log replay", "source sync workflows", "graph projection"},
		},
		{
			Name:         "durable-sync",
			Requires:     []string{"postgres", "nats-jetstream"},
			Enables:      []string{"source runtime sync", "append-log-backed workflow replay"},
			NotEnoughFor: []string{"graph queries", "graph ingest", "graph-agent workflows"},
		},
		{
			Name:     "graph-enabled",
			Requires: []string{"postgres", "nats-jetstream", "neo4j"},
			Enables:  []string{"graph projection", "graph queries", "graph health", "graph-agent workflows"},
		},
	}
}

func contractRequiredEnvVars() []ContractEnvVar {
	return []ContractEnvVar{
		{Name: "CEREBRO_HTTP_ADDR", RequiredFor: "all hosted profiles"},
		{Name: "CEREBRO_API_AUTH_ENABLED", RequiredFor: "shared deployments"},
		{Name: "CEREBRO_API_KEYS", RequiredFor: "API auth when simple bearer credentials are used", Secret: true},
		{Name: "CEREBRO_API_CREDENTIALS_JSON", RequiredFor: "API auth when structured credentials are used", Secret: true},
		{Name: "CEREBRO_PUBLIC_ORIGIN", RequiredFor: "shared deployments, MCP OAuth, and DPoP validation"},
		{Name: "CEREBRO_TRUSTED_PROXY_CIDRS", RequiredFor: "hosted deployments behind a proxy or load balancer"},
		{Name: "CEREBRO_TRUSTED_PROXY_COUNT", RequiredFor: "hosted deployments behind a proxy or load balancer"},
		{Name: "CEREBRO_STATE_STORE_DRIVER", RequiredFor: "durable-api, durable-sync, graph-enabled"},
		{Name: "CEREBRO_POSTGRES_DSN", RequiredFor: "durable-api, durable-sync, graph-enabled", Secret: true},
		{Name: "CEREBRO_APPEND_LOG_DRIVER", RequiredFor: "durable-sync and graph-enabled"},
		{Name: "CEREBRO_JETSTREAM_URL", RequiredFor: "durable-sync and graph-enabled", Secret: true},
		{Name: "CEREBRO_GRAPH_STORE_DRIVER", RequiredFor: "graph-enabled"},
		{Name: "CEREBRO_NEO4J_URI", RequiredFor: "graph-enabled", Secret: true},
		{Name: "CEREBRO_NEO4J_USERNAME", RequiredFor: "graph-enabled", Secret: true},
		{Name: "CEREBRO_NEO4J_PASSWORD", RequiredFor: "graph-enabled", Secret: true},
		{Name: "CEREBRO_CAPABILITY_TOKEN_SECRETS", RequiredFor: "MCP OAuth and capability-token auth", Secret: true},
		{Name: "CEREBRO_MCP_OAUTH_ENABLED", RequiredFor: "MCP OAuth"},
		{Name: "CEREBRO_MCP_OAUTH_CLIENTS_JSON", RequiredFor: "MCP OAuth clients when dynamic registration is disabled", Secret: true},
		{Name: "CEREBRO_MCP_OAUTH_ENTITLEMENTS_JSON", RequiredFor: "MCP OAuth tenant, scope, and role entitlements"},
		{Name: "CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", RequiredFor: "MCP OAuth upstream identity provider"},
		{Name: "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", RequiredFor: "MCP OAuth upstream identity provider"},
		{Name: "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", RequiredFor: "MCP OAuth upstream identity provider", Secret: true},
		{Name: "CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI", RequiredFor: "MCP OAuth upstream identity provider"},
		{Name: "CEREBRO_MCP_OAUTH_SECURITY_GROUPS", RequiredFor: "MCP OAuth upstream entitlement filtering"},
		{Name: "CEREBRO_DEVICE_AUTH_ENABLED", RequiredFor: "device auth"},
		{Name: "CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", RequiredFor: "device auth access and refresh tokens", Secret: true},
		{Name: "CEREBRO_DEVICE_AUTH_CURRENT_KID", RequiredFor: "device auth signing key selection"},
	}
}

func contractRequiredBackingServices() []ContractBackingService {
	return []ContractBackingService{
		{
			Name:        "postgres",
			RequiredFor: "durable runtime state, claims, findings, reports, OAuth, and device auth",
			ConfigVars:  []string{"CEREBRO_STATE_STORE_DRIVER", "CEREBRO_POSTGRES_DSN"},
		},
		{
			Name:        "nats-jetstream",
			RequiredFor: "append-log sync, replay, source runtime workflows, and graph-enabled deployments",
			ConfigVars:  []string{"CEREBRO_APPEND_LOG_DRIVER", "CEREBRO_JETSTREAM_URL"},
		},
		{
			Name:        "neo4j",
			RequiredFor: "graph projection, graph queries, graph health, and graph-agent workflows",
			ConfigVars:  []string{"CEREBRO_GRAPH_STORE_DRIVER", "CEREBRO_NEO4J_URI", "CEREBRO_NEO4J_USERNAME", "CEREBRO_NEO4J_PASSWORD"},
		},
		{
			Name:        "upstream-oauth-provider",
			RequiredFor: "MCP OAuth authorization-code exchange and entitlement checks",
			ConfigVars:  []string{"CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER", "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", "CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI"},
		},
	}
}

func contractOptionalCapabilities() []ContractCapability {
	return []ContractCapability{
		{
			Name:         "mcp-oauth",
			EnabledWhen:  "CEREBRO_MCP_OAUTH_ENABLED=true",
			Requires:     []string{"api-auth", "postgres", "CEREBRO_PUBLIC_ORIGIN", "CEREBRO_CAPABILITY_TOKEN_SECRETS"},
			HealthChecks: []string{"GET /health", "GET /.well-known/oauth-authorization-server"},
		},
		{
			Name:         "device-auth",
			EnabledWhen:  "CEREBRO_DEVICE_AUTH_ENABLED=true",
			Requires:     []string{"api-auth", "postgres", "CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", "CEREBRO_DEVICE_AUTH_CURRENT_KID"},
			HealthChecks: []string{"GET /health"},
		},
		{
			Name:         "query-cache",
			EnabledWhen:  "CEREBRO_CACHE_MODE=redis or CEREBRO_CACHE_MODE=valkey",
			Requires:     []string{"Redis or Valkey URL"},
			HealthChecks: []string{"GET /health", "cache dependency telemetry"},
		},
		{
			Name:         "graph-agent-llm",
			EnabledWhen:  "CEREBRO_GRAPH_AGENT_LLM_PROVIDER or provider credentials are set",
			Requires:     []string{"graph-enabled profile", "configured LLM provider credentials"},
			HealthChecks: []string{"cerebro deploy preflight", "graph-agent LLM probe"},
		},
		{
			Name:         "otel-export",
			EnabledWhen:  "CEREBRO_OTEL_ENABLED=true or an OTLP endpoint is set",
			Requires:     []string{"OTLP collector endpoint"},
			HealthChecks: []string{"trace and metric arrival in the collector"},
		},
	}
}

func contractPostDeployHealthChecks() []ContractHealthCheck {
	return []ContractHealthCheck{
		{Name: "liveness", Command: "curl -fsS https://cerebro.example.com/livez", RequiredFor: "all hosted profiles"},
		{Name: "readiness", Command: "curl -fsS https://cerebro.example.com/health", RequiredFor: "all hosted profiles"},
		{Name: "source catalog", Command: "curl -fsS -H 'Authorization: Bearer ${CEREBRO_API_KEY}' https://cerebro.example.com/sources", RequiredFor: "shared deployments with API auth"},
		{Name: "source runtime health", Command: "cerebro source-runtime list tenant_id=<tenant-id> limit=20", RequiredFor: "durable-api, durable-sync, graph-enabled"},
		{Name: "graph health", Command: "cerebro graph health", RequiredFor: "graph-enabled"},
		{Name: "deploy preflight", Command: "cerebro deploy preflight", RequiredFor: "every rollout before traffic shift"},
	}
}

func contractCompatibilityNotes() []string {
	return []string{
		"Deployment systems should ignore unknown JSON fields within this schema version.",
		"Concrete secret values, secret manager paths, schedules, hostnames, account IDs, and approval gates are intentionally outside this public contract.",
		"Postgres is the durable current-state store; NATS JetStream is the append log; Neo4j or Aura is a rebuildable graph projection, not a source of truth.",
		"Routes that require a missing dependency fail closed instead of switching to in-memory or embedded production storage.",
		"Source sync and graph ingest jobs should run separately from the API service with deployment-owned cadence, retries, and overlap prevention.",
	}
}

func sortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
