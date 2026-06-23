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
	SchemaVersion   string           `json:"schema_version"`
	ImageTag        string           `json:"image_tag,omitempty"`
	Environment     string           `json:"environment"`
	TenantID        string           `json:"tenant_id"`
	RequiredSecrets []string         `json:"required_secrets"`
	Sources         []ContractSource `json:"sources"`
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
		SchemaVersion:   ContractSchemaVersion,
		ImageTag:        strings.TrimSpace(opts.ImageTag),
		Environment:     strings.TrimSpace(opts.Environment),
		TenantID:        strings.TrimSpace(opts.TenantID),
		RequiredSecrets: sortedStrings(fragment.SourceSecretKeys),
		Sources:         sources,
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
