package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const schemaVersion = "cerebro.runtime-contract/v1"

type contract struct {
	SchemaVersion string           `json:"schema_version"`
	ContractID    string           `json:"contract_id"`
	GeneratedAt   string           `json:"generated_at"`
	Runtime       runtimeMetadata  `json:"runtime"`
	Compatibility compatibility    `json:"compatibility"`
	Sources       []sourceContract `json:"sources"`
}

type runtimeMetadata struct {
	Repository string `json:"repository"`
	Image      string `json:"image"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	Commit     string `json:"commit"`
}

type compatibility struct {
	MinInfraContractSchema string `json:"min_infra_contract_schema"`
	MinRuntimeImageTag     string `json:"min_runtime_image_tag"`
}

type sourceContract struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	EmittedKinds     []string          `json:"emitted_kinds"`
	SourceFamilies   []string          `json:"source_families"`
	RequiredSecrets  []string          `json:"required_secrets"`
	RoleAssumptions  []roleAssumption  `json:"role_assumptions,omitempty"`
	RuntimeTemplates []runtimeTemplate `json:"runtime_templates,omitempty"`
}

type roleAssumption struct {
	ConfigKey string `json:"config_key"`
	Scope     string `json:"scope"`
	Required  bool   `json:"required"`
}

type runtimeTemplate struct {
	LocalID string            `json:"local_id"`
	Config  map[string]string `json:"config"`
}

type deployCatalog struct {
	SourceID   string          `yaml:"sourceId"`
	SecretKeys []string        `yaml:"secretKeys"`
	Runtimes   []deployRuntime `yaml:"runtimes"`
}

type deployRuntime struct {
	LocalID string         `yaml:"localId"`
	Config  map[string]any `yaml:"config"`
}

func main() {
	var (
		repoRoot         = flag.String("repo-root", ".", "repository root")
		tag              = flag.String("tag", "", "runtime image tag")
		digest           = flag.String("digest", "", "runtime image digest")
		image            = flag.String("image", "ghcr.io/writer/cerebro", "runtime image repository")
		sourceRepository = flag.String("source-repository", "writer/cerebro", "source repository")
		commit           = flag.String("commit", "", "source commit")
		generatedAt      = flag.String("generated-at", "", "RFC3339 generation timestamp")
		output           = flag.String("output", "", "output path; stdout when empty")
	)
	flag.Parse()

	if strings.TrimSpace(*tag) == "" {
		fail("tag is required")
	}
	if strings.TrimSpace(*digest) == "" {
		fail("digest is required")
	}
	resolvedCommit := strings.TrimSpace(*commit)
	if resolvedCommit == "" {
		resolvedCommit = gitCommit(*repoRoot)
	}
	resolvedGeneratedAt := strings.TrimSpace(*generatedAt)
	if resolvedGeneratedAt == "" {
		resolvedGeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}

	contract, err := buildContract(*repoRoot, runtimeMetadata{
		Repository: strings.TrimSpace(*sourceRepository),
		Image:      strings.TrimSpace(*image),
		Tag:        strings.TrimSpace(*tag),
		Digest:     strings.TrimSpace(*digest),
		Commit:     resolvedCommit,
	}, resolvedGeneratedAt)
	if err != nil {
		fail(err.Error())
	}
	data, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		fail(err.Error())
	}
	data = append(data, '\n')
	if strings.TrimSpace(*output) == "" {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fail(err.Error())
	}
}

func buildContract(repoRoot string, runtime runtimeMetadata, generatedAt string) (*contract, error) {
	root := filepath.Clean(repoRoot)
	sourceDirs, err := filepath.Glob(filepath.Join(root, "sources", "*", "catalog.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(sourceDirs)

	deployBySource, err := loadDeployCatalogs(root)
	if err != nil {
		return nil, err
	}

	sources := make([]sourceContract, 0, len(sourceDirs))
	for _, path := range sourceDirs {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		catalog, err := sourcecdk.LoadSourceCatalog(data)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
		spec := catalog.Spec
		item := sourceContract{
			ID:             spec.Id,
			Name:           spec.Name,
			Description:    spec.Description,
			EmittedKinds:   append([]string(nil), spec.EmittedKinds...),
			SourceFamilies: familiesForSource(spec.Id, spec.EmittedKinds),
		}
		if deploy, ok := deployBySource[spec.Id]; ok {
			item.RequiredSecrets = normalizeList(deploy.SecretKeys)
			item.RuntimeTemplates = runtimeTemplates(deploy.Runtimes)
			item.RoleAssumptions = roleAssumptionsForTemplates(item.RuntimeTemplates)
		}
		if spec.Id == "aws" {
			item.RoleAssumptions = appendRoleAssumption(item.RoleAssumptions, roleAssumption{
				ConfigKey: "role_arn",
				Scope:     "source_runtime_config",
				Required:  false,
			})
		}
		sources = append(sources, item)
	}

	result := &contract{
		SchemaVersion: schemaVersion,
		GeneratedAt:   generatedAt,
		Runtime:       runtime,
		Compatibility: compatibility{
			MinInfraContractSchema: "cerebro.infra-runtime-contract/v1",
			MinRuntimeImageTag:     runtime.Tag,
		},
		Sources: sources,
	}
	result.ContractID = contractID(result)
	return result, nil
}

func loadDeployCatalogs(repoRoot string) (map[string]deployCatalog, error) {
	paths, err := filepath.Glob(filepath.Join(repoRoot, "sources", "*", "deploy.yaml"))
	if err != nil {
		return nil, err
	}
	result := map[string]deployCatalog{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var deploy deployCatalog
		if err := yaml.Unmarshal(data, &deploy); err != nil {
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
		deploy.SourceID = strings.TrimSpace(deploy.SourceID)
		if deploy.SourceID == "" {
			return nil, fmt.Errorf("%s sourceId is required", path)
		}
		result[deploy.SourceID] = deploy
	}
	return result, nil
}

func familiesForSource(sourceID string, kinds []string) []string {
	prefix := sourceID + "."
	seen := map[string]struct{}{}
	for _, kind := range kinds {
		family := strings.TrimSpace(kind)
		if strings.HasPrefix(family, prefix) {
			family = strings.TrimPrefix(family, prefix)
		}
		if family == "" {
			continue
		}
		seen[family] = struct{}{}
	}
	return sortedKeys(seen)
}

func runtimeTemplates(runtimes []deployRuntime) []runtimeTemplate {
	result := make([]runtimeTemplate, 0, len(runtimes))
	for _, runtime := range runtimes {
		localID := strings.TrimSpace(runtime.LocalID)
		if localID == "" {
			continue
		}
		config := map[string]string{}
		for key, value := range runtime.Config {
			config[strings.TrimSpace(key)] = strings.TrimSpace(fmt.Sprint(value))
		}
		result = append(result, runtimeTemplate{LocalID: localID, Config: config})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LocalID < result[j].LocalID })
	return result
}

func roleAssumptionsForTemplates(templates []runtimeTemplate) []roleAssumption {
	var result []roleAssumption
	for _, template := range templates {
		for key := range template.Config {
			if strings.HasSuffix(strings.ToLower(key), "role_arn") {
				result = appendRoleAssumption(result, roleAssumption{
					ConfigKey: key,
					Scope:     "source_runtime_config",
					Required:  false,
				})
			}
		}
	}
	return result
}

func appendRoleAssumption(items []roleAssumption, item roleAssumption) []roleAssumption {
	for _, existing := range items {
		if existing.ConfigKey == item.ConfigKey && existing.Scope == item.Scope {
			return items
		}
	}
	return append(items, item)
}

func normalizeList(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func contractID(item *contract) string {
	clone := *item
	clone.ContractID = ""
	data, _ := json.Marshal(clone)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func gitCommit(repoRoot string) string {
	cmd := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
