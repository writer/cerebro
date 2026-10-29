package cloudidentitysource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

// Settings holds resolved source configuration. Credential fields must never be
// serialized into events, finding evidence, diagnostics, or model context.
type Settings struct {
	TenantID                 string
	Plan                     ci.ScanPlan
	GitHubAppID              string
	GitHubPrivateKeyBase64   string
	GitHubInstallations      map[string]string
	AllowedRepositories      []string
	AllowedModules           []string
	RegistryModules          []string
	AllowedChartRepositories []string
	AWSRegion                string
	AWSRoleName              string
	GCPOrganization          string
	GCPQuotaProject          string
	GCPWIFAudience           string
	GCPWIFServiceAccount     string
	LLMProvider              string
	LLMModel                 string
	LLMRegion                string
	LLMAPIKey                string
	Timeout                  time.Duration
}

func ParseSettings(cfg sourcecdk.Config) (Settings, error) {
	value := func(key string) string { return strings.TrimSpace(sourcecdk.ConfigValue(cfg, key)) }
	st := Settings{
		TenantID: value("tenant_id"), GitHubAppID: value("github_app_id"),
		GitHubPrivateKeyBase64: value("github_app_private_key_base64"),
		AWSRegion:              value("aws_region"), AWSRoleName: value("aws_role_name"),
		GCPOrganization: value("gcp_organization"), GCPQuotaProject: value("gcp_quota_project"),
		GCPWIFAudience: value("gcp_wif_audience"), GCPWIFServiceAccount: value("gcp_wif_service_account"),
		LLMProvider: value("llm_provider"), LLMModel: value("llm_model"), LLMRegion: value("llm_region"), LLMAPIKey: value("llm_api_key"),
		Timeout: 45 * time.Minute,
	}
	if st.TenantID == "" {
		st.TenantID = value(sourceconfig.RuntimeTenantIDKey)
	}
	if st.TenantID == "" {
		return st, fmt.Errorf("cloud_identity tenant_id is required")
	}
	if family := value("family"); family != "" && family != "cohort" {
		return st, fmt.Errorf("cloud_identity family must be cohort")
	}
	if err := decodeScanJSON(value("scan_plan"), &st.Plan); err != nil {
		return st, fmt.Errorf("cloud_identity scan_plan: %w", err)
	}
	if err := validateScanPlan(st.Plan); err != nil {
		return st, err
	}
	st.GitHubInstallations = make(map[string]string)
	if raw := value("github_installations"); raw != "" {
		if err := decodeScanJSON(raw, &st.GitHubInstallations); err != nil {
			return st, fmt.Errorf("cloud_identity github_installations: %w", err)
		}
	}
	for key, installation := range cfg.Values() {
		if owner, ok := strings.CutPrefix(key, "github_installation_"); ok {
			if _, exists := st.GitHubInstallations[owner]; exists {
				return st, fmt.Errorf("cloud_identity duplicate GitHub installation routing")
			}
			st.GitHubInstallations[owner] = strings.TrimSpace(installation)
		}
	}
	if len(st.GitHubInstallations) == 0 || st.GitHubAppID == "" || st.GitHubPrivateKeyBase64 == "" {
		return st, fmt.Errorf("cloud_identity existing GitHub App credentials and installation routing are required")
	}
	for owner, installation := range st.GitHubInstallations {
		if owner == "" || owner != strings.ToLower(owner) || strings.ContainsAny(owner, "/ \\:") || installation == "" {
			return st, fmt.Errorf("cloud_identity github_installations requires lowercase organization keys and installation IDs")
		}
	}
	for key, target := range map[string]*[]string{"allowed_repositories": &st.AllowedRepositories, "allowed_modules": &st.AllowedModules, "registry_modules": &st.RegistryModules, "allowed_chart_repositories": &st.AllowedChartRepositories} {
		if raw := value(key); raw != "" {
			if err := decodeScanJSON(raw, target); err != nil {
				return st, fmt.Errorf("cloud_identity %s: %w", key, err)
			}
		}
	}
	st.AllowedRepositories = append(st.AllowedRepositories, planRepositories(st.Plan)...)
	if st.AWSRegion == "" {
		st.AWSRegion = "us-east-1"
	}
	if st.AWSRoleName == "" {
		st.AWSRoleName = "cerebro-org-scan-role"
	}
	if st.LLMProvider == "" {
		st.LLMProvider = "bedrock"
	}
	if st.LLMProvider != "bedrock" && st.LLMProvider != "openrouter" {
		return st, fmt.Errorf("cloud_identity llm_provider must be bedrock or openrouter")
	}
	if st.LLMProvider == "openrouter" && st.LLMAPIKey == "" {
		return st, fmt.Errorf("cloud_identity llm_api_key is required for openrouter")
	}
	if st.LLMRegion == "" {
		st.LLMRegion = st.AWSRegion
	}
	if raw := value("timeout"); raw != "" {
		duration, err := time.ParseDuration(raw)
		if err != nil || duration <= 0 || duration > 4*time.Hour {
			return st, fmt.Errorf("cloud_identity timeout must be positive and at most 4h")
		}
		st.Timeout = duration
	}
	for _, target := range st.Plan.Targets {
		if target.Provider == ci.GCP && (st.GCPOrganization == "" || st.GCPQuotaProject == "" || st.GCPWIFAudience == "" || st.GCPWIFServiceAccount == "") {
			return st, fmt.Errorf("cloud_identity GCP targets require organization, quota project, and existing WIF audience/service account")
		}
	}
	return st, nil
}

func decodeScanJSON(raw string, target any) error {
	if raw == "" || len(raw) > 1024*1024 {
		return fmt.Errorf("a nonempty JSON value of at most 1 MiB is required")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON configuration")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("a single JSON value is required")
	}
	return nil
}

func validateScanPlan(plan ci.ScanPlan) error {
	if plan.Scope == "" || len(plan.Targets) == 0 || len(plan.Targets) > 256 {
		return fmt.Errorf("cloud_identity scan_plan requires scope and 1-256 targets")
	}
	seen := make(map[string]bool)
	clusters := make(map[string]bool)
	for _, target := range plan.Targets {
		if target.Name == "" || seen[target.Name] || target.Environment == "" || target.Cluster == "" || len(target.Manifests) == 0 {
			return fmt.Errorf("cloud_identity targets require unique names, environment, cluster and manifest inputs")
		}
		seen[target.Name] = true
		// Workload IDs, Kubernetes service-account subjects and resolved
		// cluster identifiers (OIDC issuer/provider) are keyed by cluster
		// name; two targets sharing one would mis-link identities.
		if clusters[target.Cluster] {
			return fmt.Errorf("cloud_identity target clusters must be unique; cluster %q is ambiguous across targets", target.Cluster)
		}
		clusters[target.Cluster] = true
		if (target.Provider != ci.AWS && target.Provider != ci.GCP) || (target.Provider == ci.AWS && target.Account == "") || (target.Provider == ci.GCP && target.Project == "") {
			return fmt.Errorf("cloud_identity targets require aws/account or gcp/project")
		}
		if target.Provider == ci.AWS && target.Region == "" {
			return fmt.Errorf("cloud_identity AWS targets require the cluster region")
		}
		for _, manifest := range target.Manifests {
			if manifest.Source.Repository == "" || manifest.Source.Revision == "" || (len(manifest.Paths) == 0 && manifest.Chart == "") {
				return fmt.Errorf("cloud_identity manifest inputs require repository, revision and paths or chart")
			}
			for _, application := range manifest.Applications {
				if strings.TrimSpace(application) == "" {
					return fmt.Errorf("cloud_identity manifest applications must be nonempty names")
				}
			}
		}
		for _, root := range target.Terraform {
			if root.Source.Repository == "" || root.Source.Revision == "" || root.Root == "" {
				return fmt.Errorf("cloud_identity Terraform inputs require repository, revision and root")
			}
			if err := validateMetadataBindings(target, root); err != nil {
				return err
			}
		}
	}
	if len(plan.Services) == 0 {
		return fmt.Errorf("cloud_identity service mappings are required to distinguish logical applications from replicas")
	}
	for _, service := range plan.Services {
		if service.Service == "" || service.Repository == "" || len(service.ImagePrefixes) == 0 {
			return fmt.Errorf("cloud_identity services require service, repository and image_prefixes")
		}
		for _, workload := range service.Workloads {
			if strings.TrimSpace(workload) == "" {
				return fmt.Errorf("cloud_identity service workloads must be nonempty names")
			}
		}
	}
	return nil
}

var metadataBindingTraversal = regexp.MustCompile(`^data\.[a-z0-9_]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$`)

// validateMetadataBindings accepts only data-source attribute traversals bound
// to a metadata fact the target itself supplies, so a binding can never
// introduce a value that does not come from the reviewed scan plan.
func validateMetadataBindings(target ci.ScanTarget, root ci.TerraformRoot) error {
	for traversal, fact := range root.MetadataBindings {
		if !metadataBindingTraversal.MatchString(traversal) {
			return fmt.Errorf("cloud_identity metadata binding %q must be a data source attribute traversal", traversal)
		}
		var available bool
		switch fact {
		case "project_id", "project_number":
			available = target.Project != ""
		case "account_id":
			available = target.Account != ""
		case "region":
			available = root.Region != ""
		default:
			return fmt.Errorf("cloud_identity metadata binding %q must bind project_id, project_number, region or account_id", traversal)
		}
		if !available {
			return fmt.Errorf("cloud_identity metadata binding %q requires the target to supply %s", traversal, fact)
		}
	}
	return nil
}

func planRepositories(plan ci.ScanPlan) []string {
	seen := make(map[string]struct{})
	for _, target := range plan.Targets {
		for _, manifest := range target.Manifests {
			seen[manifest.Source.Repository] = struct{}{}
		}
		for _, root := range target.Terraform {
			seen[root.Source.Repository] = struct{}{}
		}
	}
	for _, service := range plan.Services {
		seen[service.Repository] = struct{}{}
	}
	repositories := make([]string, 0, len(seen))
	for repository := range seen {
		repositories = append(repositories, repository)
	}
	return repositories
}
