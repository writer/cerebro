package identity

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ServiceIdentityMapper maps CI/CD service identities to cloud provider roles
type ServiceIdentityMapper struct {
	adapters []ServiceIdentityAdapter
}

// ServiceIdentityAdapter interface for different CI/CD to cloud mappings
type ServiceIdentityAdapter interface {
	Name() string
	Match(identity ServiceIdentity) bool
	MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error)
}

// ServiceIdentity represents a CI/CD service identity
type ServiceIdentity struct {
	Provider    string            `json:"provider"`   // github, gitlab, circleci, etc.
	Repository  string            `json:"repository"` // org/repo
	Branch      string            `json:"branch"`
	Workflow    string            `json:"workflow"`
	Actor       string            `json:"actor"` // user who triggered
	RunID       string            `json:"run_id"`
	Environment string            `json:"environment"` // production, staging, etc.
	Claims      map[string]string `json:"claims"`      // OIDC claims
}

// CloudIdentityMapping represents the mapped cloud identity
type CloudIdentityMapping struct {
	Provider        string    `json:"provider"` // aws, gcp, azure
	RoleARN         string    `json:"role_arn"` // AWS role ARN, GCP SA, Azure SP
	AccountID       string    `json:"account_id"`
	TrustPolicy     string    `json:"trust_policy"`
	Permissions     []string  `json:"permissions"`
	RiskScore       int       `json:"risk_score"`  // 0-100
	TrustLevel      string    `json:"trust_level"` // high, medium, low
	LastUsed        time.Time `json:"last_used"`
	Vulnerabilities []string  `json:"vulnerabilities"`
}

// TrustEdge represents a trust relationship in the identity graph
type TrustEdge struct {
	Source     string            `json:"source"`
	Target     string            `json:"target"`
	TrustType  string            `json:"trust_type"` // oidc, assume_role, workload_identity
	Conditions map[string]string `json:"conditions"`
	RiskScore  int               `json:"risk_score"`
	CreatedAt  time.Time         `json:"created_at"`
}

func NewServiceIdentityMapper() *ServiceIdentityMapper {
	m := &ServiceIdentityMapper{
		adapters: make([]ServiceIdentityAdapter, 0),
	}
	// Register default adapters
	m.RegisterAdapter(&GitHubToAWSAdapter{})
	m.RegisterAdapter(&GitHubToGCPAdapter{})
	m.RegisterAdapter(&GitHubToAzureAdapter{})
	m.RegisterAdapter(&GitLabToGCPAdapter{})
	m.RegisterAdapter(&GitLabToAWSAdapter{})
	m.RegisterAdapter(&CircleCIToAWSAdapter{})
	return m
}

func (m *ServiceIdentityMapper) RegisterAdapter(adapter ServiceIdentityAdapter) {
	m.adapters = append(m.adapters, adapter)
}

func (m *ServiceIdentityMapper) MapIdentity(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	for _, adapter := range m.adapters {
		if adapter.Match(identity) {
			return adapter.MapToCloud(ctx, identity)
		}
	}
	return nil, fmt.Errorf("no adapter found for identity provider: %s", identity.Provider)
}

// GitHubToAWSAdapter maps GitHub Actions to AWS IAM roles via OIDC
type GitHubToAWSAdapter struct{}

func (a *GitHubToAWSAdapter) Name() string { return "github-to-aws" }

func (a *GitHubToAWSAdapter) Match(identity ServiceIdentity) bool {
	return identity.Provider == "github" && identity.Claims["aud"] == "sts.amazonaws.com"
}

func (a *GitHubToAWSAdapter) MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	mapping := &CloudIdentityMapping{
		Provider:  "aws",
		RiskScore: 50, // Base score
	}

	// Parse repository for org/repo
	parts := strings.Split(identity.Repository, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository format: %s", identity.Repository)
	}
	org, repo := parts[0], parts[1]

	// Build expected subject claim
	sub := fmt.Sprintf("repo:%s/%s:ref:refs/heads/%s", org, repo, identity.Branch)
	if identity.Environment != "" {
		sub = fmt.Sprintf("repo:%s/%s:environment:%s", org, repo, identity.Environment)
	}

	mapping.TrustPolicy = sub

	// Risk scoring
	if identity.Branch == "main" || identity.Branch == "master" {
		mapping.RiskScore -= 10 // Protected branch
		mapping.TrustLevel = "high"
	} else {
		mapping.RiskScore += 10 // Feature branch
		mapping.TrustLevel = "medium"
	}

	if identity.Environment == "production" {
		mapping.RiskScore += 20 // Production access
	}

	// Check for overly permissive conditions
	if identity.Claims["sub"] == "*" || identity.Claims["repository"] == "*" {
		mapping.RiskScore = 100
		mapping.TrustLevel = "low"
		mapping.Vulnerabilities = append(mapping.Vulnerabilities, "overly-permissive-oidc-trust")
	}

	return mapping, nil
}

// GitHubToGCPAdapter maps GitHub Actions to GCP Workload Identity
type GitHubToGCPAdapter struct{}

func (a *GitHubToGCPAdapter) Name() string { return "github-to-gcp" }

func (a *GitHubToGCPAdapter) Match(identity ServiceIdentity) bool {
	return identity.Provider == "github" &&
		(strings.Contains(identity.Claims["aud"], "iam.googleapis.com") ||
			identity.Claims["aud"] == "https://iam.googleapis.com")
}

func (a *GitHubToGCPAdapter) MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	mapping := &CloudIdentityMapping{
		Provider:   "gcp",
		RiskScore:  50,
		TrustLevel: "medium",
	}

	// GCP Workload Identity uses attribute conditions
	parts := strings.Split(identity.Repository, "/")
	if len(parts) == 2 {
		mapping.TrustPolicy = fmt.Sprintf("attribute.repository==%s/%s", parts[0], parts[1])
	}

	// Protected branch check
	if identity.Branch == "main" || identity.Branch == "master" {
		mapping.RiskScore -= 10
		mapping.TrustLevel = "high"
	}

	return mapping, nil
}

// GitHubToAzureAdapter maps GitHub Actions to Azure Federated Identity
type GitHubToAzureAdapter struct{}

func (a *GitHubToAzureAdapter) Name() string { return "github-to-azure" }

func (a *GitHubToAzureAdapter) Match(identity ServiceIdentity) bool {
	return identity.Provider == "github" &&
		strings.Contains(identity.Claims["iss"], "token.actions.githubusercontent.com")
}

func (a *GitHubToAzureAdapter) MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	mapping := &CloudIdentityMapping{
		Provider:   "azure",
		RiskScore:  50,
		TrustLevel: "medium",
	}

	// Azure uses subject claim matching
	if identity.Environment != "" {
		mapping.TrustPolicy = fmt.Sprintf("repo:%s:environment:%s", identity.Repository, identity.Environment)
	} else {
		mapping.TrustPolicy = fmt.Sprintf("repo:%s:ref:refs/heads/%s", identity.Repository, identity.Branch)
	}

	return mapping, nil
}

// GitLabToGCPAdapter maps GitLab CI to GCP Workload Identity
type GitLabToGCPAdapter struct{}

func (a *GitLabToGCPAdapter) Name() string { return "gitlab-to-gcp" }

func (a *GitLabToGCPAdapter) Match(identity ServiceIdentity) bool {
	return identity.Provider == "gitlab" &&
		strings.Contains(identity.Claims["aud"], "iam.googleapis.com")
}

func (a *GitLabToGCPAdapter) MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	mapping := &CloudIdentityMapping{
		Provider:   "gcp",
		RiskScore:  50,
		TrustLevel: "medium",
	}

	// GitLab uses project_path claim
	projectPath := identity.Claims["project_path"]
	if projectPath != "" {
		mapping.TrustPolicy = fmt.Sprintf("attribute.project_path==%s", projectPath)
	}

	// Check ref_protected claim
	if identity.Claims["ref_protected"] == "true" {
		mapping.RiskScore -= 15
		mapping.TrustLevel = "high"
	}

	return mapping, nil
}

// GitLabToAWSAdapter maps GitLab CI to AWS IAM roles
type GitLabToAWSAdapter struct{}

func (a *GitLabToAWSAdapter) Name() string { return "gitlab-to-aws" }

func (a *GitLabToAWSAdapter) Match(identity ServiceIdentity) bool {
	return identity.Provider == "gitlab" && identity.Claims["aud"] == "sts.amazonaws.com"
}

func (a *GitLabToAWSAdapter) MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	mapping := &CloudIdentityMapping{
		Provider:   "aws",
		RiskScore:  50,
		TrustLevel: "medium",
	}

	projectPath := identity.Claims["project_path"]
	namespace := identity.Claims["namespace_path"]

	if projectPath != "" {
		mapping.TrustPolicy = fmt.Sprintf("project_path:%s", projectPath)
	} else if namespace != "" {
		mapping.TrustPolicy = fmt.Sprintf("namespace_path:%s", namespace)
		mapping.RiskScore += 20 // Namespace-level is broader
	}

	return mapping, nil
}

// CircleCIToAWSAdapter maps CircleCI to AWS IAM roles
type CircleCIToAWSAdapter struct{}

func (a *CircleCIToAWSAdapter) Name() string { return "circleci-to-aws" }

func (a *CircleCIToAWSAdapter) Match(identity ServiceIdentity) bool {
	return identity.Provider == "circleci" && identity.Claims["aud"] == "sts.amazonaws.com"
}

func (a *CircleCIToAWSAdapter) MapToCloud(ctx context.Context, identity ServiceIdentity) (*CloudIdentityMapping, error) {
	mapping := &CloudIdentityMapping{
		Provider:   "aws",
		RiskScore:  50,
		TrustLevel: "medium",
	}

	orgID := identity.Claims["oidc.circleci.com/org-id"]
	projectID := identity.Claims["oidc.circleci.com/project-id"]

	if projectID != "" {
		mapping.TrustPolicy = fmt.Sprintf("oidc.circleci.com/project-id:%s", projectID)
	} else if orgID != "" {
		mapping.TrustPolicy = fmt.Sprintf("oidc.circleci.com/org-id:%s", orgID)
		mapping.RiskScore += 30 // Org-level is very broad
		mapping.Vulnerabilities = append(mapping.Vulnerabilities, "broad-org-level-trust")
	}

	return mapping, nil
}

// AnalyzeTrustChain analyzes the full trust chain from CI/CD to cloud resources
func (m *ServiceIdentityMapper) AnalyzeTrustChain(ctx context.Context, identities []ServiceIdentity, iamRoles []map[string]interface{}) []TrustEdge {
	edges := make([]TrustEdge, 0, len(identities)*len(iamRoles))

	// Build index of IAM roles by trust policy patterns
	rolePatterns := make(map[string][]map[string]interface{})
	oidcPattern := regexp.MustCompile(`token\.actions\.githubusercontent\.com|gitlab\.com|oidc\.circleci\.com`)

	for _, role := range iamRoles {
		trustPolicy, _ := role["assume_role_policy_document"].(string)
		if oidcPattern.MatchString(trustPolicy) {
			// Extract OIDC provider
			if strings.Contains(trustPolicy, "githubusercontent") {
				rolePatterns["github"] = append(rolePatterns["github"], role)
			} else if strings.Contains(trustPolicy, "gitlab") {
				rolePatterns["gitlab"] = append(rolePatterns["gitlab"], role)
			} else if strings.Contains(trustPolicy, "circleci") {
				rolePatterns["circleci"] = append(rolePatterns["circleci"], role)
			}
		}
	}

	// Create edges for each identity
	for _, identity := range identities {
		roles := rolePatterns[identity.Provider]
		for _, role := range roles {
			roleARN, _ := role["arn"].(string)
			edge := TrustEdge{
				Source:    fmt.Sprintf("%s:%s", identity.Provider, identity.Repository),
				Target:    roleARN,
				TrustType: "oidc",
				Conditions: map[string]string{
					"branch":      identity.Branch,
					"environment": identity.Environment,
				},
				CreatedAt: time.Now(),
			}

			// Calculate risk score based on trust policy restrictiveness
			mapping, err := m.MapIdentity(ctx, identity)
			if err == nil {
				edge.RiskScore = mapping.RiskScore
			}

			edges = append(edges, edge)
		}
	}

	return edges
}
