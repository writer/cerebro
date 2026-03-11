// Package lineage provides deployment lineage tracking to connect runtime
// cloud assets back to their source code, container images, and IaC definitions.
//
// The package enables:
//   - Mapping Kubernetes deployments to git commits and container images
//   - Tracking EC2/Lambda instances back to Terraform/CloudFormation
//   - Detecting configuration drift between IaC definitions and runtime state
//   - Building supply chain visibility for security analysis
//
// Lineage information is extracted from:
//   - Kubernetes labels and annotations (commit SHA, repository, pipeline)
//   - AWS/GCP/Azure resource tags
//   - Terraform state files
//   - CI/CD pipeline metadata (GitHub Actions, GitLab CI, etc.)
//
// This enables powerful queries like:
//   - "What deployments are running code from this commit?"
//   - "Which pods use images with this CVE?"
//   - "What resources drifted from their Terraform definition?"
//
// Example usage:
//
//	mapper := lineage.NewLineageMapper()
//	lineage, _ := mapper.MapKubernetesResource(ctx, podSpec)
//	fmt.Printf("Pod running commit %s from %s", lineage.CommitSHA, lineage.Repository)
//	drifts := mapper.DetectDrift(ctx, assetID, currentState, iacState)
package lineage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LineageMapper tracks relationships between runtime assets and their source
// artifacts (git commits, container images, IaC definitions, CI/CD pipelines).
//
// The mapper maintains an in-memory index of asset lineage that can be queried
// by asset ID, commit SHA, or container image digest.
type LineageMapper struct {
	assets  map[string]*AssetLineage // Lineage indexed by asset ID
	commits map[string]*CommitInfo   // Commit metadata indexed by SHA
	builds  map[string]*BuildInfo    // Build metadata indexed by build ID
}

// AssetLineage represents the full lineage of a deployed asset
type AssetLineage struct {
	AssetID   string `json:"asset_id"`
	AssetType string `json:"asset_type"` // pod, ec2, lambda, vm
	AssetName string `json:"asset_name"`
	Provider  string `json:"provider"` // aws, gcp, azure, k8s
	Region    string `json:"region"`
	AccountID string `json:"account_id"`

	// Source Code Lineage
	Repository    string     `json:"repository,omitempty"`
	Branch        string     `json:"branch,omitempty"`
	CommitSHA     string     `json:"commit_sha,omitempty"`
	CommitMessage string     `json:"commit_message,omitempty"`
	CommitAuthor  string     `json:"commit_author,omitempty"`
	CommitTime    *time.Time `json:"commit_time,omitempty"`

	// Container Image Lineage
	ImageURI    string `json:"image_uri,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
	ImageTag    string `json:"image_tag,omitempty"`
	BaseImage   string `json:"base_image,omitempty"`

	// IaC Lineage
	IaCType    string `json:"iac_type,omitempty"` // terraform, cloudformation, pulumi
	IaCFile    string `json:"iac_file,omitempty"`
	IaCModule  string `json:"iac_module,omitempty"`
	IaCStateID string `json:"iac_state_id,omitempty"`

	// Build/Pipeline Lineage
	PipelineID  string     `json:"pipeline_id,omitempty"`
	PipelineURL string     `json:"pipeline_url,omitempty"`
	BuildID     string     `json:"build_id,omitempty"`
	BuildTime   *time.Time `json:"build_time,omitempty"`
	BuildActor  string     `json:"build_actor,omitempty"`

	// Business provenance
	LeadSource     string     `json:"lead_source,omitempty"`
	DealID         string     `json:"deal_id,omitempty"`
	SalesRep       string     `json:"sales_rep,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	SubscriptionID string     `json:"subscription_id,omitempty"`
	TenantID       string     `json:"tenant_id,omitempty"`
	OnboardedAt    *time.Time `json:"onboarded_at,omitempty"`

	// Cross-system references
	CRMEntityID     string `json:"crm_entity_id,omitempty"`
	BillingEntityID string `json:"billing_entity_id,omitempty"`
	SupportEntityID string `json:"support_entity_id,omitempty"`

	// Business entity evolution chain
	BusinessChain []BusinessLineageStep `json:"business_chain,omitempty"`

	// Drift Detection
	DriftDetected bool          `json:"drift_detected"`
	DriftDetails  []DriftDetail `json:"drift_details,omitempty"`
	LastSynced    time.Time     `json:"last_synced"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// BusinessLineageStep describes a relationship transition in the business-to-infra chain.
type BusinessLineageStep struct {
	StepType  string     `json:"step_type"` // originated_from, provisioned_as
	System    string     `json:"system"`
	EntityID  string     `json:"entity_id"`
	EntityRef string     `json:"entity_ref,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

const (
	BusinessLineageStepOriginatedFrom = "originated_from"
	BusinessLineageStepProvisionedAs  = "provisioned_as"
)

// DriftDetail describes a specific configuration drift
type DriftDetail struct {
	Field         string `json:"field"`
	ExpectedValue string `json:"expected_value"`
	ActualValue   string `json:"actual_value"`
	Source        string `json:"source"` // iac, image, code
}

// CommitInfo stores commit metadata
type CommitInfo struct {
	SHA       string    `json:"sha"`
	Message   string    `json:"message"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
	Branch    string    `json:"branch"`
	Tags      []string  `json:"tags"`
}

// BuildInfo stores CI/CD build metadata
type BuildInfo struct {
	ID         string    `json:"id"`
	Provider   string    `json:"provider"` // github-actions, gitlab-ci, jenkins
	Repository string    `json:"repository"`
	Branch     string    `json:"branch"`
	CommitSHA  string    `json:"commit_sha"`
	Status     string    `json:"status"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Actor      string    `json:"actor"`
	URL        string    `json:"url"`
	Artifacts  []string  `json:"artifacts"`
}

func NewLineageMapper() *LineageMapper {
	return &LineageMapper{
		assets:  make(map[string]*AssetLineage),
		commits: make(map[string]*CommitInfo),
		builds:  make(map[string]*BuildInfo),
	}
}

// MapKubernetesResource extracts lineage from Kubernetes resource metadata
func (m *LineageMapper) MapKubernetesResource(ctx context.Context, resource map[string]interface{}) (*AssetLineage, error) {
	metadata, _ := resource["metadata"].(map[string]interface{})
	spec, _ := resource["spec"].(map[string]interface{})

	lineage := &AssetLineage{
		AssetType:  resource["kind"].(string),
		Provider:   "kubernetes",
		LastSynced: time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	if metadata != nil {
		lineage.AssetID = fmt.Sprintf("%s/%s", metadata["namespace"], metadata["name"])
		lineage.AssetName = metadata["name"].(string)

		// Extract lineage from labels
		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			m.extractLabels(lineage, labels)
		}

		// Extract lineage from annotations
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			m.extractAnnotations(lineage, annotations)
		}
	}

	// Extract container image from pod spec
	if spec != nil {
		m.extractContainerImage(lineage, spec)
	}

	m.assets[lineage.AssetID] = lineage
	return lineage, nil
}

func (m *LineageMapper) extractLabels(lineage *AssetLineage, labels map[string]interface{}) {
	labelMappings := map[string]*string{
		"app.kubernetes.io/version":    &lineage.ImageTag,
		"app.kubernetes.io/managed-by": &lineage.IaCType,
		"helm.sh/chart":                &lineage.IaCModule,
		"argocd.argoproj.io/instance":  &lineage.PipelineID,
	}

	for label, target := range labelMappings {
		if val, ok := labels[label].(string); ok && val != "" {
			*target = val
		}
	}
}

func (m *LineageMapper) extractAnnotations(lineage *AssetLineage, annotations map[string]interface{}) {
	// Standard annotations for lineage
	annotationMappings := map[string]*string{
		// Git annotations
		"app.kubernetes.io/git-commit":     &lineage.CommitSHA,
		"app.kubernetes.io/git-repository": &lineage.Repository,
		"app.kubernetes.io/git-branch":     &lineage.Branch,

		// ArgoCD annotations
		"argocd.argoproj.io/tracking-id": &lineage.IaCStateID,

		// Flux annotations
		"fluxcd.io/git-commit":     &lineage.CommitSHA,
		"fluxcd.io/git-repository": &lineage.Repository,

		// Custom annotations we support
		"cerebro.io/commit-sha":   &lineage.CommitSHA,
		"cerebro.io/repository":   &lineage.Repository,
		"cerebro.io/branch":       &lineage.Branch,
		"cerebro.io/pipeline-id":  &lineage.PipelineID,
		"cerebro.io/pipeline-url": &lineage.PipelineURL,
		"cerebro.io/build-id":     &lineage.BuildID,
		"cerebro.io/iac-file":     &lineage.IaCFile,
	}

	for annotation, target := range annotationMappings {
		if val, ok := annotations[annotation].(string); ok && val != "" {
			*target = val
		}
	}
}

func (m *LineageMapper) extractContainerImage(lineage *AssetLineage, spec map[string]interface{}) {
	// Handle Pod spec
	if containers, ok := spec["containers"].([]interface{}); ok && len(containers) > 0 {
		if container, ok := containers[0].(map[string]interface{}); ok {
			if image, ok := container["image"].(string); ok {
				m.parseImageReference(lineage, image)
			}
		}
	}

	// Handle Deployment/StatefulSet spec
	if template, ok := spec["template"].(map[string]interface{}); ok {
		if templateSpec, ok := template["spec"].(map[string]interface{}); ok {
			m.extractContainerImage(lineage, templateSpec)
		}
	}
}

func (m *LineageMapper) parseImageReference(lineage *AssetLineage, image string) {
	lineage.ImageURI = image

	// Parse digest
	if strings.Contains(image, "@sha256:") {
		parts := strings.Split(image, "@")
		lineage.ImageDigest = parts[1]
		image = parts[0]
	}

	// Parse tag
	if strings.Contains(image, ":") {
		parts := strings.Split(image, ":")
		lineage.ImageTag = parts[len(parts)-1]
	}
}

// MapEC2Instance extracts lineage from EC2 instance metadata
func (m *LineageMapper) MapEC2Instance(ctx context.Context, instance map[string]interface{}) (*AssetLineage, error) {
	lineage := &AssetLineage{
		AssetType:  "ec2",
		Provider:   "aws",
		LastSynced: time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	lineage.AssetID = instance["instance_id"].(string)
	lineage.AssetName = instance["instance_id"].(string)
	lineage.Region = extractString(instance, "region", "availability_zone")
	lineage.AccountID = extractString(instance, "account_id", "owner_id")

	// Extract from tags
	if tags, ok := instance["tags"].(map[string]interface{}); ok {
		m.extractEC2Tags(lineage, tags)
	}

	// Extract AMI lineage
	if ami, ok := instance["image_id"].(string); ok {
		lineage.ImageURI = ami
		// Could look up AMI metadata for base image info
	}

	// Check for CloudFormation stack
	if stackID, ok := instance["tags"].(map[string]interface{})["aws:cloudformation:stack-id"].(string); ok {
		lineage.IaCType = "cloudformation"
		lineage.IaCStateID = stackID
	}

	m.assets[lineage.AssetID] = lineage
	return lineage, nil
}

func (m *LineageMapper) extractEC2Tags(lineage *AssetLineage, tags map[string]interface{}) {
	tagMappings := map[string]*string{
		"Name":                          &lineage.AssetName,
		"git:commit":                    &lineage.CommitSHA,
		"git:repository":                &lineage.Repository,
		"git:branch":                    &lineage.Branch,
		"terraform:state":               &lineage.IaCStateID,
		"aws:cloudformation:stack-name": &lineage.IaCModule,
	}

	for tag, target := range tagMappings {
		if val, ok := tags[tag].(string); ok && val != "" {
			*target = val
		}
	}

	// Detect IaC type from tags
	if _, ok := tags["terraform:state"]; ok {
		lineage.IaCType = "terraform"
	}
}

// MapLambdaFunction extracts lineage from Lambda function metadata
func (m *LineageMapper) MapLambdaFunction(ctx context.Context, fn map[string]interface{}) (*AssetLineage, error) {
	lineage := &AssetLineage{
		AssetType:  "lambda",
		Provider:   "aws",
		LastSynced: time.Now(),
		Metadata:   make(map[string]interface{}),
	}

	lineage.AssetID = fn["function_arn"].(string)
	lineage.AssetName = fn["function_name"].(string)
	lineage.AccountID = extractString(fn, "account_id")

	// Extract code SHA
	if codeSHA, ok := fn["code_sha256"].(string); ok {
		lineage.ImageDigest = codeSHA
	}

	// Extract environment variables for lineage hints
	if env, ok := fn["environment"].(map[string]interface{}); ok {
		if vars, ok := env["variables"].(map[string]interface{}); ok {
			envMappings := map[string]*string{
				"GIT_COMMIT":   &lineage.CommitSHA,
				"GIT_BRANCH":   &lineage.Branch,
				"GIT_REPO":     &lineage.Repository,
				"BUILD_ID":     &lineage.BuildID,
				"PIPELINE_URL": &lineage.PipelineURL,
			}
			for envVar, target := range envMappings {
				if val, ok := vars[envVar].(string); ok && val != "" {
					*target = val
				}
			}
		}
	}

	// Extract from tags
	if tags, ok := fn["tags"].(map[string]interface{}); ok {
		m.extractEC2Tags(lineage, tags) // Same tag patterns
	}

	m.assets[lineage.AssetID] = lineage
	return lineage, nil
}

// MapTerraformState extracts lineage from Terraform state
func (m *LineageMapper) MapTerraformState(ctx context.Context, state map[string]interface{}) ([]AssetLineage, error) {
	var lineages []AssetLineage

	resources, _ := state["resources"].([]interface{})
	for _, res := range resources {
		resource, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		lineage := AssetLineage{
			IaCType:    "terraform",
			Provider:   extractString(resource, "provider"),
			LastSynced: time.Now(),
		}

		lineage.IaCModule = extractString(resource, "module")
		lineage.AssetType = extractString(resource, "type")
		lineage.AssetName = extractString(resource, "name")

		// Extract instance details
		if instances, ok := resource["instances"].([]interface{}); ok && len(instances) > 0 {
			if inst, ok := instances[0].(map[string]interface{}); ok {
				if attrs, ok := inst["attributes"].(map[string]interface{}); ok {
					lineage.AssetID = extractString(attrs, "id", "arn")
					lineage.Region = extractString(attrs, "region", "location")
				}
			}
		}

		if lineage.AssetID != "" {
			m.assets[lineage.AssetID] = &lineage
			lineages = append(lineages, lineage)
		}
	}

	return lineages, nil
}

// MapBusinessEntity extracts business-to-infrastructure provenance from entity metadata.
func (m *LineageMapper) MapBusinessEntity(ctx context.Context, entity map[string]interface{}) (*AssetLineage, error) {
	_ = ctx

	lineage := &AssetLineage{
		AssetType:  firstNonEmpty(extractString(entity, "asset_type", "entity_type", "type", "kind"), "business_entity"),
		Provider:   firstNonEmpty(extractString(entity, "provider", "system", "source", "platform"), "business"),
		LastSynced: time.Now(),
		Metadata:   make(map[string]interface{}, len(entity)),
	}

	for key, value := range entity {
		lineage.Metadata[key] = value
	}

	lineage.AssetID = extractString(
		entity,
		"asset_id",
		"entity_id",
		"id",
		"tenant_id",
		"subscription_id",
		"contract_id",
		"deal_id",
		"opportunity_id",
		"customer_id",
	)
	if lineage.AssetID == "" {
		return nil, fmt.Errorf("missing business entity identifier")
	}

	lineage.AssetName = firstNonEmpty(
		extractString(entity, "asset_name", "entity_name", "name", "customer_name", "tenant_name"),
		lineage.AssetID,
	)
	lineage.Region = extractString(entity, "region")
	lineage.AccountID = extractString(entity, "account_id", "cloud_account_id")

	lineage.LeadSource = extractString(entity, "lead_source", "leadSource", "source_channel", "utm_source")
	lineage.DealID = extractString(entity, "deal_id", "dealId", "opportunity_id", "opportunityId")
	lineage.SalesRep = extractString(entity, "sales_rep", "salesRep", "account_executive", "owner", "owner_name")
	lineage.ContractID = extractString(entity, "contract_id", "contractId", "agreement_id", "agreementId")
	lineage.SubscriptionID = extractString(entity, "subscription_id", "subscriptionId", "stripe_subscription_id")
	lineage.TenantID = extractString(entity, "tenant_id", "tenantId")
	lineage.OnboardedAt = extractTime(entity, "onboarded_at", "onboardedAt", "tenant_provisioned_at", "tenantProvisionedAt")

	lineage.CRMEntityID = extractString(entity, "crm_entity_id", "crmEntityId", "hubspot_id", "salesforce_id")
	lineage.BillingEntityID = extractString(
		entity,
		"billing_entity_id",
		"billingEntityId",
		"stripe_customer_id",
		"stripeCustomerId",
		"billing_customer_id",
	)
	lineage.SupportEntityID = extractString(entity, "support_entity_id", "supportEntityId", "zendesk_org_id", "support_org_id")

	// Keep core source/build lineage fields when present so business entities can still
	// be correlated with deployment lineage records.
	lineage.Repository = extractString(entity, "repository")
	lineage.Branch = extractString(entity, "branch")
	lineage.CommitSHA = extractString(entity, "commit_sha", "commitSha")
	lineage.ImageURI = extractString(entity, "image_uri", "imageUri")
	lineage.ImageDigest = extractString(entity, "image_digest", "imageDigest")
	lineage.PipelineID = extractString(entity, "pipeline_id", "pipelineId")
	lineage.PipelineURL = extractString(entity, "pipeline_url", "pipelineUrl")
	lineage.BuildID = extractString(entity, "build_id", "buildId")
	lineage.IaCType = extractString(entity, "iac_type", "iacType")
	lineage.IaCModule = extractString(entity, "iac_module", "iacModule")
	lineage.IaCStateID = extractString(entity, "iac_state_id", "iacStateId")

	lineage.BusinessChain = buildBusinessChain(entity, lineage)
	m.assets[lineage.AssetID] = lineage

	return lineage, nil
}

// DetectDrift compares runtime state with declared IaC state
func (m *LineageMapper) DetectDrift(ctx context.Context, assetID string, currentState map[string]interface{}, iacState map[string]interface{}) []DriftDetail {
	var drifts []DriftDetail

	for key, expected := range iacState {
		actual, exists := currentState[key]
		if !exists {
			drifts = append(drifts, DriftDetail{
				Field:         key,
				ExpectedValue: fmt.Sprintf("%v", expected),
				ActualValue:   "<missing>",
				Source:        "iac",
			})
			continue
		}

		if fmt.Sprintf("%v", expected) != fmt.Sprintf("%v", actual) {
			drifts = append(drifts, DriftDetail{
				Field:         key,
				ExpectedValue: fmt.Sprintf("%v", expected),
				ActualValue:   fmt.Sprintf("%v", actual),
				Source:        "iac",
			})
		}
	}

	// Update asset lineage
	if asset, ok := m.assets[assetID]; ok {
		asset.DriftDetected = len(drifts) > 0
		asset.DriftDetails = drifts
	}

	return drifts
}

// DetectBusinessDrift compares expected business state with observed runtime state.
func (m *LineageMapper) DetectBusinessDrift(ctx context.Context, assetID string, expectedState map[string]interface{}, runtimeState map[string]interface{}) []DriftDetail {
	_ = ctx

	var drifts []DriftDetail

	// Contract terms vs actual billing.
	contractPlan := strings.ToLower(extractString(expectedState, "contract_plan", "plan_tier", "contract_tier", "product_tier"))
	billingPlan := strings.ToLower(extractString(runtimeState, "billing_plan", "subscription_plan", "plan_tier", "product_tier", "stripe_plan"))
	if contractPlan != "" && billingPlan != "" && contractPlan != billingPlan {
		drifts = append(drifts, DriftDetail{
			Field:         "contract.billing.plan_tier",
			ExpectedValue: contractPlan,
			ActualValue:   billingPlan,
			Source:        "contract_vs_billing",
		})
	}

	contractAmount := extractValueString(expectedState, "contract_mrr", "contract_amount", "mrr")
	billingAmount := extractValueString(runtimeState, "billing_mrr", "billing_amount", "mrr")
	if contractAmount != "" && billingAmount != "" && contractAmount != billingAmount {
		drifts = append(drifts, DriftDetail{
			Field:         "contract.billing.amount",
			ExpectedValue: contractAmount,
			ActualValue:   billingAmount,
			Source:        "contract_vs_billing",
		})
	}

	// CRM stage vs product usage.
	crmStage := strings.ToLower(extractString(expectedState, "crm_stage", "deal_stage", "opportunity_stage", "stage"))
	usageState := strings.ToLower(extractString(runtimeState, "usage_state", "product_usage", "engagement_state", "tenant_usage"))
	if crmStage != "" && usageState != "" {
		stageActive := stageImpliesActive(crmStage)
		usageActive := usageImpliesActive(usageState)
		if stageActive != usageActive {
			drifts = append(drifts, DriftDetail{
				Field:         "crm.stage_vs_usage",
				ExpectedValue: crmStage,
				ActualValue:   usageState,
				Source:        "crm_vs_usage",
			})
		}
	}

	// Promised SLA tier vs configured support priority.
	slaTier := strings.ToLower(extractString(expectedState, "sla_tier", "contract_sla_tier", "support_plan"))
	supportPriority := normalizeSupportPriority(extractString(runtimeState, "support_priority", "zendesk_priority", "ticket_priority"))
	requiredPriority := requiredSupportPriorityForSLA(slaTier)
	if requiredPriority != "" && supportPriority != "" && priorityRank(supportPriority) > priorityRank(requiredPriority) {
		drifts = append(drifts, DriftDetail{
			Field:         "sla.support.priority",
			ExpectedValue: requiredPriority,
			ActualValue:   supportPriority,
			Source:        "sla_vs_support",
		})
	}

	if asset, ok := m.GetLineage(assetID); ok {
		asset.DriftDetected = len(drifts) > 0
		asset.DriftDetails = drifts
	}

	return drifts
}

// GetLineage returns lineage for an asset
func (m *LineageMapper) GetLineage(assetID string) (*AssetLineage, bool) {
	if lineage, ok := m.assets[assetID]; ok {
		return lineage, true
	}

	// Support lookups by raw entity IDs (deal, contract, subscription, tenant, etc.)
	// so `/api/v1/lineage/{entity_id}` can resolve business provenance chains.
	for _, lineage := range m.assets {
		if matchesLineageEntity(lineage, assetID) {
			return lineage, true
		}
	}
	return nil, false
}

// GetLineageByCommit returns all assets deployed from a specific commit
func (m *LineageMapper) GetLineageByCommit(commitSHA string) []*AssetLineage {
	var assets []*AssetLineage
	for _, asset := range m.assets {
		if asset.CommitSHA == commitSHA {
			assets = append(assets, asset)
		}
	}
	return assets
}

// GetLineageByRepository returns all assets deployed from a repository
func (m *LineageMapper) GetLineageByRepository(repo string) []*AssetLineage {
	var assets []*AssetLineage
	for _, asset := range m.assets {
		if asset.Repository == repo {
			assets = append(assets, asset)
		}
	}
	return assets
}

// GetLineageByImage returns all assets using a specific container image
func (m *LineageMapper) GetLineageByImage(imageDigest string) []*AssetLineage {
	var assets []*AssetLineage
	for _, asset := range m.assets {
		if asset.ImageDigest == imageDigest {
			assets = append(assets, asset)
		}
	}
	return assets
}

// GenerateLineageID creates a unique ID for lineage tracking
func GenerateLineageID(provider, assetType, assetID string) string {
	data := fmt.Sprintf("%s:%s:%s", provider, assetType, assetID)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// ParseGitHubActionsContext extracts lineage from GitHub Actions environment
func ParseGitHubActionsContext(env map[string]string) *BuildInfo {
	build := &BuildInfo{
		Provider: "github-actions",
	}

	build.Repository = env["GITHUB_REPOSITORY"]
	build.Branch = env["GITHUB_REF_NAME"]
	build.CommitSHA = env["GITHUB_SHA"]
	build.Actor = env["GITHUB_ACTOR"]
	build.ID = env["GITHUB_RUN_ID"]

	if env["GITHUB_SERVER_URL"] != "" && env["GITHUB_REPOSITORY"] != "" {
		build.URL = fmt.Sprintf("%s/%s/actions/runs/%s",
			env["GITHUB_SERVER_URL"],
			env["GITHUB_REPOSITORY"],
			env["GITHUB_RUN_ID"])
	}

	return build
}

// ParseGitLabCIContext extracts lineage from GitLab CI environment
func ParseGitLabCIContext(env map[string]string) *BuildInfo {
	build := &BuildInfo{
		Provider: "gitlab-ci",
	}

	build.Repository = env["CI_PROJECT_PATH"]
	build.Branch = env["CI_COMMIT_REF_NAME"]
	build.CommitSHA = env["CI_COMMIT_SHA"]
	build.Actor = env["GITLAB_USER_LOGIN"]
	build.ID = env["CI_PIPELINE_ID"]
	build.URL = env["CI_PIPELINE_URL"]

	return build
}

func extractString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key].(string); ok && val != "" {
			return val
		}
	}
	return ""
}

func extractValueString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case fmt.Stringer:
			out := strings.TrimSpace(v.String())
			if out != "" {
				return out
			}
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func extractTime(m map[string]interface{}, keys ...string) *time.Time {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		if ts := parseTime(raw); ts != nil {
			return ts
		}
	}
	return nil
}

func parseTime(raw interface{}) *time.Time {
	switch v := raw.(type) {
	case time.Time:
		t := v.UTC()
		return &t
	case *time.Time:
		if v == nil {
			return nil
		}
		t := v.UTC()
		return &t
	case int64:
		t := time.Unix(v, 0).UTC()
		return &t
	case int:
		t := time.Unix(int64(v), 0).UTC()
		return &t
	case float64:
		t := time.Unix(int64(v), 0).UTC()
		return &t
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
			t := time.Unix(unix, 0).UTC()
			return &t
		}
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, s); err == nil {
				t := parsed.UTC()
				return &t
			}
		}
	}
	return nil
}

func buildBusinessChain(entity map[string]interface{}, lineage *AssetLineage) []BusinessLineageStep {
	var chain []BusinessLineageStep
	add := func(stepType, system, entityID, entityRef string, ts *time.Time) {
		if entityID == "" {
			return
		}
		chain = append(chain, BusinessLineageStep{
			StepType:  stepType,
			System:    system,
			EntityID:  entityID,
			EntityRef: entityRef,
			Timestamp: ts,
		})
	}

	crmSystem := firstNonEmpty(extractString(entity, "crm_system"), "crm")
	billingSystem := firstNonEmpty(extractString(entity, "billing_system"), "billing")
	supportSystem := firstNonEmpty(extractString(entity, "support_system"), "support")
	appSystem := firstNonEmpty(extractString(entity, "tenant_system"), "application")
	cloudSystem := firstNonEmpty(extractString(entity, "cloud_provider"), "cloud")

	leadID := extractString(entity, "lead_id", "leadId")
	contactID := extractString(entity, "contact_id", "contactId")
	dealID := firstNonEmpty(lineage.DealID, extractString(entity, "opportunity_id", "opportunityId"))
	contractID := lineage.ContractID
	customerID := firstNonEmpty(lineage.BillingEntityID, extractString(entity, "customer_id"))
	subscriptionID := lineage.SubscriptionID
	tenantID := lineage.TenantID
	namespace := extractString(entity, "k8s_namespace", "namespace")
	infraID := extractString(entity, "infrastructure_id", "cloud_resource_id", "resource_id")

	add(BusinessLineageStepOriginatedFrom, crmSystem, firstNonEmpty(leadID, lineage.LeadSource), lineage.LeadSource, extractTime(entity, "lead_created_at", "leadCreatedAt"))
	add(BusinessLineageStepOriginatedFrom, crmSystem, contactID, "", extractTime(entity, "contact_created_at", "contactCreatedAt"))
	add(BusinessLineageStepOriginatedFrom, crmSystem, dealID, "", extractTime(entity, "deal_closed_at", "dealClosedAt", "closed_won_at", "closedWonAt"))
	add(BusinessLineageStepProvisionedAs, crmSystem, contractID, "", extractTime(entity, "contract_signed_at", "contractSignedAt"))
	add(BusinessLineageStepProvisionedAs, billingSystem, customerID, "", extractTime(entity, "customer_created_at", "customerCreatedAt"))
	add(BusinessLineageStepProvisionedAs, billingSystem, subscriptionID, "", extractTime(entity, "subscription_started_at", "subscriptionStartedAt", "subscription_created_at", "subscriptionCreatedAt"))
	add(BusinessLineageStepProvisionedAs, appSystem, tenantID, "", firstNonEmptyTime(lineage.OnboardedAt, extractTime(entity, "tenant_provisioned_at", "tenantProvisionedAt")))
	add(BusinessLineageStepProvisionedAs, "kubernetes", namespace, "", extractTime(entity, "k8s_provisioned_at", "k8sProvisionedAt"))
	add(BusinessLineageStepProvisionedAs, cloudSystem, infraID, "", extractTime(entity, "infra_deployed_at", "infraDeployedAt", "deployed_at", "deployedAt"))
	add(BusinessLineageStepProvisionedAs, supportSystem, lineage.SupportEntityID, "", extractTime(entity, "support_onboarded_at", "supportOnboardedAt"))

	return chain
}

func matchesLineageEntity(lineage *AssetLineage, entityID string) bool {
	if lineage == nil || entityID == "" {
		return false
	}

	candidates := []string{
		lineage.AssetID,
		lineage.DealID,
		lineage.ContractID,
		lineage.SubscriptionID,
		lineage.TenantID,
		lineage.CRMEntityID,
		lineage.BillingEntityID,
		lineage.SupportEntityID,
	}
	for _, candidate := range candidates {
		if candidate != "" && strings.EqualFold(candidate, entityID) {
			return true
		}
	}
	for _, step := range lineage.BusinessChain {
		if step.EntityID != "" && strings.EqualFold(step.EntityID, entityID) {
			return true
		}
	}
	return false
}

func stageImpliesActive(stage string) bool {
	stage = strings.ToLower(stage)
	return strings.Contains(stage, "closed_won") ||
		strings.Contains(stage, "customer") ||
		strings.Contains(stage, "active")
}

func usageImpliesActive(usage string) bool {
	usage = strings.ToLower(usage)
	return strings.Contains(usage, "active") ||
		strings.Contains(usage, "engaged") ||
		strings.Contains(usage, "adopted") ||
		strings.Contains(usage, "production")
}

func normalizeSupportPriority(priority string) string {
	p := strings.ToLower(strings.TrimSpace(priority))
	switch p {
	case "urgent", "critical", "p0", "p1", "1", "sev1", "high":
		return "p1"
	case "p2", "2", "sev2", "medium":
		return "p2"
	case "p3", "3", "sev3", "normal", "low":
		return "p3"
	case "p4", "4", "sev4":
		return "p4"
	default:
		return p
	}
}

func requiredSupportPriorityForSLA(tier string) string {
	tier = strings.ToLower(strings.TrimSpace(tier))
	switch tier {
	case "enterprise", "platinum", "premium":
		return "p1"
	case "business", "gold":
		return "p2"
	case "pro", "silver":
		return "p3"
	case "starter", "basic", "bronze":
		return "p4"
	default:
		return ""
	}
}

func priorityRank(priority string) int {
	switch normalizeSupportPriority(priority) {
	case "p1":
		return 1
	case "p2":
		return 2
	case "p3":
		return 3
	case "p4":
		return 4
	default:
		return 99
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstNonEmptyTime(values ...*time.Time) *time.Time {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// ImageDigestPattern matches container image digests
var ImageDigestPattern = regexp.MustCompile(`sha256:[a-f0-9]{64}`)

// GitSHAPattern matches git commit SHAs
var GitSHAPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
