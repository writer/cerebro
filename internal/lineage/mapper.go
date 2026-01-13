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

	// Drift Detection
	DriftDetected bool          `json:"drift_detected"`
	DriftDetails  []DriftDetail `json:"drift_details,omitempty"`
	LastSynced    time.Time     `json:"last_synced"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

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

// GetLineage returns lineage for an asset
func (m *LineageMapper) GetLineage(assetID string) (*AssetLineage, bool) {
	lineage, ok := m.assets[assetID]
	return lineage, ok
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

// ImageDigestPattern matches container image digests
var ImageDigestPattern = regexp.MustCompile(`sha256:[a-f0-9]{64}`)

// GitSHAPattern matches git commit SHAs
var GitSHAPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
