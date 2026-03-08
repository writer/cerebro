package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ContainerScanner scans container images for vulnerabilities
type ContainerScanner struct {
	registries map[string]RegistryClient
	vulnDB     VulnerabilityDB
	localScan  ImageScanner
	client     *http.Client
}

type ImageScanner interface {
	ScanImage(ctx context.Context, imageRef string) (*ContainerScanResult, error)
}

// RegistryClient interface for container registries
type RegistryClient interface {
	Name() string
	RegistryHost() string
	QualifyImageRef(repo, tag string) string
	ListRepositories(ctx context.Context) ([]Repository, error)
	ListTags(ctx context.Context, repo string) ([]ImageTag, error)
	GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error)
	GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error)
}

// Repository represents a container repository
type Repository struct {
	Name       string    `json:"name"`
	Registry   string    `json:"registry"`
	URI        string    `json:"uri"`
	CreatedAt  time.Time `json:"created_at"`
	PushedAt   time.Time `json:"pushed_at"`
	TagCount   int       `json:"tag_count"`
	ScanStatus string    `json:"scan_status"`
}

// ImageTag represents a container image tag
type ImageTag struct {
	Name       string    `json:"name"`
	Digest     string    `json:"digest"`
	PushedAt   time.Time `json:"pushed_at"`
	SizeBytes  int64     `json:"size_bytes"`
	ScanStatus string    `json:"scan_status"`
}

// ImageManifest represents container image metadata
type ImageManifest struct {
	Digest    string            `json:"digest"`
	MediaType string            `json:"media_type"`
	Config    ImageConfig       `json:"config"`
	Layers    []Layer           `json:"layers"`
	Labels    map[string]string `json:"labels"`
	Created   time.Time         `json:"created"`
}

type ImageConfig struct {
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	Entrypoint   []string          `json:"entrypoint"`
	Cmd          []string          `json:"cmd"`
	Env          []string          `json:"env"`
	User         string            `json:"user"`
	WorkDir      string            `json:"workdir"`
	Labels       map[string]string `json:"labels"`
}

type Layer struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

// ImageVulnerability represents a vulnerability in a container image
type ImageVulnerability struct {
	ID               string    `json:"id"`
	CVE              string    `json:"cve"`
	Severity         string    `json:"severity"`
	Package          string    `json:"package"`
	InstalledVersion string    `json:"installed_version"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	Description      string    `json:"description"`
	CVSS             float64   `json:"cvss"`
	Published        time.Time `json:"published"`
	Exploitable      bool      `json:"exploitable"`
	InKEV            bool      `json:"in_kev"`
	References       []string  `json:"references"`
}

// ContainerScanResult represents scan results for an image
type ContainerScanResult struct {
	Repository      string               `json:"repository"`
	Tag             string               `json:"tag"`
	Digest          string               `json:"digest"`
	Registry        string               `json:"registry"`
	ScanTime        time.Time            `json:"scan_time"`
	OS              string               `json:"os"`
	Architecture    string               `json:"architecture"`
	Vulnerabilities []ImageVulnerability `json:"vulnerabilities"`
	Summary         VulnerabilitySummary `json:"summary"`
	Findings        []ContainerFinding   `json:"findings"`
}

type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
	Fixable  int `json:"fixable"`
}

type ContainerFinding struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // vulnerability, misconfiguration, secret
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	CVE         string `json:"cve,omitempty"`
	Package     string `json:"package,omitempty"`
}

// VulnerabilityDB interface for vulnerability database
type VulnerabilityDB interface {
	LookupCVE(cve string) (*CVEInfo, bool)
	IsKEV(cve string) bool
}

type CVEInfo struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	Published   time.Time `json:"published"`
	Exploitable bool      `json:"exploitable"`
	InKEV       bool      `json:"in_kev"`
}

var manifestParseFailures atomic.Int64

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{
		registries: make(map[string]RegistryClient),
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (s *ContainerScanner) RegisterRegistry(client RegistryClient) {
	s.registries[client.Name()] = client
}

func (s *ContainerScanner) SetVulnDB(db VulnerabilityDB) {
	s.vulnDB = db
}

func (s *ContainerScanner) SetFallbackScanner(scanner ImageScanner) {
	s.localScan = scanner
}

// ScanImage scans a container image for vulnerabilities
func (s *ContainerScanner) ScanImage(ctx context.Context, registry, repo, tag string) (*ContainerScanResult, error) {
	client, ok := s.registries[registry]
	if !ok {
		return nil, fmt.Errorf("registry not configured: %s", registry)
	}

	// Get manifest
	manifest, err := client.GetManifest(ctx, repo, tag)
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}

	// Get vulnerabilities from registry's native scanning
	vulns, vulnErr := client.GetVulnerabilities(ctx, repo, tag)
	if vulnErr != nil {
		if s.localScan != nil {
			imageRef := client.QualifyImageRef(repo, tag)
			localResult, scanErr := s.localScan.ScanImage(ctx, imageRef)
			if scanErr != nil {
				return nil, fmt.Errorf("local scan failed after registry error: %w", scanErr)
			}
			vulns = localResult.Vulnerabilities
		} else {
			vulns = []ImageVulnerability{}
		}
	}

	// Enrich with KEV data
	for i := range vulns {
		if s.vulnDB != nil && s.vulnDB.IsKEV(vulns[i].CVE) {
			vulns[i].InKEV = true
			vulns[i].Exploitable = true
		}
	}

	result := &ContainerScanResult{
		Repository:      repo,
		Tag:             tag,
		Digest:          manifest.Digest,
		Registry:        registry,
		ScanTime:        time.Now(),
		OS:              manifest.Config.OS,
		Architecture:    manifest.Config.Architecture,
		Vulnerabilities: vulns,
		Summary:         summarizeVulnerabilities(vulns),
		Findings:        generateFindings(vulns, manifest),
	}

	return result, nil
}

// ScanAllRepositories scans all repositories in registered registries.
// Returns partial results and aggregated errors - scanning continues on individual failures.
func (s *ContainerScanner) ScanAllRepositories(ctx context.Context) ([]ContainerScanResult, error) {
	var results []ContainerScanResult
	var scanErrors []string

	for name, client := range s.registries {
		repos, err := client.ListRepositories(ctx)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("registry %s: list repos: %v", name, err))
			continue
		}

		for _, repo := range repos {
			tags, err := client.ListTags(ctx, repo.Name)
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("registry %s repo %s: list tags: %v", name, repo.Name, err))
				continue
			}

			// Scan latest/main tags
			for _, tag := range tags {
				if tag.Name == "latest" || tag.Name == "main" || strings.HasPrefix(tag.Name, "v") {
					result, err := s.ScanImage(ctx, name, repo.Name, tag.Name)
					if err != nil {
						scanErrors = append(scanErrors, fmt.Sprintf("%s/%s:%s: %v", name, repo.Name, tag.Name, err))
						continue
					}
					results = append(results, *result)
				}
			}
		}
	}

	var err error
	if len(scanErrors) > 0 {
		err = fmt.Errorf("scan completed with %d errors: %s", len(scanErrors), strings.Join(scanErrors[:min(5, len(scanErrors))], "; "))
	}
	return results, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func summarizeVulnerabilities(vulns []ImageVulnerability) VulnerabilitySummary {
	summary := VulnerabilitySummary{}

	for _, v := range vulns {
		summary.Total++
		if v.FixedVersion != "" {
			summary.Fixable++
		}

		switch strings.ToLower(v.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Unknown++
		}
	}

	return summary
}

func generateFindings(vulns []ImageVulnerability, manifest *ImageManifest) []ContainerFinding {
	var findings []ContainerFinding

	// Vulnerability findings
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" || v.InKEV {
			finding := ContainerFinding{
				ID:          fmt.Sprintf("vuln-%s-%s", v.CVE, v.Package),
				Type:        "vulnerability",
				Severity:    v.Severity,
				Title:       fmt.Sprintf("%s in %s", v.CVE, v.Package),
				Description: v.Description,
				CVE:         v.CVE,
				Package:     v.Package,
			}

			if v.FixedVersion != "" {
				finding.Remediation = fmt.Sprintf("Update %s to version %s", v.Package, v.FixedVersion)
			} else {
				finding.Remediation = "No fix available. Consider using an alternative package or mitigating controls."
			}

			if v.InKEV {
				finding.Severity = "critical"
				finding.Title = "[KEV] " + finding.Title
			}

			findings = append(findings, finding)
		}
	}

	// Configuration findings
	if manifest.Config.User == "" || manifest.Config.User == "root" {
		findings = append(findings, ContainerFinding{
			ID:          "config-root-user",
			Type:        "misconfiguration",
			Severity:    "medium",
			Title:       "Container runs as root",
			Description: "Container image is configured to run as root user",
			Remediation: "Add USER directive to Dockerfile to run as non-root user",
		})
	}

	// Check for sensitive environment variables
	for _, env := range manifest.Config.Env {
		if containsSensitive(env) {
			findings = append(findings, ContainerFinding{
				ID:          "config-sensitive-env",
				Type:        "secret",
				Severity:    "high",
				Title:       "Sensitive data in environment variable",
				Description: "Image contains potentially sensitive data in environment variables",
				Remediation: "Remove secrets from image and use runtime secret injection",
			})
			break
		}
	}

	return findings
}

func containsSensitive(env string) bool {
	lower := strings.ToLower(env)
	sensitivePatterns := []string{"password", "secret", "api_key", "apikey", "token", "credential"}
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) && strings.Contains(env, "=") {
			// Check if it has a value (not just the variable name)
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && len(parts[1]) > 0 {
				return true
			}
		}
	}
	return false
}

type ecrAPI interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	BatchGetImage(ctx context.Context, params *ecr.BatchGetImageInput, optFns ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error)
	DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

// ECRClient implements RegistryClient for AWS ECR
type ECRClient struct {
	region    string
	accountID string
	client    ecrAPI
	initOnce  sync.Once
	initErr   error
}

func NewECRClient(region, accountID string) *ECRClient {
	return &ECRClient{region: region, accountID: accountID}
}

func NewECRClientWithAPI(region, accountID string, api ecrAPI) *ECRClient {
	return &ECRClient{region: region, accountID: accountID, client: api}
}

func (c *ECRClient) Name() string { return "ecr" }

func (c *ECRClient) RegistryHost() string {
	if c.accountID != "" && c.region != "" {
		return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", c.accountID, c.region)
	}
	return ""
}

func (c *ECRClient) QualifyImageRef(repo, tag string) string {
	host := c.RegistryHost()
	if host == "" {
		return fmt.Sprintf("%s:%s", repo, tag)
	}
	return fmt.Sprintf("%s/%s:%s", host, repo, tag)
}

func (c *ECRClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	if err := c.ensureClient(ctx); err != nil {
		return nil, err
	}

	var repos []Repository
	input := &ecr.DescribeRepositoriesInput{}
	if c.accountID != "" {
		input.RegistryId = aws.String(c.accountID)
	}

	for {
		out, err := c.client.DescribeRepositories(ctx, input)
		if err != nil {
			return nil, err
		}
		for _, repo := range out.Repositories {
			repos = append(repos, Repository{
				Name:      aws.ToString(repo.RepositoryName),
				Registry:  "ecr",
				URI:       aws.ToString(repo.RepositoryUri),
				CreatedAt: aws.ToTime(repo.CreatedAt),
			})
		}
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}

	return repos, nil
}

func (c *ECRClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	if err := c.ensureClient(ctx); err != nil {
		return nil, err
	}

	var tags []ImageTag
	input := &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repo),
		Filter: &ecrtypes.DescribeImagesFilter{
			TagStatus: ecrtypes.TagStatusTagged,
		},
	}
	if c.accountID != "" {
		input.RegistryId = aws.String(c.accountID)
	}

	for {
		out, err := c.client.DescribeImages(ctx, input)
		if err != nil {
			return nil, err
		}
		for _, detail := range out.ImageDetails {
			for _, tag := range detail.ImageTags {
				tags = append(tags, ImageTag{
					Name:      tag,
					Digest:    aws.ToString(detail.ImageDigest),
					PushedAt:  aws.ToTime(detail.ImagePushedAt),
					SizeBytes: aws.ToInt64(detail.ImageSizeInBytes),
				})
			}
		}
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}

	return tags, nil
}

func (c *ECRClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	if err := c.ensureClient(ctx); err != nil {
		return nil, err
	}

	input := &ecr.BatchGetImageInput{
		RepositoryName: aws.String(repo),
		ImageIds: []ecrtypes.ImageIdentifier{
			{ImageTag: aws.String(tag)},
		},
	}
	if c.accountID != "" {
		input.RegistryId = aws.String(c.accountID)
	}

	out, err := c.client.BatchGetImage(ctx, input)
	if err != nil {
		return nil, err
	}
	if len(out.Images) == 0 {
		return nil, fmt.Errorf("image not found")
	}

	img := out.Images[0]
	manifest := &ImageManifest{
		Digest:    aws.ToString(img.ImageId.ImageDigest),
		MediaType: aws.ToString(img.ImageManifestMediaType),
	}
	if img.ImageManifest != nil {
		if err := parseManifest([]byte(*img.ImageManifest), manifest); err != nil {
			slog.Warn("failed to parse image manifest",
				"registry", "ecr",
				"repository", repo,
				"tag", tag,
				"digest", manifest.Digest,
				"manifest_size", len(*img.ImageManifest),
				"error", err,
			)
			return nil, fmt.Errorf("parse manifest: %w", err)
		}
	}

	return manifest, nil
}

func (c *ECRClient) GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error) {
	if err := c.ensureClient(ctx); err != nil {
		return nil, err
	}

	var vulns []ImageVulnerability
	input := &ecr.DescribeImageScanFindingsInput{
		RepositoryName: aws.String(repo),
		ImageId:        &ecrtypes.ImageIdentifier{ImageTag: aws.String(tag)},
	}
	if c.accountID != "" {
		input.RegistryId = aws.String(c.accountID)
	}

	for {
		out, err := c.client.DescribeImageScanFindings(ctx, input)
		if err != nil {
			return nil, err
		}
		if out.ImageScanFindings != nil {
			for _, finding := range out.ImageScanFindings.Findings {
				vuln := ImageVulnerability{
					ID:          aws.ToString(finding.Name),
					CVE:         aws.ToString(finding.Name),
					Severity:    strings.ToLower(string(finding.Severity)),
					Description: aws.ToString(finding.Description),
				}
				if finding.Uri != nil {
					vuln.References = []string{aws.ToString(finding.Uri)}
				}
				for _, attr := range finding.Attributes {
					key := aws.ToString(attr.Key)
					value := aws.ToString(attr.Value)
					switch key {
					case "package_name", "package":
						vuln.Package = value
					case "package_version", "installed_version":
						vuln.InstalledVersion = value
					case "fixed_version", "fix_version":
						vuln.FixedVersion = value
					}
				}
				vulns = append(vulns, vuln)
			}
		}
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}

	return vulns, nil
}

func (c *ECRClient) ensureClient(ctx context.Context) error {
	if c.client != nil {
		return nil
	}
	if c.region == "" {
		return fmt.Errorf("region is required")
	}
	c.initOnce.Do(func() {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.region))
		if err != nil {
			c.initErr = err
			return
		}
		c.client = ecr.NewFromConfig(cfg)
	})
	return c.initErr
}

// GCRClient implements RegistryClient for Google Container Registry
type GCRClient struct {
	projectID    string
	registryHost string
	accessToken  string
	client       *http.Client
}

func NewGCRClient(projectID string) *GCRClient {
	return &GCRClient{
		projectID:    projectID,
		registryHost: "gcr.io",
		client:       &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *GCRClient) Name() string { return "gcr" }

func (c *GCRClient) RegistryHost() string { return stripURLScheme(c.registryHost) }

func (c *GCRClient) QualifyImageRef(repo, tag string) string {
	fullRepo := c.qualifyRepo(repo)
	return fmt.Sprintf("%s/%s:%s", c.RegistryHost(), fullRepo, tag)
}

func (c *GCRClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	url := fmt.Sprintf("%s/v2/_catalog?n=1000", c.baseURL())
	body, _, err := c.doRequest(ctx, http.MethodGet, url, "")
	if err != nil {
		return nil, err
	}

	var payload struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	repos := make([]Repository, 0, len(payload.Repositories))
	prefix := c.projectID + "/"
	for _, repo := range payload.Repositories {
		name := strings.TrimPrefix(repo, prefix)
		repos = append(repos, Repository{
			Name:     name,
			Registry: "gcr",
			URI:      fmt.Sprintf("%s/%s", c.baseURL(), repo),
		})
	}
	return repos, nil
}

func (c *GCRClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	fullRepo := c.qualifyRepo(repo)
	url := fmt.Sprintf("%s/v2/%s/tags/list", c.baseURL(), fullRepo)
	body, _, err := c.doRequest(ctx, http.MethodGet, url, "")
	if err != nil {
		return nil, err
	}

	var payload struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	tags := make([]ImageTag, 0, len(payload.Tags))
	for _, tag := range payload.Tags {
		tags = append(tags, ImageTag{Name: tag})
	}
	return tags, nil
}

func (c *GCRClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	fullRepo := c.qualifyRepo(repo)
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", c.baseURL(), fullRepo, tag)
	body, headers, err := c.doRequest(ctx, http.MethodGet, url, "application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return nil, err
	}

	manifest := &ImageManifest{
		Digest:    headers.Get("Docker-Content-Digest"),
		MediaType: headers.Get("Content-Type"),
	}
	if err := parseManifest(body, manifest); err != nil {
		slog.Warn("failed to parse image manifest",
			"registry", "gcr",
			"repository", repo,
			"tag", tag,
			"digest", manifest.Digest,
			"manifest_size", len(body),
			"error", err,
		)
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return manifest, nil
}

func (c *GCRClient) GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error) {
	return nil, fmt.Errorf("registry does not provide vulnerability scanning")
}

func (c *GCRClient) SetAccessToken(token string) {
	c.accessToken = token
}

func (c *GCRClient) SetRegistryHost(host string) {
	if host != "" {
		c.registryHost = strings.TrimRight(host, "/")
	}
}

func (c *GCRClient) baseURL() string {
	if strings.HasPrefix(c.registryHost, "http://") || strings.HasPrefix(c.registryHost, "https://") {
		return c.registryHost
	}
	return "https://" + c.registryHost
}

func (c *GCRClient) qualifyRepo(repo string) string {
	if strings.HasPrefix(repo, c.projectID+"/") {
		return repo
	}
	return c.projectID + "/" + repo
}

func (c *GCRClient) doRequest(ctx context.Context, method, url, accept string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, resp.Header, fmt.Errorf("registry API error %d: %s", resp.StatusCode, string(body))
	}

	return body, resp.Header, nil
}

// ACRClient implements RegistryClient for Azure Container Registry
type ACRClient struct {
	registryName    string
	subscriptionID  string
	username        string
	password        string
	client          *http.Client
	baseURLOverride string
}

func NewACRClient(registryName, subscriptionID string) *ACRClient {
	return &ACRClient{
		registryName:   registryName,
		subscriptionID: subscriptionID,
		client:         &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *ACRClient) Name() string { return "acr" }

func (c *ACRClient) RegistryHost() string {
	if c.baseURLOverride != "" {
		return stripURLScheme(c.baseURLOverride)
	}
	return fmt.Sprintf("%s.azurecr.io", c.registryName)
}

func (c *ACRClient) QualifyImageRef(repo, tag string) string {
	host := c.RegistryHost()
	return fmt.Sprintf("%s/%s:%s", host, repo, tag)
}

func (c *ACRClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	url := fmt.Sprintf("%s/v2/_catalog?n=1000", c.baseURL())
	body, _, err := c.doRequest(ctx, http.MethodGet, url, "")
	if err != nil {
		return nil, err
	}

	var payload struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	repos := make([]Repository, 0, len(payload.Repositories))
	for _, repo := range payload.Repositories {
		repos = append(repos, Repository{
			Name:     repo,
			Registry: "acr",
			URI:      fmt.Sprintf("%s/%s", c.baseURL(), repo),
		})
	}
	return repos, nil
}

func (c *ACRClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	url := fmt.Sprintf("%s/v2/%s/tags/list", c.baseURL(), repo)
	body, _, err := c.doRequest(ctx, http.MethodGet, url, "")
	if err != nil {
		return nil, err
	}

	var payload struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	tags := make([]ImageTag, 0, len(payload.Tags))
	for _, tag := range payload.Tags {
		tags = append(tags, ImageTag{Name: tag})
	}
	return tags, nil
}

func (c *ACRClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", c.baseURL(), repo, tag)
	body, headers, err := c.doRequest(ctx, http.MethodGet, url, "application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return nil, err
	}

	manifest := &ImageManifest{
		Digest:    headers.Get("Docker-Content-Digest"),
		MediaType: headers.Get("Content-Type"),
	}
	if err := parseManifest(body, manifest); err != nil {
		slog.Warn("failed to parse image manifest",
			"registry", "acr",
			"repository", repo,
			"tag", tag,
			"digest", manifest.Digest,
			"manifest_size", len(body),
			"error", err,
		)
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return manifest, nil
}

func (c *ACRClient) GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error) {
	return nil, fmt.Errorf("registry does not provide vulnerability scanning")
}

func (c *ACRClient) SetCredentials(username, password string) {
	c.username = username
	c.password = password
}

func (c *ACRClient) SetBaseURL(url string) {
	c.baseURLOverride = strings.TrimRight(url, "/")
}

func (c *ACRClient) baseURL() string {
	if c.baseURLOverride != "" {
		return c.baseURLOverride
	}
	return fmt.Sprintf("https://%s.azurecr.io", c.registryName)
}

func (c *ACRClient) doRequest(ctx context.Context, method, url, accept string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c.username != "" || c.password != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
		req.Header.Set("Authorization", "Basic "+credentials)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, resp.Header, fmt.Errorf("registry API error %d: %s", resp.StatusCode, string(body))
	}

	return body, resp.Header, nil
}

// TrivyScanner wraps Trivy for local scanning
type TrivyScanner struct {
	binaryPath string
}

func NewTrivyScanner(binaryPath string) *TrivyScanner {
	if binaryPath == "" {
		binaryPath = "trivy"
	}
	return &TrivyScanner{binaryPath: binaryPath}
}

// ScanImage uses Trivy to scan a container image
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string) (*ContainerScanResult, error) {
	if strings.TrimSpace(s.binaryPath) == "" {
		return nil, fmt.Errorf("trivy binary path is required")
	}
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return nil, fmt.Errorf("image reference is required")
	}
	if strings.ContainsAny(imageRef, " \t\r\n") {
		return nil, fmt.Errorf("image reference must not contain whitespace")
	}

	cmd := exec.CommandContext(ctx, s.binaryPath, "image", "--format", "json", imageRef) // #nosec G204 -- fixed binary/arguments, no shell interpolation
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w: %s", err, string(output))
	}

	result, err := ParseTrivyOutput(output)
	if err != nil {
		return nil, err
	}
	result.Repository = imageRef
	result.Tag = ""
	return result, nil
}

// ParseTrivyOutput parses Trivy JSON output
func ParseTrivyOutput(data []byte) (*ContainerScanResult, error) {
	var trivyResult struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				Description      string `json:"Description"`
				CVSS             map[string]struct {
					V3Score float64 `json:"V3Score"`
				} `json:"CVSS"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &trivyResult); err != nil {
		return nil, err
	}

	result := &ContainerScanResult{
		ScanTime: time.Now(),
	}

	for _, r := range trivyResult.Results {
		for _, v := range r.Vulnerabilities {
			vuln := ImageVulnerability{
				CVE:              v.VulnerabilityID,
				Severity:         v.Severity,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Description:      v.Description,
			}

			// Get CVSS score
			if nvd, ok := v.CVSS["nvd"]; ok {
				vuln.CVSS = nvd.V3Score
			}

			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	result.Summary = summarizeVulnerabilities(result.Vulnerabilities)
	return result, nil
}

type registryManifest struct {
	MediaType string `json:"mediaType"`
	Config    struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

func parseManifest(data []byte, manifest *ImageManifest) error {
	var decoded registryManifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		manifestParseFailures.Add(1)
		return err
	}

	if decoded.MediaType != "" {
		manifest.MediaType = decoded.MediaType
	}
	manifest.Config = ImageConfig{Labels: make(map[string]string)}
	manifest.Layers = make([]Layer, 0, len(decoded.Layers))
	for _, layer := range decoded.Layers {
		manifest.Layers = append(manifest.Layers, Layer{
			Digest:    layer.Digest,
			MediaType: layer.MediaType,
			Size:      layer.Size,
		})
	}
	return nil
}

// ManifestParseFailures returns total manifest parse failures observed.
func ManifestParseFailures() int64 {
	return manifestParseFailures.Load()
}

// stripURLScheme removes http:// or https:// prefixes from a host string,
// returning a bare host suitable for use in container image references.
func stripURLScheme(host string) string {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	return host
}
