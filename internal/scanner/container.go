package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ContainerScanner scans container images for vulnerabilities
type ContainerScanner struct {
	registries map[string]RegistryClient
	vulnDB     VulnerabilityDB
	client     *http.Client
}

// RegistryClient interface for container registries
type RegistryClient interface {
	Name() string
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
	vulns, err := client.GetVulnerabilities(ctx, repo, tag)
	if err != nil {
		// Continue without native scan results
		vulns = []ImageVulnerability{}
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

// ScanAllRepositories scans all repositories in registered registries
func (s *ContainerScanner) ScanAllRepositories(ctx context.Context) ([]ContainerScanResult, error) {
	var results []ContainerScanResult

	for name, client := range s.registries {
		repos, err := client.ListRepositories(ctx)
		if err != nil {
			continue
		}

		for _, repo := range repos {
			tags, err := client.ListTags(ctx, repo.Name)
			if err != nil {
				continue
			}

			// Scan latest/main tags
			for _, tag := range tags {
				if tag.Name == "latest" || tag.Name == "main" || strings.HasPrefix(tag.Name, "v") {
					result, err := s.ScanImage(ctx, name, repo.Name, tag.Name)
					if err == nil {
						results = append(results, *result)
					}
				}
			}
		}
	}

	return results, nil
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

// ECRClient implements RegistryClient for AWS ECR
type ECRClient struct {
	region    string
	accountID string
}

func NewECRClient(region, accountID string) *ECRClient {
	return &ECRClient{region: region, accountID: accountID}
}

func (c *ECRClient) Name() string { return "ecr" }

func (c *ECRClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	// Would use AWS SDK to list repositories
	return nil, fmt.Errorf("ECR SDK integration required")
}

func (c *ECRClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	return nil, fmt.Errorf("ECR SDK integration required")
}

func (c *ECRClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	return nil, fmt.Errorf("ECR SDK integration required")
}

func (c *ECRClient) GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error) {
	// Would use ECR DescribeImageScanFindings
	return nil, fmt.Errorf("ECR SDK integration required")
}

// GCRClient implements RegistryClient for Google Container Registry
type GCRClient struct {
	projectID string
}

func NewGCRClient(projectID string) *GCRClient {
	return &GCRClient{projectID: projectID}
}

func (c *GCRClient) Name() string { return "gcr" }

func (c *GCRClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	return nil, fmt.Errorf("GCR SDK integration required")
}

func (c *GCRClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	return nil, fmt.Errorf("GCR SDK integration required")
}

func (c *GCRClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	return nil, fmt.Errorf("GCR SDK integration required")
}

func (c *GCRClient) GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error) {
	// Would use Container Analysis API
	return nil, fmt.Errorf("GCR SDK integration required")
}

// ACRClient implements RegistryClient for Azure Container Registry
type ACRClient struct {
	registryName   string
	subscriptionID string
}

func NewACRClient(registryName, subscriptionID string) *ACRClient {
	return &ACRClient{registryName: registryName, subscriptionID: subscriptionID}
}

func (c *ACRClient) Name() string { return "acr" }

func (c *ACRClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	return nil, fmt.Errorf("ACR SDK integration required")
}

func (c *ACRClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	return nil, fmt.Errorf("ACR SDK integration required")
}

func (c *ACRClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	return nil, fmt.Errorf("ACR SDK integration required")
}

func (c *ACRClient) GetVulnerabilities(ctx context.Context, repo, tag string) ([]ImageVulnerability, error) {
	// Would use Defender for Cloud API
	return nil, fmt.Errorf("ACR SDK integration required")
}

// TrivyScanner wraps Trivy for local scanning
type TrivyScanner struct {
	binaryPath string
}

func NewTrivyScanner(binaryPath string) *TrivyScanner {
	return &TrivyScanner{binaryPath: binaryPath}
}

// ScanImage uses Trivy to scan a container image
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string) (*ContainerScanResult, error) {
	// Would execute trivy image --format json <imageRef>
	// and parse the JSON output
	return nil, fmt.Errorf("trivy binary execution not implemented")
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
