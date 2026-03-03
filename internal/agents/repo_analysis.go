package agents

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxRepoFileSize = 2 * 1024 * 1024
const maxRepoResources = 200

var repoScanExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".jsx":  true,
	".tsx":  true,
	".tf":   true,
	".yaml": true,
	".yml":  true,
	".json": true,
	".toml": true,
	".env":  true,
}

var repoSkipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"dist":         true,
	"build":        true,
	"bin":          true,
	".terraform":   true,
	".venv":        true,
	".idea":        true,
	".vscode":      true,
}

type RepoAnalysis struct {
	RepoURL        string         `json:"repo_url"`
	FilesScanned   int            `json:"files_scanned"`
	TotalResources int            `json:"total_resources"`
	Truncated      bool           `json:"truncated"`
	Resources      []RepoResource `json:"resources"`
}

type RepoResource struct {
	Provider     string `json:"provider"`
	Service      string `json:"service,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Identifier   string `json:"identifier"`
	Resource     string `json:"resource"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Snippet      string `json:"snippet"`
	Confidence   string `json:"confidence"`
}

type resourcePattern struct {
	Name         string
	Regex        *regexp.Regexp
	Provider     string
	Service      string
	ResourceType string
	Confidence   string
	CaptureGroup int
}

var resourcePatterns = []resourcePattern{
	{
		Name:       "aws_arn",
		Regex:      regexp.MustCompile(`arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[A-Za-z0-9-_/.:]+`),
		Provider:   "aws",
		Confidence: "high",
	},
	{
		Name:         "aws_s3_uri",
		Regex:        regexp.MustCompile(`s3://[a-z0-9.-]{3,63}`),
		Provider:     "aws",
		Service:      "s3",
		ResourceType: "bucket",
		Confidence:   "high",
	},
	{
		Name:         "aws_s3_arn",
		Regex:        regexp.MustCompile(`arn:aws:s3:::[a-z0-9.-]{3,63}`),
		Provider:     "aws",
		Service:      "s3",
		ResourceType: "bucket",
		Confidence:   "high",
	},
	{
		Name:         "gcp_gcs_uri",
		Regex:        regexp.MustCompile(`gs://[a-z0-9._-]{3,63}`),
		Provider:     "gcp",
		Service:      "storage",
		ResourceType: "bucket",
		Confidence:   "high",
	},
	{
		Name:         "gcp_gcs_url",
		Regex:        regexp.MustCompile(`storage.googleapis.com/[a-z0-9._-]{3,63}`),
		Provider:     "gcp",
		Service:      "storage",
		ResourceType: "bucket",
		Confidence:   "medium",
	},
	{
		Name:         "gcp_project_path",
		Regex:        regexp.MustCompile(`projects/[a-z][a-z0-9-]{4,28}[a-z0-9]`),
		Provider:     "gcp",
		Service:      "resourcemanager",
		ResourceType: "project",
		Confidence:   "medium",
	},
	{
		Name:         "gcp_project_id",
		Regex:        regexp.MustCompile(`(?i)project[_-]?id\s*[:=]\s*["']([a-z][a-z0-9-]{4,28}[a-z0-9])["']`),
		Provider:     "gcp",
		Service:      "resourcemanager",
		ResourceType: "project",
		Confidence:   "medium",
		CaptureGroup: 1,
	},
	{
		Name:         "aws_bucket_name",
		Regex:        regexp.MustCompile(`(?i)bucket[_-]?name\s*[:=]\s*["']([a-z0-9.-]{3,63})["']`),
		Provider:     "aws",
		Service:      "s3",
		ResourceType: "bucket",
		Confidence:   "low",
		CaptureGroup: 1,
	},
}

func scanRepositoryForResources(root, repoURL string) (*RepoAnalysis, error) {
	analysis := &RepoAnalysis{
		RepoURL:   repoURL,
		Resources: []RepoResource{},
	}
	seen := make(map[string]bool)
	resourceCount := 0

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if repoSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !repoScanExtensions[ext] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxRepoFileSize {
			return nil
		}

		file, err := os.Open(path) //#nosec G304,G122 -- path is from controlled filepath.WalkDir
		if err != nil {
			return nil
		}
		defer func() { _ = file.Close() }()

		analysis.FilesScanned++

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 1024*1024)
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			if line == "" {
				continue
			}

			for _, pattern := range resourcePatterns {
				matches := pattern.Regex.FindAllStringSubmatch(line, -1)
				for _, match := range matches {
					resource := match[0]
					identifier := resource
					if pattern.CaptureGroup > 0 && len(match) > pattern.CaptureGroup {
						identifier = match[pattern.CaptureGroup]
					}

					provider := pattern.Provider
					service := pattern.Service
					resourceType := pattern.ResourceType

					switch pattern.Name {
					case "aws_arn":
						arn, err := parseAWSArn(resource)
						if err != nil {
							continue
						}
						service = arn.Service
						resourceType = arn.ResourceType
						if arn.Service == "s3" && resourceType == "" {
							resourceType = "bucket"
						}
						identifier = arn.ResourceID
					case "aws_s3_uri":
						if bucket, ok := parseS3URI(resource); ok {
							identifier = bucket
						}
					case "gcp_gcs_uri":
						if bucket, ok := parseGCSURI(resource); ok {
							identifier = bucket
						}
					case "gcp_gcs_url":
						if bucket, ok := parseGCSURL(resource); ok {
							identifier = bucket
						}
					case "gcp_project_path":
						if project, ok := parseGCPProjectPath(resource); ok {
							identifier = project
						}
					}

					if identifier == "" {
						continue
					}

					key := fmt.Sprintf("%s|%s|%s|%s|%d|%s", provider, service, identifier, path, lineNum, resourceType)
					if seen[key] {
						continue
					}
					seen[key] = true

					snippet := strings.TrimSpace(line)
					if len(snippet) > 200 {
						snippet = snippet[:200] + "..."
					}

					resourceCount++
					if len(analysis.Resources) < maxRepoResources {
						analysis.Resources = append(analysis.Resources, RepoResource{
							Provider:     provider,
							Service:      service,
							ResourceType: resourceType,
							Identifier:   identifier,
							Resource:     resource,
							File:         path,
							Line:         lineNum,
							Snippet:      snippet,
							Confidence:   pattern.Confidence,
						})
					} else {
						analysis.Truncated = true
					}
				}
			}

			if analysis.Truncated {
				return filepath.SkipDir
			}
		}

		return scanner.Err()
	})

	analysis.TotalResources = resourceCount
	if walkErr != nil {
		return nil, walkErr
	}

	return analysis, nil
}
