package sourcegen

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ValidateRequest configures the sourcegen validate command.
type ValidateRequest struct {
	SourceID  string
	OutputDir string
}

// ValidateResult reports validation findings for a generated source.
type ValidateResult struct {
	SourceID string          `json:"source_id"`
	Valid    bool            `json:"valid"`
	Issues   []ValidateIssue `json:"issues"`
}

// ValidateIssue describes one validation finding.
type ValidateIssue struct {
	Severity string `json:"severity"`
	File     string `json:"file"`
	Message  string `json:"message"`
}

// Validate cross-checks a generated source's catalog.yaml, deploy.yaml,
// and source.go for consistency. It catches the class of bugs that the
// Droid review found (missing templateKeys, dangling evidence links,
// undeclared secretKeys) at generation time rather than at CI time.
func Validate(request ValidateRequest) (*ValidateResult, error) {
	sourceID := strings.TrimSpace(request.SourceID)
	if sourceID == "" {
		return nil, fmt.Errorf("source_id is required")
	}
	outputDir := strings.TrimSpace(request.OutputDir)
	if outputDir == "" {
		outputDir = "."
	}

	sourceDir := filepath.Join(outputDir, "sources", sourceID)
	result := &ValidateResult{SourceID: sourceID, Valid: true}

	// 1. Check catalog.yaml exists and has emitted_kinds.
	catalogPath := filepath.Join(sourceDir, "catalog.yaml")
	catalogBytes, err := os.ReadFile(catalogPath) // #nosec G304 -- known path.
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidateIssue{
			Severity: "error",
			File:     catalogPath,
			Message:  fmt.Sprintf("catalog.yaml not found: %v", err),
		})
		return result, nil
	}

	// 2. Check source.go exists and verify templateKeys.
	sourcePath := filepath.Join(sourceDir, "source.go")
	sourceBytes, err := os.ReadFile(sourcePath) // #nosec G304 -- known path.
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidateIssue{
			Severity: "error",
			File:     sourcePath,
			Message:  fmt.Sprintf("source.go not found: %v", err),
		})
		return result, nil
	}
	sourceText := string(sourceBytes)

	// 3. Verify templateKeys include all template variables from defaultBaseURLTemplate.
	templateKeys := extractTemplateKeysFromSource(sourceText)
	baseURLTemplate := extractBaseURLTemplateFromSource(sourceText)
	if baseURLTemplate != "" {
		templateVars := extractTemplateKeys(baseURLTemplate)
		for _, varKey := range templateVars {
			found := false
			for _, tk := range templateKeys {
				if tk == varKey {
					found = true
					break
				}
			}
			if !found {
				result.Valid = false
				result.Issues = append(result.Issues, ValidateIssue{
					Severity: "error",
					File:     sourcePath,
					Message:  fmt.Sprintf("templateKey %q is referenced in defaultBaseURLTemplate %q but not in templateKeys", varKey, baseURLTemplate),
				})
			}
		}
	}

	// 4. Check deploy.yaml exists and verify secretKeys.
	deployPath := filepath.Join(sourceDir, "deploy.yaml")
	deployBytes, err := os.ReadFile(deployPath) // #nosec G304 -- known path.
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidateIssue{
			Severity: "warning",
			File:     deployPath,
			Message:  fmt.Sprintf("deploy.yaml not found: %v", err),
		})
	} else {
		deployText := string(deployBytes)
		secretKeys := extractSecretKeysFromDeploy(deployText)
		envRefs := extractEnvRefsFromDeploy(deployText)
		for _, ref := range envRefs {
			found := false
			for _, sk := range secretKeys {
				if sk == ref {
					found = true
					break
				}
			}
			if !found {
				result.Valid = false
				result.Issues = append(result.Issues, ValidateIssue{
					Severity: "error",
					File:     deployPath,
					Message:  fmt.Sprintf("env reference %q is used in deploy.yaml but not declared in secretKeys", ref),
				})
			}
		}
	}

	// 5. Verify the source is wired into the source registry.
	registryPath := filepath.Join(outputDir, "internal/sourceregistry/registry.go")
	registryBytes, err := os.ReadFile(registryPath) // #nosec G304 -- known path.
	if err == nil {
		registryText := string(registryBytes)
		if !strings.Contains(registryText, fmt.Sprintf(`name: %q`, sourceID)) {
			result.Issues = append(result.Issues, ValidateIssue{
				Severity: "warning",
				File:     registryPath,
				Message:  fmt.Sprintf("source %q is not wired into the source registry", sourceID),
			})
		}
	}

	// 6. Verify the source is wired into the projection registry.
	projRegistryPath := filepath.Join(outputDir, "internal/sourceprojection/registry.go")
	projRegistryBytes, err := os.ReadFile(projRegistryPath) // #nosec G304 -- known path.
	if err == nil {
		projRegistryText := string(projRegistryBytes)
		kinds := parseEmittedKindsFromCatalog(catalogBytes)
		for _, kind := range kinds {
			if !strings.Contains(projRegistryText, fmt.Sprintf("%q:", kind)) {
				result.Issues = append(result.Issues, ValidateIssue{
					Severity: "warning",
					File:     projRegistryPath,
					Message:  fmt.Sprintf("kind %q is not wired into the projection registry", kind),
				})
			}
		}
	}

	// 7. Verify docs reference includes the source.
	docsPath := filepath.Join(outputDir, "docs/reference/sources.md")
	docsBytes, err := os.ReadFile(docsPath) // #nosec G304 -- known path.
	if err == nil {
		docsText := string(docsBytes)
		if !strings.Contains(docsText, fmt.Sprintf("| `%s` |", sourceID)) {
			result.Issues = append(result.Issues, ValidateIssue{
				Severity: "warning",
				File:     docsPath,
				Message:  fmt.Sprintf("source %q is not listed in docs/reference/sources.md", sourceID),
			})
		}
	}

	if len(result.Issues) > 0 {
		for _, issue := range result.Issues {
			if issue.Severity == "error" {
				result.Valid = false
				break
			}
		}
	}

	return result, nil
}

var templateKeysPattern = regexp.MustCompile(`var templateKeys = \[\]string\{([^}]+)\}`)
var baseURLTemplatePattern = regexp.MustCompile(`defaultBaseURLTemplate = "([^"]+)"`)
var envRefPattern = regexp.MustCompile(`env:(\w+)`)

func extractTemplateKeysFromSource(sourceText string) []string {
	matches := templateKeysPattern.FindStringSubmatch(sourceText)
	if len(matches) < 2 {
		return nil
	}
	raw := matches[1]
	var keys []string
	for _, part := range strings.Split(raw, ",") {
		key := strings.Trim(strings.TrimSpace(part), `"`)
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func extractBaseURLTemplateFromSource(sourceText string) string {
	matches := baseURLTemplatePattern.FindStringSubmatch(sourceText)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func extractSecretKeysFromDeploy(deployText string) []string {
	// Find the secretKeys section.
	lines := strings.Split(deployText, "\n")
	var keys []string
	inSecretKeys := false
	for _, line := range lines {
		if strings.HasPrefix(line, "secretKeys:") {
			inSecretKeys = true
			continue
		}
		if inSecretKeys {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "- ") {
				key := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				keys = append(keys, key)
			} else if !strings.HasPrefix(line, " ") && trimmed != "" {
				inSecretKeys = false
			}
		}
	}
	return keys
}

func extractEnvRefsFromDeploy(deployText string) []string {
	matches := envRefPattern.FindAllStringSubmatch(deployText, -1)
	var refs []string
	for _, m := range matches {
		refs = append(refs, m[1])
	}
	return refs
}
