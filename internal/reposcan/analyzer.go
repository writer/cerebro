package reposcan

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanner"
)

type FilesystemAnalyzer struct {
	Analyzer      *filesystemanalyzer.Analyzer
	ConfigScanner scanner.ConfigScanner
}

func (a FilesystemAnalyzer) Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error) {
	analyzer := a.Analyzer
	if analyzer == nil {
		analyzer = filesystemanalyzer.New(filesystemanalyzer.Options{})
	}
	if input.Checkout == nil || strings.TrimSpace(input.Checkout.Path) == "" {
		return nil, fmt.Errorf("repository checkout is required for filesystem analysis")
	}
	catalog, err := analyzer.Analyze(ctx, input.Checkout.Path)
	if err != nil {
		return nil, err
	}

	filteredArtifacts := filterIaCArtifacts(catalog.IaCArtifacts, input.ChangedPaths)
	catalog.IaCArtifacts = filteredArtifacts
	if a.ConfigScanner != nil {
		catalog.Misconfigurations, err = a.scanConfigMisconfigurations(ctx, input, filteredArtifacts)
		if err != nil {
			return nil, err
		}
	} else {
		catalog.Misconfigurations = filterConfigFindings(catalog.Misconfigurations, input.ChangedPaths)
	}
	catalog.Summary.IaCArtifactCount = len(catalog.IaCArtifacts)
	catalog.Summary.MisconfigurationCount = len(catalog.Misconfigurations)

	report := &AnalysisReport{
		Analyzer:              analyzerName(a.ConfigScanner != nil),
		Catalog:               catalog,
		IaCArtifactCount:      len(catalog.IaCArtifacts),
		MisconfigurationCount: len(catalog.Misconfigurations),
		IncrementalBaseCommit: strings.TrimSpace(input.SinceCommit),
		ChangedPaths:          cloneStringSlice(input.ChangedPaths),
		Metadata: map[string]any{
			"repository":         input.Descriptor.Repository,
			"commit_sha":         input.Descriptor.CommitSHA,
			"since_commit":       strings.TrimSpace(input.SinceCommit),
			"changed_file_count": len(input.ChangedPaths),
		},
	}
	return report, nil
}

func analyzerName(usingConfigScanner bool) string {
	if usingConfigScanner {
		return "iac_trivy"
	}
	return "filesystem"
}

func (a FilesystemAnalyzer) scanConfigMisconfigurations(ctx context.Context, input AnalysisInput, artifacts []filesystemanalyzer.IaCArtifact) ([]filesystemanalyzer.ConfigFinding, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	result, err := a.ConfigScanner.ScanConfig(ctx, input.Checkout.Path)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	artifactByPath := make(map[string]filesystemanalyzer.IaCArtifact, len(artifacts))
	for _, artifact := range artifacts {
		artifactByPath[normalizeRepoPath(artifact.Path)] = artifact
	}
	findings := make([]filesystemanalyzer.ConfigFinding, 0)
	for _, target := range result.Results {
		path := normalizeScanTargetPath(input.Checkout.Path, target.Path)
		artifact, ok := artifactByPath[path]
		if !ok {
			continue
		}
		for _, finding := range target.Findings {
			findings = append(findings, filesystemanalyzer.ConfigFinding{
				ID:           normalizeConfigFindingID(path, finding),
				Type:         firstNonEmpty(strings.TrimSpace(finding.Type), "misconfiguration"),
				Severity:     strings.ToLower(strings.TrimSpace(finding.Severity)),
				Path:         path,
				Line:         finding.StartLine,
				EndLine:      finding.EndLine,
				Title:        strings.TrimSpace(finding.Title),
				Description:  strings.TrimSpace(finding.Description),
				Remediation:  strings.TrimSpace(finding.Remediation),
				ResourceType: firstNonEmpty(strings.TrimSpace(finding.Resource), strings.TrimSpace(artifact.ResourceType)),
				ArtifactType: strings.TrimSpace(artifact.Type),
				Format:       firstNonEmpty(strings.TrimSpace(finding.Format), strings.TrimSpace(artifact.Format)),
			})
		}
	}
	slices.SortStableFunc(findings, func(left, right filesystemanalyzer.ConfigFinding) int {
		return strings.Compare(left.Path+":"+left.ID, right.Path+":"+right.ID)
	})
	return findings, nil
}

func filterIaCArtifacts(artifacts []filesystemanalyzer.IaCArtifact, changedPaths []string) []filesystemanalyzer.IaCArtifact {
	if len(changedPaths) == 0 {
		return append([]filesystemanalyzer.IaCArtifact(nil), artifacts...)
	}
	allowed := make(map[string]struct{}, len(changedPaths))
	for _, path := range changedPaths {
		allowed[normalizeRepoPath(path)] = struct{}{}
	}
	filtered := make([]filesystemanalyzer.IaCArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		if _, ok := allowed[normalizeRepoPath(artifact.Path)]; ok {
			filtered = append(filtered, artifact)
		}
	}
	return filtered
}

func filterConfigFindings(findings []filesystemanalyzer.ConfigFinding, changedPaths []string) []filesystemanalyzer.ConfigFinding {
	if len(changedPaths) == 0 {
		return append([]filesystemanalyzer.ConfigFinding(nil), findings...)
	}
	allowed := make(map[string]struct{}, len(changedPaths))
	for _, path := range changedPaths {
		allowed[normalizeRepoPath(path)] = struct{}{}
	}
	filtered := make([]filesystemanalyzer.ConfigFinding, 0, len(findings))
	for _, finding := range findings {
		if _, ok := allowed[normalizeRepoPath(finding.Path)]; ok {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func normalizeScanTargetPath(rootPath, rawPath string) string {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return ""
	}
	trimmed = filepath.ToSlash(trimmed)
	rootPath = filepath.Clean(strings.TrimSpace(rootPath))
	if filepath.IsAbs(trimmed) {
		if rel, err := filepath.Rel(rootPath, trimmed); err == nil {
			trimmed = rel
		}
	}
	return normalizeRepoPath(trimmed)
}

func normalizeRepoPath(path string) string {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(cleaned))
}

func normalizeConfigFindingID(path string, finding scanner.ConfigScanFinding) string {
	parts := []string{
		normalizeRepoPath(path),
		strings.TrimSpace(finding.ID),
		strings.TrimSpace(finding.Title),
		fmt.Sprintf("%d", finding.StartLine),
	}
	return strings.Join(parts, ":")
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
