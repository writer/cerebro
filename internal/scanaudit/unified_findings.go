package scanaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/functionscan"
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/reposcan"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/workloadscan"
)

const defaultUnifiedFindingListLimit = 50

type UnifiedFindingListOptions struct {
	Namespaces []string
	Severities []string
	Kinds      []string
	Limit      int
	Offset     int
}

type UnifiedFinding struct {
	ID              string                     `json:"id"`
	AssetKey        string                     `json:"asset_key"`
	Kind            string                     `json:"kind"`
	Severity        string                     `json:"severity"`
	Title           string                     `json:"title"`
	Description     string                     `json:"description,omitempty"`
	CVE             string                     `json:"cve,omitempty"`
	Package         string                     `json:"package,omitempty"`
	FixedVersion    string                     `json:"fixed_version,omitempty"`
	Namespaces      []string                   `json:"namespaces,omitempty"`
	ScanKinds       []string                   `json:"scan_kinds,omitempty"`
	DetectionKinds  []string                   `json:"detection_kinds,omitempty"`
	Targets         []string                   `json:"targets,omitempty"`
	OccurrenceCount int                        `json:"occurrence_count"`
	FirstSeen       time.Time                  `json:"first_seen"`
	LastSeen        time.Time                  `json:"last_seen"`
	Occurrences     []UnifiedFindingOccurrence `json:"occurrences,omitempty"`
}

type UnifiedFindingOccurrence struct {
	Namespace        string    `json:"namespace"`
	RunID            string    `json:"run_id"`
	ScanKind         string    `json:"scan_kind"`
	DetectionKind    string    `json:"detection_kind"`
	Target           string    `json:"target,omitempty"`
	Severity         string    `json:"severity"`
	ObservedAt       time.Time `json:"observed_at"`
	CVE              string    `json:"cve,omitempty"`
	Package          string    `json:"package,omitempty"`
	InstalledVersion string    `json:"installed_version,omitempty"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	Path             string    `json:"path,omitempty"`
	ResourceType     string    `json:"resource_type,omitempty"`
	ArtifactType     string    `json:"artifact_type,omitempty"`
	Title            string    `json:"title,omitempty"`
	Description      string    `json:"description,omitempty"`
}

type unifiedFindingAggregate struct {
	finding          UnifiedFinding
	namespaceSet     map[string]struct{}
	scanKindSet      map[string]struct{}
	detectionKindSet map[string]struct{}
	targetSet        map[string]struct{}
	occurrenceKeySet map[string]struct{}
}

type normalizedFinding struct {
	assetKey    string
	issueKey    string
	kind        string
	severity    string
	title       string
	description string
	cve         string
	pkg         string
	fixed       string
	occurrence  UnifiedFindingOccurrence
}

func (s Service) ListUnifiedFindings(ctx context.Context, opts UnifiedFindingListOptions) ([]UnifiedFinding, error) {
	if s.store == nil {
		return nil, nil
	}
	namespaces, err := normalizeNamespaces(opts.Namespaces)
	if err != nil {
		return nil, err
	}
	severities := normalizeFindingFilterValues(opts.Severities)
	kinds := normalizeFindingFilterValues(opts.Kinds)

	envs, err := s.store.ListAllRuns(ctx, executionstore.RunListOptions{
		Namespaces:         namespaces,
		Statuses:           []string{"succeeded"},
		OrderBySubmittedAt: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list unified scan findings: %w", err)
	}

	aggregates := make(map[string]*unifiedFindingAggregate)
	for _, env := range envs {
		findings, err := s.extractUnifiedFindings(env)
		if err != nil {
			return nil, err
		}
		for _, item := range findings {
			if len(kinds) > 0 && !containsNormalizedValue(kinds, item.kind) {
				continue
			}
			if len(severities) > 0 && !containsNormalizedValue(severities, item.severity) {
				continue
			}
			groupKey := item.assetKey + "|" + item.issueKey
			aggregate, ok := aggregates[groupKey]
			if !ok {
				aggregate = &unifiedFindingAggregate{
					finding: UnifiedFinding{
						ID:           groupKey,
						AssetKey:     item.assetKey,
						Kind:         item.kind,
						Severity:     item.severity,
						Title:        item.title,
						Description:  item.description,
						CVE:          item.cve,
						Package:      item.pkg,
						FixedVersion: item.fixed,
						FirstSeen:    item.occurrence.ObservedAt.UTC(),
						LastSeen:     item.occurrence.ObservedAt.UTC(),
						Occurrences:  make([]UnifiedFindingOccurrence, 0, 1),
					},
					namespaceSet:     make(map[string]struct{}),
					scanKindSet:      make(map[string]struct{}),
					detectionKindSet: make(map[string]struct{}),
					targetSet:        make(map[string]struct{}),
					occurrenceKeySet: make(map[string]struct{}),
				}
				aggregates[groupKey] = aggregate
			}
			aggregate.add(item)
		}
	}

	items := make([]UnifiedFinding, 0, len(aggregates))
	for _, aggregate := range aggregates {
		aggregate.finalize()
		items = append(items, aggregate.finding)
	}
	sort.Slice(items, func(i, j int) bool {
		leftSeverity := findingSeverityRank(items[i].Severity)
		rightSeverity := findingSeverityRank(items[j].Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}
		if !items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].LastSeen.After(items[j].LastSeen)
		}
		if items[i].AssetKey != items[j].AssetKey {
			return items[i].AssetKey < items[j].AssetKey
		}
		return items[i].ID < items[j].ID
	})

	offset := max(opts.Offset, 0)
	if offset >= len(items) {
		return []UnifiedFinding{}, nil
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultUnifiedFindingListLimit
	}
	end := min(offset+limit, len(items))
	return append([]UnifiedFinding(nil), items[offset:end]...), nil
}

func (s Service) extractUnifiedFindings(env executionstore.RunEnvelope) ([]normalizedFinding, error) {
	switch env.Namespace {
	case executionstore.NamespaceImageScan:
		var run imagescan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode image scan correlation record %q: %w", env.RunID, err)
		}
		return unifiedFindingsFromImageRun(env.Namespace, run), nil
	case executionstore.NamespaceFunctionScan:
		var run functionscan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode function scan correlation record %q: %w", env.RunID, err)
		}
		return unifiedFindingsFromFunctionRun(env.Namespace, run), nil
	case executionstore.NamespaceWorkloadScan:
		var run workloadscan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode workload scan correlation record %q: %w", env.RunID, err)
		}
		return unifiedFindingsFromWorkloadRun(env.Namespace, run), nil
	case executionstore.NamespaceRepoScan:
		var run reposcan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode repo scan correlation record %q: %w", env.RunID, err)
		}
		return unifiedFindingsFromRepoRun(env.Namespace, run), nil
	default:
		return nil, nil
	}
}

func unifiedFindingsFromImageRun(namespace string, run imagescan.RunRecord) []normalizedFinding {
	if run.Analysis == nil {
		return nil
	}
	assetKey := normalizeAssetKey(firstNonEmpty(
		run.Metadata["correlation_id"],
		run.Metadata["repository"],
		run.Metadata["repo"],
		run.Target.Repository,
	))
	target := run.Target.Reference()
	observedAt := observedAt(run.SubmittedAt, run.UpdatedAt, run.CompletedAt)
	items := make([]normalizedFinding, 0)
	for _, vuln := range run.Analysis.Result.Vulnerabilities {
		if item, ok := vulnerabilityFinding(assetKey, namespace, run.ID, "image", "image_native", target, observedAt, vuln); ok {
			items = append(items, item)
		}
	}
	items = append(items, unifiedFindingsFromCatalog(assetKey, namespace, run.ID, "image", target, observedAt, run.Analysis.Catalog)...)
	return items
}

func unifiedFindingsFromFunctionRun(namespace string, run functionscan.RunRecord) []normalizedFinding {
	if run.Analysis == nil {
		return nil
	}
	assetKey := normalizeAssetKey(firstNonEmpty(
		run.Metadata["correlation_id"],
		run.Metadata["repository"],
		run.Metadata["repo"],
		run.Target.Identity(),
	))
	target := run.Target.Identity()
	observedAt := observedAt(run.SubmittedAt, run.UpdatedAt, run.CompletedAt)
	items := make([]normalizedFinding, 0)
	for _, vuln := range run.Analysis.Result.Vulnerabilities {
		if item, ok := vulnerabilityFinding(assetKey, namespace, run.ID, "function", "filesystem", target, observedAt, vuln); ok {
			items = append(items, item)
		}
	}
	items = append(items, unifiedFindingsFromCatalog(assetKey, namespace, run.ID, "function", target, observedAt, run.Analysis.Catalog)...)
	return items
}

func unifiedFindingsFromWorkloadRun(namespace string, run workloadscan.RunRecord) []normalizedFinding {
	assetKey := normalizeAssetKey(firstNonEmpty(
		run.Metadata["correlation_id"],
		run.Metadata["repository"],
		run.Metadata["repo"],
		run.Target.Identity(),
	))
	target := run.Target.Identity()
	observedAt := observedAt(run.SubmittedAt, run.UpdatedAt, run.CompletedAt)
	items := make([]normalizedFinding, 0)
	for _, volume := range run.Volumes {
		if volume.Analysis == nil {
			continue
		}
		items = append(items, unifiedFindingsFromCatalog(assetKey, namespace, run.ID, "workload", target, observedAt, volume.Analysis.Catalog)...)
	}
	return items
}

func unifiedFindingsFromRepoRun(namespace string, run reposcan.RunRecord) []normalizedFinding {
	if run.Analysis == nil {
		return nil
	}
	assetKey := normalizeAssetKey(firstNonEmpty(
		run.Metadata["correlation_id"],
		run.Metadata["repository"],
		run.Metadata["repo"],
		func() string {
			if run.Descriptor != nil {
				return run.Descriptor.Repository
			}
			return ""
		}(),
		run.Target.Repository,
		run.Target.RepoURL,
	))
	target := firstNonEmpty(
		func() string {
			if run.Descriptor != nil {
				return run.Descriptor.Repository
			}
			return ""
		}(),
		run.Target.Identity(),
	)
	observedAt := observedAt(run.SubmittedAt, run.UpdatedAt, run.CompletedAt)
	return unifiedFindingsFromCatalog(assetKey, namespace, run.ID, "repo", target, observedAt, run.Analysis.Catalog)
}

func unifiedFindingsFromCatalog(assetKey, namespace, runID, scanKind, target string, observedAt time.Time, catalog *filesystemanalyzer.Report) []normalizedFinding {
	if catalog == nil {
		return nil
	}
	items := make([]normalizedFinding, 0, len(catalog.Vulnerabilities)+len(catalog.Misconfigurations))
	for _, vuln := range catalog.Vulnerabilities {
		if item, ok := vulnerabilityFinding(assetKey, namespace, runID, scanKind, "filesystem", target, observedAt, vuln); ok {
			items = append(items, item)
		}
	}
	for _, finding := range catalog.Misconfigurations {
		if item, ok := misconfigurationFinding(assetKey, namespace, runID, scanKind, target, observedAt, finding); ok {
			items = append(items, item)
		}
	}
	return items
}

func vulnerabilityFinding(assetKey, namespace, runID, scanKind, detectionKind, target string, observedAt time.Time, vuln scanner.ImageVulnerability) (normalizedFinding, bool) {
	assetKey = normalizeAssetKey(assetKey)
	issueKey := issueKeyForVulnerability(vuln)
	if assetKey == "" || issueKey == "" {
		return normalizedFinding{}, false
	}
	title := firstNonEmpty(strings.TrimSpace(vuln.CVE), strings.TrimSpace(vuln.ID), strings.TrimSpace(vuln.Package), "vulnerability")
	description := strings.TrimSpace(vuln.Description)
	return normalizedFinding{
		assetKey:    assetKey,
		issueKey:    issueKey,
		kind:        "vulnerability",
		severity:    strings.ToLower(strings.TrimSpace(vuln.Severity)),
		title:       title,
		description: description,
		cve:         strings.TrimSpace(vuln.CVE),
		pkg:         strings.TrimSpace(vuln.Package),
		fixed:       strings.TrimSpace(vuln.FixedVersion),
		occurrence: UnifiedFindingOccurrence{
			Namespace:        namespace,
			RunID:            strings.TrimSpace(runID),
			ScanKind:         scanKind,
			DetectionKind:    detectionKind,
			Target:           strings.TrimSpace(target),
			Severity:         strings.ToLower(strings.TrimSpace(vuln.Severity)),
			ObservedAt:       observedAt.UTC(),
			CVE:              strings.TrimSpace(vuln.CVE),
			Package:          strings.TrimSpace(vuln.Package),
			InstalledVersion: strings.TrimSpace(vuln.InstalledVersion),
			FixedVersion:     strings.TrimSpace(vuln.FixedVersion),
			Title:            title,
			Description:      description,
		},
	}, true
}

func misconfigurationFinding(assetKey, namespace, runID, scanKind, target string, observedAt time.Time, finding filesystemanalyzer.ConfigFinding) (normalizedFinding, bool) {
	assetKey = normalizeAssetKey(assetKey)
	issueKey := issueKeyForMisconfiguration(finding)
	if assetKey == "" || issueKey == "" {
		return normalizedFinding{}, false
	}
	detectionKind := "filesystem"
	if strings.TrimSpace(finding.ArtifactType) != "" || strings.TrimSpace(finding.ResourceType) != "" {
		detectionKind = "iac"
	}
	return normalizedFinding{
		assetKey:    assetKey,
		issueKey:    issueKey,
		kind:        "misconfiguration",
		severity:    strings.ToLower(strings.TrimSpace(finding.Severity)),
		title:       strings.TrimSpace(finding.Title),
		description: strings.TrimSpace(finding.Description),
		occurrence: UnifiedFindingOccurrence{
			Namespace:     namespace,
			RunID:         strings.TrimSpace(runID),
			ScanKind:      scanKind,
			DetectionKind: detectionKind,
			Target:        strings.TrimSpace(target),
			Severity:      strings.ToLower(strings.TrimSpace(finding.Severity)),
			ObservedAt:    observedAt.UTC(),
			Path:          strings.TrimSpace(finding.Path),
			ResourceType:  strings.TrimSpace(finding.ResourceType),
			ArtifactType:  strings.TrimSpace(finding.ArtifactType),
			Title:         strings.TrimSpace(finding.Title),
			Description:   strings.TrimSpace(finding.Description),
		},
	}, true
}

func (a *unifiedFindingAggregate) add(item normalizedFinding) {
	if a == nil {
		return
	}
	if findingSeverityRank(item.severity) > findingSeverityRank(a.finding.Severity) {
		a.finding.Severity = item.severity
	}
	if a.finding.Title == "" {
		a.finding.Title = item.title
	}
	if a.finding.Description == "" {
		a.finding.Description = item.description
	}
	if a.finding.CVE == "" {
		a.finding.CVE = item.cve
	}
	if a.finding.Package == "" {
		a.finding.Package = item.pkg
	}
	if a.finding.FixedVersion == "" {
		a.finding.FixedVersion = item.fixed
	}
	if item.occurrence.ObservedAt.Before(a.finding.FirstSeen) {
		a.finding.FirstSeen = item.occurrence.ObservedAt.UTC()
	}
	if item.occurrence.ObservedAt.After(a.finding.LastSeen) {
		a.finding.LastSeen = item.occurrence.ObservedAt.UTC()
	}

	addFindingString(a.namespaceSet, &a.finding.Namespaces, item.occurrence.Namespace)
	addFindingString(a.scanKindSet, &a.finding.ScanKinds, item.occurrence.ScanKind)
	addFindingString(a.detectionKindSet, &a.finding.DetectionKinds, item.occurrence.DetectionKind)
	addFindingString(a.targetSet, &a.finding.Targets, item.occurrence.Target)

	occurrenceKey := strings.Join([]string{
		item.occurrence.Namespace,
		item.occurrence.RunID,
		item.occurrence.ScanKind,
		item.occurrence.DetectionKind,
		item.occurrence.Target,
		item.occurrence.CVE,
		item.occurrence.Package,
		item.occurrence.InstalledVersion,
		item.occurrence.Path,
		item.occurrence.Title,
	}, "|")
	if _, ok := a.occurrenceKeySet[occurrenceKey]; ok {
		return
	}
	a.occurrenceKeySet[occurrenceKey] = struct{}{}
	a.finding.Occurrences = append(a.finding.Occurrences, item.occurrence)
	a.finding.OccurrenceCount++
}

func (a *unifiedFindingAggregate) finalize() {
	if a == nil {
		return
	}
	sort.Strings(a.finding.Namespaces)
	sort.Strings(a.finding.ScanKinds)
	sort.Strings(a.finding.DetectionKinds)
	sort.Strings(a.finding.Targets)
	sort.Slice(a.finding.Occurrences, func(i, j int) bool {
		if !a.finding.Occurrences[i].ObservedAt.Equal(a.finding.Occurrences[j].ObservedAt) {
			return a.finding.Occurrences[i].ObservedAt.Before(a.finding.Occurrences[j].ObservedAt)
		}
		if a.finding.Occurrences[i].Namespace != a.finding.Occurrences[j].Namespace {
			return a.finding.Occurrences[i].Namespace < a.finding.Occurrences[j].Namespace
		}
		return a.finding.Occurrences[i].RunID < a.finding.Occurrences[j].RunID
	})
}

func addFindingString(seen map[string]struct{}, dest *[]string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if _, ok := seen[value]; ok {
		return
	}
	seen[value] = struct{}{}
	*dest = append(*dest, value)
}

func issueKeyForVulnerability(vuln scanner.ImageVulnerability) string {
	cveOrID := normalizeFindingToken(firstNonEmpty(vuln.CVE, vuln.ID))
	pkg := normalizeFindingToken(vuln.Package)
	if cveOrID == "" && pkg == "" {
		return ""
	}
	return strings.Join([]string{"vulnerability", cveOrID, pkg}, "|")
}

func issueKeyForMisconfiguration(finding filesystemanalyzer.ConfigFinding) string {
	parts := []string{
		"misconfiguration",
		normalizeFindingToken(finding.Type),
		normalizeFindingToken(finding.ResourceType),
		normalizeFindingToken(finding.ArtifactType),
		normalizeFindingToken(finding.Title),
	}
	if strings.Trim(strings.Join(parts[1:], ""), "|") == "" {
		return ""
	}
	return strings.Join(parts, "|")
}

func normalizeFindingFilterValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func containsNormalizedValue(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func normalizeAssetKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "\\", "/")
	if parsed, err := url.Parse(raw); err == nil && strings.TrimSpace(parsed.Path) != "" && (parsed.Scheme != "" || parsed.Host != "") {
		raw = parsed.Path
	}
	raw = strings.TrimSpace(strings.Trim(raw, "/"))
	raw = strings.TrimSuffix(raw, ".git")
	if raw == "" {
		return ""
	}
	parts := make([]string, 0)
	for _, part := range strings.Split(strings.ToLower(raw), "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "/")
}

func normalizeFindingToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if lastDash {
				continue
			}
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func findingSeverityRank(raw string) int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func observedAt(submittedAt, updatedAt time.Time, completedAt *time.Time) time.Time {
	switch {
	case completedAt != nil && !completedAt.IsZero():
		return completedAt.UTC()
	case !updatedAt.IsZero():
		return updatedAt.UTC()
	default:
		return submittedAt.UTC()
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
