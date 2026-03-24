package scanaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/functionscan"
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/repohistoryscan"
	"github.com/writer/cerebro/internal/reposcan"
	"github.com/writer/cerebro/internal/sbom"
	"github.com/writer/cerebro/internal/workloadscan"
)

var (
	ErrUnsupportedNamespace = errors.New("unsupported scan audit namespace")
	ErrRecordNotFound       = errors.New("scan audit record not found")
)

const (
	defaultListLimit      = 50
	retentionStorageClass = "execution_store"
	retentionTierAudit    = "audit"
)

type Service struct {
	store         executionstore.Store
	retentionDays int
	now           func() time.Time
}

type genericEvent struct {
	Sequence   int64          `json:"sequence"`
	Status     string         `json:"status"`
	Stage      string         `json:"stage"`
	Message    string         `json:"message,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	RecordedAt time.Time      `json:"recorded_at"`
}

var supportedNamespaces = []string{
	executionstore.NamespaceWorkloadScan,
	executionstore.NamespaceImageScan,
	executionstore.NamespaceFunctionScan,
	executionstore.NamespaceRepoScan,
	executionstore.NamespaceRepoHistoryScan,
}

func NewService(store executionstore.Store, cfg Config) Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return Service{
		store:         store,
		retentionDays: max(cfg.RetentionDays, 0),
		now:           now,
	}
}

func SupportedNamespaces() []string {
	return append([]string(nil), supportedNamespaces...)
}

func IsSupportedNamespace(namespace string) bool {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	for _, candidate := range supportedNamespaces {
		if namespace == candidate {
			return true
		}
	}
	return false
}

func (s Service) ListRecords(ctx context.Context, opts ListOptions) ([]Record, error) {
	if s.store == nil {
		return nil, nil
	}
	namespaces, err := normalizeNamespaces(opts.Namespaces)
	if err != nil {
		return nil, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	envs, err := s.store.ListAllRuns(ctx, executionstore.RunListOptions{
		Namespaces:         namespaces,
		Statuses:           cloneStrings(opts.Statuses),
		ExcludeStatuses:    cloneStrings(opts.ExcludeStatuses),
		Limit:              limit,
		Offset:             opts.Offset,
		OrderBySubmittedAt: opts.OrderBySubmittedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("list scan audit records: %w", err)
	}
	records := make([]Record, 0, len(envs))
	for _, env := range envs {
		record, err := s.buildRecord(ctx, env, false)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if opts.OrderBySubmittedAt {
			if records[i].SubmittedAt.Equal(records[j].SubmittedAt) {
				return records[i].RunID > records[j].RunID
			}
			return records[i].SubmittedAt.After(records[j].SubmittedAt)
		}
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			return records[i].RunID > records[j].RunID
		}
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	return records, nil
}

func (s Service) GetRecord(ctx context.Context, namespace, runID string) (*Record, bool, error) {
	if s.store == nil {
		return nil, false, nil
	}
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	runID = strings.TrimSpace(runID)
	if !IsSupportedNamespace(namespace) {
		return nil, false, fmt.Errorf("%w: %s", ErrUnsupportedNamespace, namespace)
	}
	if runID == "" {
		return nil, false, nil
	}
	env, err := s.store.LoadRun(ctx, namespace, runID)
	if err != nil {
		return nil, false, fmt.Errorf("load scan audit record %s/%s: %w", namespace, runID, err)
	}
	if env == nil {
		return nil, false, nil
	}
	record, err := s.buildRecord(ctx, *env, true)
	if err != nil {
		return nil, false, err
	}
	return &record, true, nil
}

func (s Service) ExportRecord(ctx context.Context, namespace, runID string) (*ExportPackage, error) {
	if s.store == nil {
		return nil, ErrRecordNotFound
	}
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	runID = strings.TrimSpace(runID)
	if !IsSupportedNamespace(namespace) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedNamespace, namespace)
	}
	env, err := s.store.LoadRun(ctx, namespace, runID)
	if err != nil {
		return nil, fmt.Errorf("load scan audit record %s/%s: %w", namespace, runID, err)
	}
	if env == nil {
		return nil, ErrRecordNotFound
	}
	record, err := s.buildRecord(ctx, *env, true)
	if err != nil {
		return nil, err
	}
	pkg := BuildExportPackage(record, s.now().UTC())
	pkg.SBOMs, err = buildSBOMArtifacts(*env, record)
	if err != nil {
		return nil, err
	}
	return &pkg, nil
}

func buildSBOMArtifacts(env executionstore.RunEnvelope, record Record) ([]SBOMArtifact, error) {
	documents, err := extractSBOMDocuments(env)
	if err != nil {
		return nil, err
	}
	if len(documents) == 0 {
		return nil, nil
	}
	merged := sbom.Merge(documents...)
	if len(merged.Components) == 0 && len(merged.Dependencies) == 0 {
		return nil, nil
	}
	source := sbom.SourceDescriptor{
		Name:        firstNonEmpty(record.Kind, record.Target, env.RunID),
		Namespace:   env.Namespace,
		RunID:       env.RunID,
		Target:      record.Target,
		GeneratedAt: merged.GeneratedAt,
	}
	formats := []struct {
		name     string
		filename string
	}{
		{name: sbom.FormatCycloneDXJSON, filename: "sbom.cyclonedx.json"},
		{name: sbom.FormatSPDXJSON, filename: "sbom.spdx.json"},
	}
	artifacts := make([]SBOMArtifact, 0, len(formats))
	for _, format := range formats {
		payload, contentType, err := sbom.Render(format.name, source, merged)
		if err != nil {
			return nil, fmt.Errorf("render %s for %s/%s: %w", format.name, env.Namespace, env.RunID, err)
		}
		artifacts = append(artifacts, SBOMArtifact{
			Format:      format.name,
			Filename:    format.filename,
			ContentType: contentType,
			Document:    append(json.RawMessage(nil), payload...),
		})
	}
	return artifacts, nil
}

func extractSBOMDocuments(env executionstore.RunEnvelope) ([]filesystemanalyzer.SBOMDocument, error) {
	switch env.Namespace {
	case executionstore.NamespaceImageScan:
		var run imagescan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode image scan export record %q: %w", env.RunID, err)
		}
		return catalogSBOMDocuments(func() *filesystemanalyzer.Report {
			if run.Analysis == nil {
				return nil
			}
			return run.Analysis.Catalog
		}()), nil
	case executionstore.NamespaceRepoScan:
		var run reposcan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode repo scan export record %q: %w", env.RunID, err)
		}
		return catalogSBOMDocuments(func() *filesystemanalyzer.Report {
			if run.Analysis == nil {
				return nil
			}
			return run.Analysis.Catalog
		}()), nil
	case executionstore.NamespaceFunctionScan:
		var run functionscan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode function scan export record %q: %w", env.RunID, err)
		}
		return catalogSBOMDocuments(func() *filesystemanalyzer.Report {
			if run.Analysis == nil {
				return nil
			}
			return run.Analysis.Catalog
		}()), nil
	case executionstore.NamespaceWorkloadScan:
		var run workloadscan.RunRecord
		if err := json.Unmarshal(env.Payload, &run); err != nil {
			return nil, fmt.Errorf("decode workload scan export record %q: %w", env.RunID, err)
		}
		docs := make([]filesystemanalyzer.SBOMDocument, 0, len(run.Volumes))
		for _, volume := range run.Volumes {
			if volume.Analysis == nil || volume.Analysis.Catalog == nil {
				continue
			}
			docs = append(docs, catalogSBOMDocuments(volume.Analysis.Catalog)...)
		}
		return docs, nil
	default:
		return nil, nil
	}
}

func catalogSBOMDocuments(catalog *filesystemanalyzer.Report) []filesystemanalyzer.SBOMDocument {
	if catalog == nil {
		return nil
	}
	if strings.TrimSpace(catalog.SBOM.Format) == "" && len(catalog.SBOM.Components) == 0 && len(catalog.SBOM.Dependencies) == 0 {
		return nil
	}
	return []filesystemanalyzer.SBOMDocument{catalog.SBOM}
}

func (s Service) buildRecord(ctx context.Context, env executionstore.RunEnvelope, includeEvents bool) (Record, error) {
	events, err := s.store.LoadEvents(ctx, env.Namespace, env.RunID)
	if err != nil {
		return Record{}, fmt.Errorf("load scan audit events %s/%s: %w", env.Namespace, env.RunID, err)
	}
	projectedEvents, err := projectEvents(events)
	if err != nil {
		return Record{}, err
	}
	switch env.Namespace {
	case executionstore.NamespaceWorkloadScan:
		return s.projectWorkloadRecord(env, projectedEvents, includeEvents)
	case executionstore.NamespaceImageScan:
		return s.projectImageRecord(env, projectedEvents, includeEvents)
	case executionstore.NamespaceFunctionScan:
		return s.projectFunctionRecord(env, projectedEvents, includeEvents)
	case executionstore.NamespaceRepoScan:
		return s.projectRepoRecord(env, projectedEvents, includeEvents)
	case executionstore.NamespaceRepoHistoryScan:
		return s.projectRepoHistoryRecord(env, projectedEvents, includeEvents)
	default:
		return Record{}, fmt.Errorf("%w: %s", ErrUnsupportedNamespace, env.Namespace)
	}
}

func (s Service) projectWorkloadRecord(env executionstore.RunEnvelope, events []Event, includeEvents bool) (Record, error) {
	var run workloadscan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Record{}, fmt.Errorf("decode workload scan audit record %q: %w", env.RunID, err)
	}
	artifacts, snapshotCount, retainedSnapshots, inspectionCount, retainedInspections := workloadArtifactRetention(run.Volumes)
	results := map[string]any{
		"volume_count":         len(run.Volumes),
		"succeeded_volumes":    run.Summary.SucceededVolumes,
		"failed_volumes":       run.Summary.FailedVolumes,
		"finding_count":        run.Summary.Findings,
		"snapshot_gib_hours":   run.Summary.SnapshotGiBHours,
		"volume_gib_hours":     run.Summary.VolumeGiBHours,
		"reconciled_volumes":   run.Summary.ReconciledVolumes,
		"snapshot_count":       snapshotCount,
		"retained_snapshots":   retainedSnapshots,
		"inspection_count":     inspectionCount,
		"retained_inspections": retainedInspections,
	}
	return recordFromRunEnvelope(
		env,
		run.RequestedBy,
		string(run.Provider),
		run.Target.Identity(),
		map[string]any{
			"target":                   run.Target,
			"scanner_host":             run.ScannerHost,
			"dry_run":                  run.DryRun,
			"max_concurrent_snapshots": run.MaxConcurrentSnapshots,
			"metadata":                 cloneStringMap(run.Metadata),
			"priority":                 run.Priority,
		},
		results,
		sanitizeMessage(run.Error),
		artifacts,
		events,
		includeEvents,
		s.retentionDays,
	)
}

func (s Service) projectImageRecord(env executionstore.RunEnvelope, events []Event, includeEvents bool) (Record, error) {
	var run imagescan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Record{}, fmt.Errorf("decode image scan audit record %q: %w", env.RunID, err)
	}
	results := map[string]any{
		"layer_count": len(run.Layers),
	}
	artifacts := make([]ArtifactRetention, 0, 1)
	if run.Manifest != nil {
		results["manifest_digest"] = strings.TrimSpace(run.Manifest.Digest)
		results["image_os"] = strings.TrimSpace(run.Manifest.Config.OS)
		results["image_architecture"] = strings.TrimSpace(run.Manifest.Config.Architecture)
	}
	if run.Filesystem != nil {
		results["filesystem_retained"] = run.Filesystem.Retained
		results["filesystem_file_count"] = run.Filesystem.FileCount
		results["filesystem_byte_size"] = run.Filesystem.ByteSize
		artifacts = append(artifacts, ArtifactRetention{
			Type:     "filesystem",
			Count:    1,
			Retained: run.Filesystem.Retained,
		})
	}
	if run.Analysis != nil {
		results["analyzer"] = strings.TrimSpace(run.Analysis.Analyzer)
		results["native_vulnerability_count"] = run.Analysis.NativeVulnerabilityCount
		results["filesystem_vulnerability_count"] = run.Analysis.FilesystemVulnerabilityCount
		results["vulnerability_summary"] = run.Analysis.Result.Summary
		if summary := catalogSummary(run.Analysis.Catalog); len(summary) > 0 {
			results["catalog_summary"] = summary
		}
	}
	return recordFromRunEnvelope(
		env,
		run.RequestedBy,
		string(run.Registry),
		run.Target.Reference(),
		map[string]any{
			"target":          run.Target,
			"dry_run":         run.DryRun,
			"keep_filesystem": run.KeepFilesystem,
			"metadata":        cloneStringMap(run.Metadata),
		},
		results,
		sanitizeMessage(run.Error),
		artifacts,
		events,
		includeEvents,
		s.retentionDays,
	)
}

func (s Service) projectFunctionRecord(env executionstore.RunEnvelope, events []Event, includeEvents bool) (Record, error) {
	var run functionscan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Record{}, fmt.Errorf("decode function scan audit record %q: %w", env.RunID, err)
	}
	results := map[string]any{
		"applied_artifact_count": len(run.AppliedArtifacts),
	}
	artifacts := make([]ArtifactRetention, 0, 1)
	if run.Descriptor != nil {
		results["runtime"] = strings.TrimSpace(run.Descriptor.Runtime)
		results["package_type"] = strings.TrimSpace(run.Descriptor.PackageType)
		results["architecture_count"] = len(run.Descriptor.Architectures)
	}
	if run.Filesystem != nil {
		results["filesystem_retained"] = run.Filesystem.Retained
		results["filesystem_file_count"] = run.Filesystem.FileCount
		results["filesystem_byte_size"] = run.Filesystem.ByteSize
		artifacts = append(artifacts, ArtifactRetention{
			Type:     "filesystem",
			Count:    1,
			Retained: run.Filesystem.Retained,
		})
	}
	if run.Analysis != nil {
		results["analyzer"] = strings.TrimSpace(run.Analysis.Analyzer)
		results["filesystem_vulnerability_count"] = run.Analysis.FilesystemVulnerabilityCount
		results["environment_secret_count"] = run.Analysis.EnvironmentSecretCount
		results["code_secret_count"] = run.Analysis.CodeSecretCount
		results["runtime_deprecated"] = run.Analysis.RuntimeDeprecated
		results["vulnerability_summary"] = run.Analysis.Result.Summary
		if summary := catalogSummary(run.Analysis.Catalog); len(summary) > 0 {
			results["catalog_summary"] = summary
		}
	}
	return recordFromRunEnvelope(
		env,
		run.RequestedBy,
		string(run.Provider),
		run.Target.Identity(),
		map[string]any{
			"target":          run.Target,
			"dry_run":         run.DryRun,
			"keep_filesystem": run.KeepFilesystem,
			"metadata":        cloneStringMap(run.Metadata),
		},
		results,
		sanitizeMessage(run.Error),
		artifacts,
		events,
		includeEvents,
		s.retentionDays,
	)
}

func (s Service) projectRepoRecord(env executionstore.RunEnvelope, events []Event, includeEvents bool) (Record, error) {
	var run reposcan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Record{}, fmt.Errorf("decode repo scan audit record %q: %w", env.RunID, err)
	}
	results := map[string]any{}
	artifacts := make([]ArtifactRetention, 0, 1)
	if run.Descriptor != nil {
		results["requested_ref"] = strings.TrimSpace(run.Descriptor.RequestedRef)
		results["resolved_ref"] = strings.TrimSpace(run.Descriptor.ResolvedRef)
		results["commit_sha"] = strings.TrimSpace(run.Descriptor.CommitSHA)
	}
	if run.Checkout != nil {
		results["checkout_retained"] = run.Checkout.Retained
		artifacts = append(artifacts, ArtifactRetention{
			Type:     "checkout",
			Count:    1,
			Retained: run.Checkout.Retained,
		})
	}
	if run.Analysis != nil {
		results["analyzer"] = strings.TrimSpace(run.Analysis.Analyzer)
		results["iac_artifact_count"] = run.Analysis.IaCArtifactCount
		results["misconfiguration_count"] = run.Analysis.MisconfigurationCount
		if summary := catalogSummary(run.Analysis.Catalog); len(summary) > 0 {
			results["catalog_summary"] = summary
		}
	}
	return recordFromRunEnvelope(
		env,
		run.RequestedBy,
		"",
		run.Target.Identity(),
		map[string]any{
			"target":        run.Target,
			"dry_run":       run.DryRun,
			"keep_checkout": run.KeepCheckout,
			"metadata":      cloneStringMap(run.Metadata),
		},
		results,
		sanitizeMessage(run.Error),
		artifacts,
		events,
		includeEvents,
		s.retentionDays,
	)
}

func (s Service) projectRepoHistoryRecord(env executionstore.RunEnvelope, events []Event, includeEvents bool) (Record, error) {
	var run repohistoryscan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Record{}, fmt.Errorf("decode repo history scan audit record %q: %w", env.RunID, err)
	}
	results := map[string]any{}
	artifacts := make([]ArtifactRetention, 0, 1)
	if run.Descriptor != nil {
		results["requested_ref"] = strings.TrimSpace(run.Descriptor.RequestedRef)
		results["resolved_ref"] = strings.TrimSpace(run.Descriptor.ResolvedRef)
		results["commit_sha"] = strings.TrimSpace(run.Descriptor.CommitSHA)
	}
	if run.Checkout != nil {
		results["checkout_retained"] = run.Checkout.Retained
		artifacts = append(artifacts, ArtifactRetention{
			Type:     "checkout",
			Count:    1,
			Retained: run.Checkout.Retained,
		})
	}
	if run.Analysis != nil {
		results["engine"] = strings.TrimSpace(run.Analysis.Engine)
		results["total_findings"] = run.Analysis.TotalFindings
		results["verified_findings"] = run.Analysis.VerifiedFindings
	}
	return recordFromRunEnvelope(
		env,
		run.RequestedBy,
		"",
		run.Target.Identity(),
		map[string]any{
			"target":        run.Target,
			"dry_run":       run.DryRun,
			"keep_checkout": run.KeepCheckout,
			"metadata":      cloneStringMap(run.Metadata),
		},
		results,
		sanitizeMessage(run.Error),
		artifacts,
		events,
		includeEvents,
		s.retentionDays,
	)
}

func recordFromRunEnvelope(env executionstore.RunEnvelope, requestedBy, provider, target string, configuration, results map[string]any, runError string, artifacts []ArtifactRetention, events []Event, includeEvents bool, retentionDays int) (Record, error) {
	record := Record{
		Namespace:     env.Namespace,
		RunID:         env.RunID,
		Kind:          strings.TrimSpace(env.Kind),
		Status:        strings.TrimSpace(env.Status),
		Stage:         strings.TrimSpace(env.Stage),
		SubmittedAt:   env.SubmittedAt.UTC(),
		StartedAt:     utcTimePtr(env.StartedAt),
		CompletedAt:   utcTimePtr(env.CompletedAt),
		UpdatedAt:     env.UpdatedAt.UTC(),
		RequestedBy:   strings.TrimSpace(requestedBy),
		Provider:      strings.TrimSpace(provider),
		Target:        strings.TrimSpace(target),
		Configuration: compactMap(configuration),
		Results:       compactMap(results),
		Exceptions:    buildExceptions(runError, exceptionTimestamp(env), strings.TrimSpace(env.Status), strings.TrimSpace(env.Stage), events),
		Retention:     buildRetention(env.SubmittedAt, retentionDays, artifacts),
	}
	if includeEvents {
		record.Events = append([]Event(nil), events...)
	}
	return record, nil
}

func projectEvents(envs []executionstore.EventEnvelope) ([]Event, error) {
	events := make([]Event, 0, len(envs))
	for _, env := range envs {
		var raw genericEvent
		if len(env.Payload) > 0 {
			if err := json.Unmarshal(env.Payload, &raw); err != nil {
				return nil, fmt.Errorf("decode scan audit event %s/%s#%d: %w", env.Namespace, env.RunID, env.Sequence, err)
			}
		}
		data, _ := sanitizeAny(raw.Data).(map[string]any)
		recordedAt := raw.RecordedAt
		if recordedAt.IsZero() {
			recordedAt = env.RecordedAt
		}
		events = append(events, Event{
			Sequence:   firstNonZero(raw.Sequence, env.Sequence),
			Status:     strings.TrimSpace(raw.Status),
			Stage:      strings.TrimSpace(raw.Stage),
			Message:    sanitizeMessage(raw.Message),
			Data:       data,
			RecordedAt: recordedAt.UTC(),
		})
	}
	return events, nil
}

func buildExceptions(runError string, recordedAt time.Time, status, stage string, events []Event) []Exception {
	exceptions := make([]Exception, 0, 1+len(events))
	seen := make(map[string]struct{})
	if message := sanitizeMessage(runError); message != "" {
		item := Exception{
			Source:     "run",
			Status:     status,
			Stage:      stage,
			Message:    message,
			RecordedAt: recordedAt.UTC(),
		}
		key := exceptionKey(item)
		seen[key] = struct{}{}
		exceptions = append(exceptions, item)
	}
	for _, event := range events {
		if !isExceptionEvent(event) {
			continue
		}
		item := Exception{
			Source:     "event",
			Status:     event.Status,
			Stage:      event.Stage,
			Message:    sanitizeMessage(event.Message),
			RecordedAt: event.RecordedAt.UTC(),
		}
		if item.Message == "" {
			continue
		}
		key := exceptionKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		exceptions = append(exceptions, item)
	}
	if len(exceptions) == 0 {
		return nil
	}
	return exceptions
}

func isExceptionEvent(event Event) bool {
	status := strings.ToLower(strings.TrimSpace(event.Status))
	stage := strings.ToLower(strings.TrimSpace(event.Stage))
	message := strings.ToLower(strings.TrimSpace(event.Message))
	return status == "failed" ||
		strings.HasSuffix(stage, "failed") ||
		strings.Contains(message, "failed") ||
		strings.Contains(message, "error")
}

func buildRetention(submittedAt time.Time, retentionDays int, artifacts []ArtifactRetention) RetentionPolicy {
	policy := RetentionPolicy{
		StorageClass:  retentionStorageClass,
		RetentionTier: retentionTierAudit,
	}
	if retentionDays > 0 {
		retainUntil := submittedAt.UTC().Add(time.Duration(retentionDays) * 24 * time.Hour)
		policy.RetentionDays = retentionDays
		policy.RetainUntil = &retainUntil
	}
	if len(artifacts) > 0 {
		policy.Artifacts = append([]ArtifactRetention(nil), artifacts...)
	}
	return policy
}

func workloadArtifactRetention(volumes []workloadscan.VolumeScanRecord) ([]ArtifactRetention, int, int, int, int) {
	snapshotCount := 0
	retainedSnapshots := 0
	inspectionCount := 0
	retainedInspections := 0
	for _, volume := range volumes {
		if volume.Snapshot != nil {
			snapshotCount++
			if volume.Snapshot.DeletedAt == nil {
				retainedSnapshots++
			}
		}
		if volume.Inspection != nil {
			inspectionCount++
			if volume.Inspection.DeletedAt == nil {
				retainedInspections++
			}
		}
	}
	artifacts := make([]ArtifactRetention, 0, 2)
	if snapshotCount > 0 {
		artifacts = append(artifacts, ArtifactRetention{
			Type:     "snapshot",
			Count:    snapshotCount,
			Retained: retainedSnapshots > 0,
		})
	}
	if inspectionCount > 0 {
		artifacts = append(artifacts, ArtifactRetention{
			Type:     "inspection_volume",
			Count:    inspectionCount,
			Retained: retainedInspections > 0,
		})
	}
	return artifacts, snapshotCount, retainedSnapshots, inspectionCount, retainedInspections
}

func catalogSummary(report *filesystemanalyzer.Report) map[string]any {
	if report == nil {
		return nil
	}
	summary := map[string]any{
		"package_count":          report.Summary.PackageCount,
		"dependency_count":       report.Summary.DependencyCount,
		"vulnerability_count":    report.Summary.VulnerabilityCount,
		"secret_count":           report.Summary.SecretCount,
		"misconfiguration_count": report.Summary.MisconfigurationCount,
		"iac_artifact_count":     report.Summary.IaCArtifactCount,
		"malware_count":          report.Summary.MalwareCount,
		"technology_count":       report.Summary.TechnologyCount,
		"truncated":              report.Summary.Truncated,
	}
	if strings.TrimSpace(report.OS.Name) != "" || strings.TrimSpace(report.OS.Version) != "" || strings.TrimSpace(report.OS.Architecture) != "" {
		summary["os"] = map[string]any{
			"name":         strings.TrimSpace(report.OS.Name),
			"version":      strings.TrimSpace(report.OS.Version),
			"architecture": strings.TrimSpace(report.OS.Architecture),
		}
	}
	return compactMap(summary)
}

func normalizeNamespaces(values []string) ([]string, error) {
	if len(values) == 0 {
		return SupportedNamespaces(), nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if !IsSupportedNamespace(value) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedNamespace, value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return SupportedNamespaces(), nil
	}
	return normalized, nil
}

func compactMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any)
	for key, value := range values {
		switch typed := value.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
			out[key] = typed
		case map[string]string:
			if len(typed) == 0 {
				continue
			}
			out[key] = cloneStringMap(typed)
		case map[string]any:
			if compacted := compactMap(typed); len(compacted) > 0 {
				out[key] = compacted
			}
		default:
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func exceptionTimestamp(env executionstore.RunEnvelope) time.Time {
	switch {
	case env.CompletedAt != nil && !env.CompletedAt.IsZero():
		return env.CompletedAt.UTC()
	case !env.UpdatedAt.IsZero():
		return env.UpdatedAt.UTC()
	default:
		return env.SubmittedAt.UTC()
	}
}

func exceptionKey(item Exception) string {
	return strings.Join([]string{
		item.Source,
		item.Status,
		item.Stage,
		item.Message,
		item.RecordedAt.UTC().Format(time.RFC3339Nano),
	}, "|")
}

func utcTimePtr(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	ts := value.UTC()
	return &ts
}

func firstNonZero(primary, fallback int64) int64 {
	if primary != 0 {
		return primary
	}
	return fallback
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
