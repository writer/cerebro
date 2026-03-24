package api

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/writer/cerebro/internal/forensics"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/workloadscan"
)

const defaultForensicsRetentionDays = 90

var errForensicsUnavailable = errors.New("forensics not initialized")

type forensicsService interface {
	CreateCapture(ctx context.Context, req forensicsCaptureRequest) (*forensics.CaptureRecord, error)
	ListCaptures(ctx context.Context, opts forensics.CaptureListOptions) ([]forensics.CaptureRecord, error)
	GetCapture(ctx context.Context, captureID string) (*forensics.CaptureRecord, bool, error)
	RecordRemediationEvidence(ctx context.Context, req forensicsRemediationEvidenceRequest) (*forensics.RemediationEvidenceRecord, error)
	GetRemediationEvidence(ctx context.Context, evidenceID string) (*forensics.RemediationEvidenceRecord, bool, error)
	ExportEvidencePackage(ctx context.Context, evidenceID string) (*forensics.EvidencePackage, error)
}

type workloadProviderResolver func(context.Context, workloadscan.VMTarget) (workloadscan.Provider, error)

type serverForensicsService struct {
	deps             *serverDependencies
	providerResolver workloadProviderResolver
}

func newForensicsService(deps *serverDependencies) forensicsService {
	return serverForensicsService{
		deps:             deps,
		providerResolver: resolveWorkloadProvider,
	}
}

func (s serverForensicsService) CreateCapture(ctx context.Context, req forensicsCaptureRequest) (*forensics.CaptureRecord, error) {
	store, closeStore, err := s.store()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}

	now := time.Now().UTC()
	target := req.Target
	retentionDays := req.RetentionDays
	if retentionDays <= 0 {
		retentionDays = defaultForensicsRetentionDays
	}
	record := &forensics.CaptureRecord{
		ID:            firstNonEmpty(req.ID, "forensic_capture:"+uuid.NewString()),
		IncidentID:    strings.TrimSpace(req.IncidentID),
		WorkloadID:    strings.TrimSpace(req.WorkloadID),
		Status:        forensics.CaptureStatusPending,
		Target:        target,
		RequestedBy:   strings.TrimSpace(req.RequestedBy),
		Reason:        strings.TrimSpace(req.Reason),
		RetentionDays: retentionDays,
		SubmittedAt:   now,
		RetainUntil:   timePtr(now.Add(time.Duration(retentionDays) * 24 * time.Hour)),
		Metadata:      cloneJSONMap(req.Metadata),
	}
	appendCustodyEvent(&record.ChainOfCustody, "requested", record.RequestedBy, "api", "Forensic capture requested", nil, now)
	if err := store.SaveCapture(ctx, record); err != nil {
		return nil, err
	}

	provider, err := s.providerResolver(ctx, target)
	if err != nil {
		record.Status = forensics.CaptureStatusFailed
		record.Error = err.Error()
		record.CompletedAt = timePtr(now)
		appendCustodyEvent(&record.ChainOfCustody, "provider_error", record.RequestedBy, "api", err.Error(), nil, now)
		_ = store.SaveCapture(ctx, record)
		s.materialize(ctx, []forensics.CaptureRecord{*record}, nil)
		return nil, err
	}

	volumes, err := provider.InventoryVolumes(ctx, target)
	if err != nil {
		record.Status = forensics.CaptureStatusFailed
		record.Error = err.Error()
		record.CompletedAt = timePtr(time.Now().UTC())
		appendCustodyEvent(&record.ChainOfCustody, "inventory_failed", record.RequestedBy, "provider", err.Error(), nil, time.Now().UTC())
		_ = store.SaveCapture(ctx, record)
		s.materialize(ctx, []forensics.CaptureRecord{*record}, nil)
		return nil, err
	}
	if len(volumes) == 0 {
		record.Status = forensics.CaptureStatusFailed
		record.Error = "no source volumes discovered for target"
		record.CompletedAt = timePtr(time.Now().UTC())
		appendCustodyEvent(&record.ChainOfCustody, "inventory_empty", record.RequestedBy, "provider", record.Error, nil, time.Now().UTC())
		_ = store.SaveCapture(ctx, record)
		s.materialize(ctx, []forensics.CaptureRecord{*record}, nil)
		return nil, errors.New(record.Error)
	}

	var failures []string
	for _, volume := range volumes {
		snapshot, snapshotErr := provider.CreateSnapshot(ctx, target, volume, captureMetadata(record))
		if snapshotErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", volume.ID, snapshotErr))
			appendCustodyEvent(&record.ChainOfCustody, "snapshot_failed", record.RequestedBy, "provider", snapshotErr.Error(), map[string]any{"volume_id": volume.ID}, time.Now().UTC())
			continue
		}
		record.Snapshots = append(record.Snapshots, *snapshot)
		appendCustodyEvent(&record.ChainOfCustody, "snapshot_created", record.RequestedBy, string(snapshot.Scope), "Snapshot preserved", map[string]any{
			"snapshot_id": snapshot.ID,
			"volume_id":   volume.ID,
		}, time.Now().UTC())
	}

	completedAt := time.Now().UTC()
	record.CompletedAt = &completedAt
	switch {
	case len(record.Snapshots) == 0:
		record.Status = forensics.CaptureStatusFailed
		record.Error = strings.Join(failures, "; ")
	case len(failures) > 0:
		record.Status = forensics.CaptureStatusPartial
		record.Error = strings.Join(failures, "; ")
	default:
		record.Status = forensics.CaptureStatusCaptured
	}
	appendCustodyEvent(&record.ChainOfCustody, "capture_recorded", record.RequestedBy, "execution_store", string(record.Status), map[string]any{
		"snapshot_count": len(record.Snapshots),
	}, completedAt)
	if err := store.SaveCapture(ctx, record); err != nil {
		return nil, err
	}
	s.materialize(ctx, []forensics.CaptureRecord{*record}, nil)
	if record.Status == forensics.CaptureStatusFailed {
		return nil, errors.New(firstNonEmpty(record.Error, "forensic capture failed"))
	}
	return record, nil
}

func (s serverForensicsService) ListCaptures(ctx context.Context, opts forensics.CaptureListOptions) ([]forensics.CaptureRecord, error) {
	store, closeStore, err := s.store()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	return store.ListCaptures(ctx, opts)
}

func (s serverForensicsService) GetCapture(ctx context.Context, captureID string) (*forensics.CaptureRecord, bool, error) {
	store, closeStore, err := s.store()
	if err != nil {
		return nil, false, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	record, err := store.LoadCapture(ctx, captureID)
	return record, record != nil, err
}

func (s serverForensicsService) RecordRemediationEvidence(ctx context.Context, req forensicsRemediationEvidenceRequest) (*forensics.RemediationEvidenceRecord, error) {
	store, closeStore, err := s.store()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	now := time.Now().UTC()
	record := &forensics.RemediationEvidenceRecord{
		ID:                     firstNonEmpty(req.ID, "remediation_evidence:"+uuid.NewString()),
		IncidentID:             strings.TrimSpace(req.IncidentID),
		WorkloadID:             strings.TrimSpace(req.WorkloadID),
		BeforeCaptureID:        strings.TrimSpace(req.BeforeCaptureID),
		AfterCaptureID:         strings.TrimSpace(req.AfterCaptureID),
		RemediationExecutionID: strings.TrimSpace(req.RemediationExecutionID),
		ActionSummary:          strings.TrimSpace(req.ActionSummary),
		Actor:                  strings.TrimSpace(req.Actor),
		Status:                 normalizeEvidenceStatus(req.Status),
		CreatedAt:              now,
		Notes:                  strings.TrimSpace(req.Notes),
		Metadata:               cloneJSONMap(req.Metadata),
	}
	appendCustodyEvent(&record.ChainOfCustody, "evidence_recorded", record.Actor, "api", "Remediation evidence recorded", nil, now)

	captures := make([]forensics.CaptureRecord, 0, 2)
	for _, captureID := range []string{record.BeforeCaptureID, record.AfterCaptureID} {
		if captureID == "" {
			continue
		}
		capture, err := store.LoadCapture(ctx, captureID)
		if err != nil {
			return nil, err
		}
		if capture == nil {
			return nil, fmt.Errorf("forensic capture not found: %s", captureID)
		}
		captures = append(captures, *capture)
		if record.WorkloadID == "" {
			record.WorkloadID = strings.TrimSpace(capture.WorkloadID)
		}
		if record.IncidentID == "" {
			record.IncidentID = strings.TrimSpace(capture.IncidentID)
		}
	}
	if record.RemediationExecutionID != "" && s.deps != nil && s.deps.Remediation != nil {
		if execution, ok := s.deps.Remediation.GetExecution(record.RemediationExecutionID); ok && execution != nil && record.ActionSummary == "" {
			record.ActionSummary = summarizeRemediationExecution(execution)
		}
	}
	if err := store.SaveEvidence(ctx, record); err != nil {
		return nil, err
	}
	s.materialize(ctx, captures, []forensics.RemediationEvidenceRecord{*record})
	return record, nil
}

func (s serverForensicsService) GetRemediationEvidence(ctx context.Context, evidenceID string) (*forensics.RemediationEvidenceRecord, bool, error) {
	store, closeStore, err := s.store()
	if err != nil {
		return nil, false, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	record, err := store.LoadEvidence(ctx, evidenceID)
	return record, record != nil, err
}

func (s serverForensicsService) ExportEvidencePackage(ctx context.Context, evidenceID string) (*forensics.EvidencePackage, error) {
	store, closeStore, err := s.store()
	if err != nil {
		return nil, err
	}
	if closeStore != nil {
		defer closeStore()
	}
	record, err := store.LoadEvidence(ctx, evidenceID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("remediation evidence not found: %s", evidenceID)
	}
	pkg := &forensics.EvidencePackage{
		ID:                  "evidence_package:" + strings.TrimSpace(record.ID),
		GeneratedAt:         time.Now().UTC(),
		IncidentID:          strings.TrimSpace(record.IncidentID),
		WorkloadID:          strings.TrimSpace(record.WorkloadID),
		RemediationEvidence: record,
	}
	for _, captureID := range []string{record.BeforeCaptureID, record.AfterCaptureID} {
		if captureID == "" {
			continue
		}
		capture, err := store.LoadCapture(ctx, captureID)
		if err != nil {
			return nil, err
		}
		if capture != nil {
			pkg.Captures = append(pkg.Captures, *capture)
			pkg.ChainOfCustody = append(pkg.ChainOfCustody, capture.ChainOfCustody...)
		}
	}
	pkg.ChainOfCustody = append(pkg.ChainOfCustody, record.ChainOfCustody...)
	sort.Slice(pkg.ChainOfCustody, func(i, j int) bool {
		if !pkg.ChainOfCustody[i].RecordedAt.Equal(pkg.ChainOfCustody[j].RecordedAt) {
			return pkg.ChainOfCustody[i].RecordedAt.Before(pkg.ChainOfCustody[j].RecordedAt)
		}
		return pkg.ChainOfCustody[i].Step < pkg.ChainOfCustody[j].Step
	})
	if record.RemediationExecutionID != "" && s.deps != nil && s.deps.Remediation != nil {
		if execution, ok := s.deps.Remediation.GetExecution(record.RemediationExecutionID); ok && execution != nil {
			pkg.RemediationExecution = remediationExecutionSummary(execution)
		}
	}
	return pkg, nil
}

func (s serverForensicsService) materialize(ctx context.Context, captures []forensics.CaptureRecord, evidence []forensics.RemediationEvidenceRecord) {
	if s.deps == nil || s.deps.graphMutator == nil {
		return
	}
	_, err := s.deps.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		forensics.MaterializeIntoGraph(g, captures, evidence, time.Now().UTC())
		return nil
	})
	if err != nil && s.deps.Logger != nil {
		s.deps.Logger.Warn("failed to materialize forensic records into graph", "error", err)
	}
}

func (s serverForensicsService) store() (forensics.Store, func(), error) {
	if s.deps == nil {
		return nil, nil, errForensicsUnavailable
	}
	if s.deps.ExecutionStore != nil {
		return forensics.NewSQLiteStoreWithExecutionStore(s.deps.ExecutionStore), nil, nil
	}
	if s.deps.Config == nil {
		return nil, nil, errForensicsUnavailable
	}
	path := strings.TrimSpace(s.deps.Config.ExecutionStoreFile)
	if path == "" {
		path = strings.TrimSpace(s.deps.Config.WorkloadScanStateFile)
	}
	if path == "" {
		return nil, nil, errForensicsUnavailable
	}
	store, err := forensics.NewSQLiteStore(path)
	if err != nil {
		return nil, nil, errors.Join(errForensicsUnavailable, err)
	}
	return store, func() { _ = store.Close() }, nil
}

func resolveWorkloadProvider(ctx context.Context, target workloadscan.VMTarget) (workloadscan.Provider, error) {
	switch target.Provider {
	case workloadscan.ProviderAWS:
		if strings.TrimSpace(target.Region) == "" {
			return nil, fmt.Errorf("target.region is required for aws forensic captures")
		}
		return workloadscan.NewAWSProvider(ctx, target.Region)
	case workloadscan.ProviderGCP:
		return workloadscan.NewGCPProvider(ctx)
	case workloadscan.ProviderAzure:
		return workloadscan.NewAzureProvider()
	default:
		return nil, fmt.Errorf("unsupported forensic capture provider: %s", target.Provider)
	}
}

func captureMetadata(record *forensics.CaptureRecord) map[string]string {
	metadata := map[string]string{
		"forensic":       "true",
		"capture_id":     strings.TrimSpace(record.ID),
		"requested_by":   strings.TrimSpace(record.RequestedBy),
		"reason":         strings.TrimSpace(record.Reason),
		"retention_days": fmt.Sprintf("%d", record.RetentionDays),
	}
	if record.RetainUntil != nil && !record.RetainUntil.IsZero() {
		metadata["retain_until"] = record.RetainUntil.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(record.IncidentID) != "" {
		metadata["incident_id"] = strings.TrimSpace(record.IncidentID)
	}
	return metadata
}

func appendCustodyEvent(events *[]forensics.CustodyEvent, step, actor, location, detail string, metadata map[string]any, recordedAt time.Time) {
	if events == nil {
		return
	}
	*events = append(*events, forensics.CustodyEvent{
		Step:       strings.TrimSpace(step),
		Actor:      strings.TrimSpace(actor),
		Location:   strings.TrimSpace(location),
		Detail:     strings.TrimSpace(detail),
		RecordedAt: recordedAt.UTC(),
		Metadata:   cloneJSONMap(metadata),
	})
}

func normalizeEvidenceStatus(status string) forensics.EvidenceStatus {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case string(forensics.EvidenceStatusVerified):
		return forensics.EvidenceStatusVerified
	default:
		return forensics.EvidenceStatusRecorded
	}
}

func remediationExecutionSummary(execution *remediation.Execution) *forensics.RemediationExecutionSummary {
	if execution == nil {
		return nil
	}
	startedAt := execution.StartedAt.UTC()
	return &forensics.RemediationExecutionSummary{
		ID:          execution.ID,
		RuleID:      execution.RuleID,
		RuleName:    execution.RuleName,
		Status:      string(execution.Status),
		StartedAt:   &startedAt,
		CompletedAt: execution.CompletedAt,
		Error:       execution.Error,
	}
}

func summarizeRemediationExecution(execution *remediation.Execution) string {
	if execution == nil {
		return ""
	}
	if trimmed := strings.TrimSpace(execution.RuleName); trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(execution.RuleID)
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}
