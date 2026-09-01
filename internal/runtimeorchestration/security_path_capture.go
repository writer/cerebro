package runtimeorchestration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphpaths"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitypathdelta"
	"github.com/writer/cerebro/internal/sourceruntime"
)

const (
	securityPathDetectorID       = "public-to-privileged"
	securityPathDetectorRevision = "attackpath/v1"
	assertionMigrationBatchSize  = 1000
)

type graphIngestService interface {
	RuntimeCheckpointStatus(context.Context, graphingest.RuntimeRequest) (*graphingest.RuntimeCheckpointStatus, error)
	ListRuns(context.Context, graphstore.IngestRunFilter) (*graphingest.ListResult, error)
	RunRuntime(context.Context, graphingest.RuntimeRequest) (*graphingest.RunResult, error)
}

type CheckpointStore interface {
	GetIngestCheckpoint(context.Context, string) (graphstore.IngestCheckpoint, bool, error)
}

type runtimeSyncService interface {
	Sync(context.Context, *cerebrov1.SyncSourceRuntimeRequest) (*cerebrov1.SyncSourceRuntimeResponse, error)
	SyncWithLease(context.Context, *cerebrov1.SyncSourceRuntimeRequest, sourceruntime.SyncWithLeaseOptions) (*cerebrov1.SyncSourceRuntimeResponse, error)
}

type SecurityPathDependencies struct {
	AttackPaths       ports.CloudAttackPathStore
	AssertionCoverage ports.ProjectionAssertionCoverageStore
	AssertionMigrator ports.ProjectionAssertionMigrator
	GraphIngest       graphIngestService
	Checkpoints       CheckpointStore
	RuntimeStore      ports.SourceRuntimeStore
	LeaseStore        ports.SourceRuntimeLeaseStore
	RuntimeSync       runtimeSyncService
}

type SecurityPathService struct {
	deps SecurityPathDependencies
}

func NewSecurityPathService(deps SecurityPathDependencies) *SecurityPathService {
	return &SecurityPathService{deps: deps}
}

type securityPathGraphReceipt struct {
	runtimeID                 string
	sourceID                  string
	configRevision            string
	checkpointID              string
	runID                     string
	runStartedAt              time.Time
	runFinishedAt             time.Time
	checkpointComplete        bool
	checkpointCurrent         bool
	collectionMode            string
	sourcePagesRead           int
	sourceEvents              int
	sourceEntities            int
	sourceLinks               int
	graphPagesRead            int
	graphEvents               int
	graphEntities             int
	graphLinks                int
	reconciliationRequested   bool
	reconciliationSupported   bool
	reconciliationCompleted   bool
	staleMaterialLinksDeleted int
	limitations               []string
}

type snapshotRequest struct {
	Runtime                 *cerebrov1.SourceRuntime
	AccountID               string
	ObservationID           string
	GraphReceipt            securityPathGraphReceipt
	LeaseHeld               bool
	RuntimeReceipts         []securitypathdelta.RuntimeCollectionReceiptInput
	RequiredProofRuntimeIDs []string
}

func (s *SecurityPathService) captureSnapshot(ctx context.Context, request snapshotRequest) (securitypathdelta.Snapshot, error) {
	runtime := request.Runtime
	if runtime == nil {
		return securitypathdelta.Snapshot{}, errors.New("source runtime is required for security path capture")
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	if tenantID == "" || runtimeID == "" {
		return securitypathdelta.Snapshot{}, errors.New("source runtime tenant and id are required for security path capture")
	}
	if s == nil || s.deps.AttackPaths == nil {
		return securitypathdelta.Snapshot{}, attackpath.ErrRuntimeUnavailable
	}
	migrationLimitations, err := s.migrateLegacyAssertions(ctx, tenantID)
	if err != nil {
		return securitypathdelta.Snapshot{}, err
	}
	observedAt := time.Now().UTC()
	result, err := attackpath.New(s.deps.AttackPaths).Traverse(ctx, attackpath.Request{
		TenantID:              tenantID,
		AccountID:             strings.TrimSpace(request.AccountID),
		RequireAssertionProof: true,
		Limit:                 attackpath.MaxLimit,
	})
	if err != nil {
		return securitypathdelta.Snapshot{}, fmt.Errorf("capture security paths: %w", err)
	}
	paths := make([]securitypathdelta.ObservedPath, 0, len(result.Paths))
	for _, path := range result.Paths {
		paths = append(paths, securitypathdelta.ObservedPath{Path: path})
	}
	runtimeReceipts := mergeRuntimeReceipts(s.proofRuntimeReceipts(ctx, runtime, result.Paths), request.RuntimeReceipts)
	limitations := append([]string(nil), request.GraphReceipt.limitations...)
	limitations = append(limitations, migrationLimitations...)
	limitations = append(limitations, sourceruntime.CollectionIncompletenessReasons(runtime)...)
	coverageStore := s.deps.AssertionCoverage
	if coverageStore == nil {
		limitations = append(limitations, "material_link_assertion_coverage_unavailable")
	} else {
		missing, coverageErr := coverageStore.CountProjectedLinksMissingAssertions(ctx, tenantID, securityPathMaterialRelations())
		if coverageErr != nil {
			return securitypathdelta.Snapshot{}, fmt.Errorf("read security path assertion coverage: %w", coverageErr)
		}
		if missing != 0 {
			limitations = append(limitations, "material_link_assertion_coverage_incomplete")
		}
	}
	if result.Counts.Paths != len(result.Paths) || len(result.Paths) >= attackpath.MaxLimit {
		limitations = append(limitations, "path_query_limit_reached")
	}
	watermark, lastSyncedAt := runtimeTimes(runtime)
	scopeID := "source-runtime:" + runtimeID
	if account := strings.TrimSpace(request.AccountID); account != "" {
		scopeID += ":account:" + account
	}
	providerFamily := runtimeProviderFamily(runtime)
	return securitypathdelta.NewSnapshot(securitypathdelta.SnapshotInput{
		TenantID:                tenantID,
		ScopeID:                 scopeID,
		DetectorID:              securityPathDetectorID,
		DetectorRevision:        securityPathDetectorRevision,
		ObservationID:           strings.TrimSpace(request.ObservationID),
		ObservedAt:              observedAt,
		RequiredProofRuntimeIDs: append([]string(nil), request.RequiredProofRuntimeIDs...),
		Receipt: securitypathdelta.CollectionReceiptInput{
			SourceRuntimeID:  runtimeID,
			SourceID:         strings.TrimSpace(runtime.GetSourceId()),
			ProviderFamily:   providerFamily,
			ConfigRevision:   strings.TrimSpace(request.GraphReceipt.configRevision),
			RuntimeWatermark: watermark,
			LastSyncedAt:     lastSyncedAt,
			CollectionMode:   request.GraphReceipt.collectionMode,
			CollectionSourceProjectionReceipt: securitypathdelta.CollectionSourceProjectionReceipt{
				SourcePagesRead:         request.GraphReceipt.sourcePagesRead,
				SourceEventsAppended:    request.GraphReceipt.sourceEvents,
				SourceEntitiesProjected: request.GraphReceipt.sourceEntities,
				SourceLinksProjected:    request.GraphReceipt.sourceLinks,
			},
			GraphCheckpointID:  strings.TrimSpace(request.GraphReceipt.checkpointID),
			GraphRunID:         strings.TrimSpace(request.GraphReceipt.runID),
			GraphRunStartedAt:  request.GraphReceipt.runStartedAt,
			GraphRunFinishedAt: request.GraphReceipt.runFinishedAt,
			CollectionGraphProjectionReceipt: securitypathdelta.CollectionGraphProjectionReceipt{
				GraphPagesRead:                 request.GraphReceipt.graphPagesRead,
				GraphEventsRead:                request.GraphReceipt.graphEvents,
				GraphEntitiesProjected:         request.GraphReceipt.graphEntities,
				GraphLinksProjected:            request.GraphReceipt.graphLinks,
				GraphStaleMaterialLinksDeleted: request.GraphReceipt.staleMaterialLinksDeleted,
			},
			GraphMaterialLinkReconciliationRequested: request.GraphReceipt.reconciliationRequested,
			GraphMaterialLinkReconciliationSupported: request.GraphReceipt.reconciliationSupported,
			GraphMaterialLinkReconciliationCompleted: request.GraphReceipt.reconciliationCompleted,
			GraphCheckpointComplete:                  request.GraphReceipt.checkpointComplete,
			GraphCheckpointCurrent:                   request.GraphReceipt.checkpointCurrent,
			ObservedPathCount:                        len(result.Paths),
			TotalPathCount:                           result.Counts.Paths,
			LeaseHeld:                                request.LeaseHeld,
			Limitations:                              limitations,
			RuntimeReceipts:                          runtimeReceipts,
		},
		Paths: paths,
	})
}

func (s *SecurityPathService) migrateLegacyAssertions(ctx context.Context, tenantID string) ([]string, error) {
	migrator := s.deps.AssertionMigrator
	if migrator == nil {
		return []string{"material_link_assertion_migration_unavailable"}, nil
	}
	quarantined := false
	for {
		result, err := migrator.MigrateProjectedLinkAssertions(ctx, ports.ProjectionAssertionMigrationRequest{
			TenantID: strings.TrimSpace(tenantID), Relations: securityPathMaterialRelations(), Limit: assertionMigrationBatchSize,
		})
		if err != nil {
			return nil, fmt.Errorf("migrate legacy security path assertions: %w", err)
		}
		quarantined = quarantined || result.LinksQuarantined != 0
		if result.LinksMigrated < assertionMigrationBatchSize {
			break
		}
	}
	if quarantined {
		return []string{"material_link_assertion_migration_quarantined"}, nil
	}
	return nil, nil
}

func securityPathMaterialRelations() []string {
	values := append([]string{"belongs_to", "can_admin", "can_perform", "can_reach", "owned_by"}, graphpaths.CloudExposurePrivilegeTraversalRelations()...)
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (s *SecurityPathService) proofRuntimeReceipts(ctx context.Context, primary *cerebrov1.SourceRuntime, paths []attackpath.Path) []securitypathdelta.RuntimeCollectionReceiptInput {
	primaryID := strings.TrimSpace(primary.GetId())
	runtimeIDs := attackPathRuntimeIDs(paths)
	inputs := make([]securitypathdelta.RuntimeCollectionReceiptInput, 0, len(runtimeIDs))
	for _, runtimeID := range runtimeIDs {
		if runtimeID == primaryID {
			continue
		}
		placeholder := securitypathdelta.RuntimeCollectionReceiptInput{SourceRuntimeID: runtimeID}
		if s.deps.RuntimeStore == nil {
			placeholder.Limitations = []string{"runtime_store_unavailable"}
			inputs = append(inputs, placeholder)
			continue
		}
		runtime, err := s.deps.RuntimeStore.GetSourceRuntime(ctx, runtimeID)
		if err != nil || runtime == nil {
			placeholder.Limitations = []string{"runtime_record_unavailable"}
			inputs = append(inputs, placeholder)
			continue
		}
		graphReceipt, err := s.baselineGraphReceipt(ctx, runtimeID)
		if err != nil {
			placeholder.SourceID = strings.TrimSpace(runtime.GetSourceId())
			placeholder.ProviderFamily = runtimeProviderFamily(runtime)
			placeholder.Limitations = []string{"graph_receipt_unavailable"}
			inputs = append(inputs, placeholder)
			continue
		}
		inputs = append(inputs, runtimeReceiptInput(runtime, graphReceipt))
	}
	return inputs
}

func attackPathRuntimeIDs(paths []attackpath.Path) []string {
	set := map[string]struct{}{}
	for _, path := range paths {
		edges := []attackpath.Edge{path.ExposureEdge, path.ResourceAccountEdge}
		edges = append(edges, path.TraversalEdges...)
		edges = append(edges, path.PrivilegeEdge, path.PermissionAccountEdge)
		for _, edge := range edges {
			for _, runtimeID := range append(append([]string(nil), edge.AssertionRuntimeIDs...), edge.SourceRuntimeID) {
				if runtimeID = strings.TrimSpace(runtimeID); runtimeID != "" {
					set[runtimeID] = struct{}{}
				}
			}
		}
		for _, ownership := range path.Ownerships {
			for _, runtimeID := range append(append([]string(nil), ownership.Edge.AssertionRuntimeIDs...), ownership.Edge.SourceRuntimeID) {
				if runtimeID = strings.TrimSpace(runtimeID); runtimeID != "" {
					set[runtimeID] = struct{}{}
				}
			}
		}
	}
	return sortedSet(set)
}

func runtimeReceiptInput(runtime *cerebrov1.SourceRuntime, graphReceipt securityPathGraphReceipt) securitypathdelta.RuntimeCollectionReceiptInput {
	watermark, lastSyncedAt := runtimeTimes(runtime)
	return securitypathdelta.RuntimeCollectionReceiptInput{
		SourceRuntimeID:         strings.TrimSpace(runtime.GetId()),
		SourceID:                strings.TrimSpace(runtime.GetSourceId()),
		ProviderFamily:          runtimeProviderFamily(runtime),
		ConfigRevision:          strings.TrimSpace(graphReceipt.configRevision),
		RuntimeWatermark:        watermark,
		LastSyncedAt:            lastSyncedAt,
		GraphCheckpointID:       strings.TrimSpace(graphReceipt.checkpointID),
		GraphRunID:              strings.TrimSpace(graphReceipt.runID),
		GraphRunStartedAt:       graphReceipt.runStartedAt,
		GraphRunFinishedAt:      graphReceipt.runFinishedAt,
		GraphCheckpointComplete: graphReceipt.checkpointComplete,
		GraphCheckpointCurrent:  graphReceipt.checkpointCurrent,
		Limitations:             append(append([]string(nil), graphReceipt.limitations...), sourceruntime.CollectionIncompletenessReasons(runtime)...),
	}
}

func mergeRuntimeReceipts(baseline, replacements []securitypathdelta.RuntimeCollectionReceiptInput) []securitypathdelta.RuntimeCollectionReceiptInput {
	byRuntime := make(map[string]securitypathdelta.RuntimeCollectionReceiptInput, len(baseline)+len(replacements))
	for _, receipt := range baseline {
		if runtimeID := strings.TrimSpace(receipt.SourceRuntimeID); runtimeID != "" {
			byRuntime[runtimeID] = receipt
		}
	}
	for _, receipt := range replacements {
		if runtimeID := strings.TrimSpace(receipt.SourceRuntimeID); runtimeID != "" {
			byRuntime[runtimeID] = receipt
		}
	}
	runtimeIDs := make([]string, 0, len(byRuntime))
	for runtimeID := range byRuntime {
		runtimeIDs = append(runtimeIDs, runtimeID)
	}
	sort.Strings(runtimeIDs)
	result := make([]securitypathdelta.RuntimeCollectionReceiptInput, 0, len(runtimeIDs))
	for _, runtimeID := range runtimeIDs {
		result = append(result, byRuntime[runtimeID])
	}
	return result
}

func runtimeTimes(runtime *cerebrov1.SourceRuntime) (time.Time, time.Time) {
	var watermark, lastSyncedAt time.Time
	if runtime.GetCheckpoint().GetWatermark() != nil {
		watermark = runtime.GetCheckpoint().GetWatermark().AsTime().UTC()
	}
	if runtime.GetLastSyncedAt() != nil {
		lastSyncedAt = runtime.GetLastSyncedAt().AsTime().UTC()
	}
	return watermark, lastSyncedAt
}

func runtimeProviderFamily(runtime *cerebrov1.SourceRuntime) string {
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	if family == "" {
		return "default"
	}
	return family
}

func (s *SecurityPathService) baselineGraphReceipt(ctx context.Context, runtimeID string) (securityPathGraphReceipt, error) {
	if s == nil || s.deps.GraphIngest == nil {
		return securityPathGraphReceipt{}, graphingest.ErrRuntimeUnavailable
	}
	status, err := s.deps.GraphIngest.RuntimeCheckpointStatus(ctx, graphingest.RuntimeRequest{RuntimeID: strings.TrimSpace(runtimeID)})
	if err != nil {
		return securityPathGraphReceipt{}, fmt.Errorf("read baseline graph checkpoint: %w", err)
	}
	receipt := securityPathGraphReceipt{
		runtimeID:          strings.TrimSpace(runtimeID),
		sourceID:           strings.TrimSpace(status.SourceID),
		checkpointID:       strings.TrimSpace(status.CheckpointID),
		checkpointComplete: status.Completed,
		checkpointCurrent:  status.CheckpointCurrent,
		collectionMode:     securitypathdelta.CollectionModeCheckpointed,
	}
	receipt.configRevision, err = s.checkpointConfigRevision(ctx, receipt.checkpointID)
	if err != nil {
		return securityPathGraphReceipt{}, err
	}
	runs, err := s.deps.GraphIngest.ListRuns(ctx, graphstore.IngestRunFilter{RuntimeID: runtimeID, Status: graphstore.IngestRunStatusCompleted, Limit: 1})
	if err != nil {
		return securityPathGraphReceipt{}, fmt.Errorf("read baseline graph run: %w", err)
	}
	if len(runs.Runs) == 0 {
		receipt.limitations = append(receipt.limitations, "baseline_graph_run_missing")
		return receipt, nil
	}
	latest := runs.Runs[0]
	if receipt.sourceID == "" {
		receipt.sourceID = strings.TrimSpace(latest.SourceID)
	}
	receipt.runID = strings.TrimSpace(latest.ID)
	receipt.runStartedAt = parseGraphTime(latest.StartedAt)
	receipt.runFinishedAt = parseGraphTime(latest.FinishedAt)
	receipt.graphPagesRead = int(latest.PagesRead)
	receipt.graphEvents = int(latest.EventsRead)
	receipt.graphEntities = int(latest.EntitiesProjected)
	receipt.graphLinks = int(latest.LinksProjected)
	if latest.CheckpointID != receipt.checkpointID {
		receipt.limitations = append(receipt.limitations, "baseline_graph_run_checkpoint_mismatch")
	}
	if !latest.CheckpointComplete {
		receipt.limitations = append(receipt.limitations, "baseline_graph_run_incomplete")
	}
	return receipt, nil
}

func (s *SecurityPathService) graphReceiptForRun(ctx context.Context, request graphingest.RuntimeRequest, result *graphingest.RunResult, collectionMode string) (securityPathGraphReceipt, error) {
	if result == nil {
		return securityPathGraphReceipt{}, errors.New("security path graph run result is required")
	}
	run := result.Run
	status, err := s.deps.GraphIngest.RuntimeCheckpointStatus(ctx, graphingest.RuntimeRequest{RuntimeID: strings.TrimSpace(request.RuntimeID), CheckpointID: strings.TrimSpace(run.CheckpointID)})
	if err != nil {
		return securityPathGraphReceipt{}, fmt.Errorf("read security path graph checkpoint after run: %w", err)
	}
	configRevision, err := s.checkpointConfigRevision(ctx, strings.TrimSpace(run.CheckpointID))
	if err != nil {
		return securityPathGraphReceipt{}, err
	}
	receipt := securityPathGraphReceipt{
		runtimeID:                 strings.TrimSpace(run.RuntimeID),
		sourceID:                  strings.TrimSpace(run.SourceID),
		configRevision:            configRevision,
		checkpointID:              strings.TrimSpace(run.CheckpointID),
		runID:                     strings.TrimSpace(run.ID),
		runStartedAt:              parseGraphTime(run.StartedAt),
		runFinishedAt:             parseGraphTime(run.FinishedAt),
		checkpointComplete:        run.CheckpointComplete && status.Completed,
		checkpointCurrent:         status.CheckpointCurrent,
		collectionMode:            strings.TrimSpace(collectionMode),
		graphPagesRead:            int(run.PagesRead),
		graphEvents:               int(run.EventsRead),
		graphEntities:             int(run.EntitiesProjected),
		graphLinks:                int(run.LinksProjected),
		reconciliationRequested:   run.MaterialLinkReconciliationRequested,
		reconciliationSupported:   run.MaterialLinkReconciliationSupported,
		reconciliationCompleted:   run.MaterialLinkReconciliationCompleted,
		staleMaterialLinksDeleted: int(run.StaleMaterialLinksDeleted),
	}
	if result.Ingest != nil {
		receipt.sourcePagesRead = int(result.Ingest.PagesRead)
		receipt.sourceEvents = int(result.Ingest.EventsRead)
		receipt.sourceEntities = int(result.Ingest.EntitiesProjected)
		receipt.sourceLinks = int(result.Ingest.LinksProjected)
	}
	if strings.TrimSpace(status.CheckpointID) != receipt.checkpointID {
		receipt.limitations = append(receipt.limitations, "graph_run_checkpoint_mismatch")
	}
	if !status.Found {
		receipt.limitations = append(receipt.limitations, "graph_checkpoint_missing_after_run")
	}
	if run.Status != graphstore.IngestRunStatusCompleted {
		receipt.limitations = append(receipt.limitations, "graph_run_not_completed")
	}
	if result.Ingest != nil && result.Ingest.CheckpointAlreadyFresh && collectionMode == securitypathdelta.CollectionModeGraphResetFullScan {
		receipt.limitations = append(receipt.limitations, "fresh_graph_collection_reused_checkpoint")
	}
	return receipt, nil
}

func (s *SecurityPathService) checkpointConfigRevision(ctx context.Context, checkpointID string) (string, error) {
	if s == nil || s.deps.Checkpoints == nil {
		return "", errors.New("graph checkpoint store is required for security path capture")
	}
	checkpoint, found, err := s.deps.Checkpoints.GetIngestCheckpoint(ctx, strings.TrimSpace(checkpointID))
	if err != nil {
		return "", fmt.Errorf("read security path graph checkpoint revision: %w", err)
	}
	if !found {
		return "", nil
	}
	return strings.TrimSpace(checkpoint.ConfigHash), nil
}

func verificationCheckpointID(runtimeID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(runtimeID)))
	return "security-path-verification:" + hex.EncodeToString(sum[:8])
}

func parseGraphTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}
