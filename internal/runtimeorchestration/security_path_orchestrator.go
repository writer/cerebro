package runtimeorchestration

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/securitypathdelta"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type SecurityPathRequest struct {
	RuntimeID       string
	AccountID       string
	ObservationID   string
	SourcePageLimit uint32
	GraphPageLimit  uint32
	LeaseOwner      string
}

type RuntimeGraphRun struct {
	RuntimeID string                 `json:"runtime_id"`
	Result    *graphingest.RunResult `json:"result"`
}

type SecurityPathResult struct {
	Sync                    *cerebrov1.SyncSourceRuntimeResponse     `json:"sync,omitempty"`
	Graph                   *graphingest.RunResult                   `json:"graph_ingest,omitempty"`
	Before                  securitypathdelta.Snapshot               `json:"before"`
	After                   securitypathdelta.Snapshot               `json:"after"`
	Delta                   securitypathdelta.Delta                  `json:"delta"`
	VerificationGraphIngest *graphingest.RunResult                   `json:"verification_graph_ingest,omitempty"`
	VerificationGraphRuns   []RuntimeGraphRun                        `json:"verification_graph_ingests,omitempty"`
	VerificationSnapshot    *securitypathdelta.Snapshot              `json:"verification_snapshot,omitempty"`
	Verification            *securitypathdelta.Verification          `json:"verification,omitempty"`
	RustAuthority           []securitypathdelta.RustAuthorityReceipt `json:"rust_authority"`
}

func (s *SecurityPathService) Capture(ctx context.Context, request SecurityPathRequest) (result SecurityPathResult, runErr error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return result, errors.New("source runtime id is required for security path capture")
	}
	if s == nil || s.deps.GraphQueries == nil || s.deps.GraphIngest == nil || s.deps.Checkpoints == nil || s.deps.RuntimeStore == nil || s.deps.RuntimeSync == nil || s.deps.LeaseStore == nil {
		return result, errors.New("security path capture dependencies are unavailable")
	}
	owner := strings.TrimSpace(request.LeaseOwner)
	if owner == "" {
		owner = "security-path-delta:" + strings.TrimSpace(request.ObservationID)
	}
	leaseCtx, releasePrimary, acquired, err := sourceruntime.AcquireRenewableLease(ctx, s.deps.LeaseStore, runtimeID, owner, sourceruntime.DefaultLeaseTTL)
	if err != nil {
		return result, fmt.Errorf("acquire security path capture lease: %w", err)
	}
	if !acquired {
		return result, fmt.Errorf("%w: %s", sourceruntime.ErrSyncInProgress, runtimeID)
	}
	ctx = leaseCtx
	defer func() {
		if err := releasePrimary(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("release security path capture lease: %w", err))
		}
	}()

	runtime, err := s.deps.RuntimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return result, err
	}
	baselineReceipt, err := s.baselineGraphReceipt(ctx, runtimeID)
	if err != nil {
		return result, err
	}
	result.Before, err = s.captureSnapshot(ctx, snapshotRequest{
		Runtime: runtime, AccountID: request.AccountID, ObservationID: request.ObservationID + ":before",
		GraphReceipt: baselineReceipt, LeaseHeld: true,
	})
	if err != nil {
		return result, err
	}

	result.Sync, err = s.deps.RuntimeSync.Sync(ctx, &cerebrov1.SyncSourceRuntimeRequest{Id: runtimeID, PageLimit: request.SourcePageLimit})
	if err != nil {
		return result, err
	}
	graphRequest := orchestrationGraphRequest(runtimeID, request.GraphPageLimit)
	result.Graph, err = s.deps.GraphIngest.RunRuntime(ctx, graphRequest)
	if err != nil {
		return result, err
	}
	currentRuntime, err := s.deps.RuntimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return result, fmt.Errorf("read source runtime after sync: %w", err)
	}
	currentReceipt, err := s.graphReceiptForRun(ctx, graphRequest, result.Graph, securitypathdelta.CollectionModeGraphResetFullScan)
	if err != nil {
		return result, err
	}
	currentReceipt.sourcePagesRead = int(result.Sync.GetPagesRead())
	currentReceipt.sourceEvents = int(result.Sync.GetEventsAppended())
	currentReceipt.sourceEntities = int(result.Sync.GetEntitiesProjected())
	currentReceipt.sourceLinks = int(result.Sync.GetLinksProjected())
	result.After, err = s.captureSnapshot(ctx, snapshotRequest{
		Runtime: currentRuntime, AccountID: request.AccountID, ObservationID: request.ObservationID + ":after",
		GraphReceipt: currentReceipt, LeaseHeld: true,
	})
	if err != nil {
		return result, err
	}
	var deltaAuthority securitypathdelta.RustAuthorityReceipt
	result.Delta, deltaAuthority, err = securitypathdelta.CompareRustAuthority(ctx, &result.Before, result.After)
	if err != nil {
		return result, err
	}
	result.RustAuthority = append(result.RustAuthority, deltaAuthority)
	if len(result.Delta.NoLongerObserved) == 0 {
		return result, nil
	}

	requestedPathIDs := make([]string, 0, len(result.Delta.NoLongerObserved))
	for _, path := range result.Delta.NoLongerObserved {
		requestedPathIDs = append(requestedPathIDs, path.ID)
	}
	contributingRuntimeIDs := securityPathRuntimeIDs(result.Delta.NoLongerObserved)
	verification, err := s.collectVerification(ctx, verificationRequest{
		PrimaryRuntimeID:       runtimeID,
		AccountID:              request.AccountID,
		ObservationID:          request.ObservationID + ":verify",
		GraphPageLimit:         request.GraphPageLimit,
		LeaseOwner:             owner,
		Reference:              result.Before,
		Current:                result.After,
		RequestedPathIDs:       requestedPathIDs,
		ContributingRuntimeIDs: contributingRuntimeIDs,
	})
	result.VerificationGraphRuns = verification.GraphRuns
	for _, run := range verification.GraphRuns {
		if run.RuntimeID == runtimeID {
			result.VerificationGraphIngest = run.Result
			break
		}
	}
	if verification.Snapshot.ID != "" {
		result.VerificationSnapshot = &verification.Snapshot
	}
	if verification.Verification.ID != "" {
		result.Verification = &verification.Verification
		result.RustAuthority = append(result.RustAuthority, verification.Authority)
	}
	return result, err
}

type verificationRequest struct {
	PrimaryRuntimeID       string
	AccountID              string
	ObservationID          string
	GraphPageLimit         uint32
	LeaseOwner             string
	Reference              securitypathdelta.Snapshot
	Current                securitypathdelta.Snapshot
	RequestedPathIDs       []string
	ContributingRuntimeIDs []string
}

type verificationResult struct {
	GraphRuns    []RuntimeGraphRun
	Snapshot     securitypathdelta.Snapshot
	Verification securitypathdelta.Verification
	Authority    securitypathdelta.RustAuthorityReceipt
}

func (s *SecurityPathService) collectVerification(ctx context.Context, request verificationRequest) (result verificationResult, runErr error) {
	primaryID := strings.TrimSpace(request.PrimaryRuntimeID)
	contributingRuntimeIDs := normalizedRuntimeIDs(request.ContributingRuntimeIDs)
	refreshSet := make(map[string]struct{}, len(contributingRuntimeIDs)+1)
	refreshSet[primaryID] = struct{}{}
	for _, runtimeID := range contributingRuntimeIDs {
		refreshSet[runtimeID] = struct{}{}
	}
	refreshRuntimeIDs := sortedSet(refreshSet)

	leaseCtx := ctx
	releases := make([]func() error, 0, len(refreshRuntimeIDs)-1)
	for _, runtimeID := range refreshRuntimeIDs {
		if runtimeID == primaryID {
			continue
		}
		acquiredCtx, release, acquired, err := sourceruntime.AcquireRenewableLease(
			leaseCtx, s.deps.LeaseStore, runtimeID, request.LeaseOwner, sourceruntime.DefaultLeaseTTL,
		)
		if err != nil {
			runErr = fmt.Errorf("acquire security path verification lease for %s: %w", runtimeID, err)
			return result, errors.Join(runErr, releaseLeases(releases))
		}
		if !acquired {
			runErr = fmt.Errorf("%w: %s", sourceruntime.ErrSyncInProgress, runtimeID)
			return result, errors.Join(runErr, releaseLeases(releases))
		}
		leaseCtx = acquiredCtx
		releases = append(releases, release)
	}
	defer func() { runErr = errors.Join(runErr, releaseLeases(releases)) }()

	currentRuns := runtimeReceiptRunIDs(request.Current.Receipt.RuntimeReceipts)
	runtimeReceipts := make([]securitypathdelta.RuntimeCollectionReceiptInput, 0, len(refreshRuntimeIDs)-1)
	var primaryReceipt securityPathGraphReceipt
	for _, runtimeID := range refreshRuntimeIDs {
		graphRequest := verificationGraphRequest(runtimeID, request.GraphPageLimit)
		graphResult, err := s.deps.GraphIngest.RunRuntime(leaseCtx, graphRequest)
		if graphResult != nil {
			result.GraphRuns = append(result.GraphRuns, RuntimeGraphRun{RuntimeID: runtimeID, Result: graphResult})
		}
		if err != nil {
			return result, fmt.Errorf("run fresh security path verification collection for %s: %w", runtimeID, err)
		}
		receipt, err := s.graphReceiptForRun(leaseCtx, graphRequest, graphResult, securitypathdelta.CollectionModeGraphResetFullScan)
		if err != nil {
			return result, err
		}
		if receipt.runID == "" || receipt.runID == currentRuns[runtimeID] {
			return result, fmt.Errorf("security path verification requires a distinct graph run for %s", runtimeID)
		}
		if !receipt.runStartedAt.After(request.Current.ObservedAt) {
			return result, fmt.Errorf("security path verification graph collection for %s did not start after the delta observation", runtimeID)
		}
		runtime, err := s.deps.RuntimeStore.GetSourceRuntime(leaseCtx, runtimeID)
		if err != nil {
			return result, fmt.Errorf("read source runtime after verification collection for %s: %w", runtimeID, err)
		}
		if runtimeID == primaryID {
			primaryReceipt = receipt
			continue
		}
		runtimeReceipts = append(runtimeReceipts, runtimeReceiptInput(runtime, receipt))
	}
	primaryRuntime, err := s.deps.RuntimeStore.GetSourceRuntime(leaseCtx, primaryID)
	if err != nil {
		return result, fmt.Errorf("read primary source runtime after verification collection: %w", err)
	}
	result.Snapshot, err = s.captureSnapshot(leaseCtx, snapshotRequest{
		Runtime:                 primaryRuntime,
		AccountID:               request.AccountID,
		ObservationID:           request.ObservationID,
		GraphReceipt:            primaryReceipt,
		LeaseHeld:               true,
		RuntimeReceipts:         runtimeReceipts,
		RequiredProofRuntimeIDs: contributingRuntimeIDs,
	})
	if err != nil {
		return result, err
	}
	if !result.Snapshot.ObservedAt.After(request.Current.ObservedAt) {
		return result, errors.New("security path verification observation did not follow the delta observation")
	}
	result.Verification, result.Authority, err = securitypathdelta.VerifyObservedAbsentRustAuthority(
		leaseCtx,
		request.Reference,
		result.Snapshot,
		request.RequestedPathIDs,
	)
	return result, err
}

func securityPathRuntimeIDs(paths []securitypathdelta.SecurityPath) []string {
	set := map[string]struct{}{}
	for _, path := range paths {
		for _, edge := range path.ProofEdges {
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

func normalizedRuntimeIDs(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	return sortedSet(set)
}

func runtimeReceiptRunIDs(receipts []securitypathdelta.RuntimeCollectionReceipt) map[string]string {
	result := make(map[string]string, len(receipts))
	for _, receipt := range receipts {
		result[strings.TrimSpace(receipt.SourceRuntimeID)] = strings.TrimSpace(receipt.GraphRunID)
	}
	return result
}

func releaseLeases(releases []func() error) error {
	var result error
	for index := len(releases) - 1; index >= 0; index-- {
		result = errors.Join(result, releases[index]())
	}
	return result
}

func orchestrationGraphRequest(runtimeID string, pageLimit uint32) graphingest.RuntimeRequest {
	if pageLimit == 0 {
		pageLimit = graphingest.MaxPageLimit
	}
	return graphingest.RuntimeRequest{
		RuntimeID: strings.TrimSpace(runtimeID), PageLimit: pageLimit,
		ResetCheckpoint: true, Trigger: "platform_orchestration_job", RuntimeLeaseHeld: true, ReconcileMaterialLinks: true,
	}
}

func verificationGraphRequest(runtimeID string, pageLimit uint32) graphingest.RuntimeRequest {
	if pageLimit == 0 {
		pageLimit = graphingest.MaxPageLimit
	}
	return graphingest.RuntimeRequest{
		RuntimeID: strings.TrimSpace(runtimeID), PageLimit: pageLimit,
		CheckpointID: verificationCheckpointID(runtimeID), ResetCheckpoint: true,
		Trigger: "security_path_verification", RuntimeLeaseHeld: true, ReconcileMaterialLinks: true,
	}
}
