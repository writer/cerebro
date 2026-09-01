package runtimeorchestration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitypathdelta"
	"github.com/writer/cerebro/internal/sourceruntime"
)

func TestCollectVerificationRefreshesEveryContributingRuntime(t *testing.T) {
	now := time.Now().UTC().Add(-2 * time.Minute)
	runtimes := verificationRuntimeStore(now)
	graph := &verificationGraph{now: now, checkpoints: map[string]graphstore.IngestCheckpoint{}}
	leases := &verificationLeaseStore{}
	service := NewSecurityPathService(SecurityPathDependencies{
		AttackPaths: graph, AssertionCoverage: graph, AssertionMigrator: graph,
		GraphIngest: graph, Checkpoints: graph, RuntimeStore: runtimes, LeaseStore: leases,
	})
	reference := verificationReferenceSnapshot(t, now)
	current := verificationCurrentSnapshot(now, map[string]string{"runtime-a": "current-a", "runtime-b": "current-b"})
	contributors := securityPathRuntimeIDs(reference.Paths)
	if !reflect.DeepEqual(contributors, []string{"runtime-a", "runtime-b"}) {
		t.Fatalf("reference contributors = %#v, want selected and duplicate-assertion runtimes", contributors)
	}

	result, err := service.collectVerification(context.Background(), verificationRequest{
		PrimaryRuntimeID: "runtime-a", ObservationID: "job-a:verify", LeaseOwner: "owner-a",
		Reference: reference, Current: current, RequestedPathIDs: []string{reference.Paths[0].ID},
		ContributingRuntimeIDs: contributors,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verification.State != securitypathdelta.VerificationObservedAbsent {
		t.Fatalf("verification = %#v, want observed_absent", result.Verification)
	}
	if got := graph.runtimeOrder(); !reflect.DeepEqual(got, []string{"runtime-a", "runtime-b"}) {
		t.Fatalf("verification runtime order = %#v", got)
	}
	if !reflect.DeepEqual(leases.acquired, []string{"runtime-b"}) || !reflect.DeepEqual(leases.released, []string{"runtime-b"}) {
		t.Fatalf("extra runtime leases acquired=%#v released=%#v", leases.acquired, leases.released)
	}
	for _, request := range graph.requests {
		if !request.ResetCheckpoint || !request.ReconcileMaterialLinks || !request.RuntimeLeaseHeld || request.CheckpointID == "" {
			t.Fatalf("verification graph request = %#v, want leased reset reconciliation", request)
		}
	}
	receiptRuns := map[string]string{}
	for _, receipt := range result.Snapshot.Receipt.RuntimeReceipts {
		receiptRuns[receipt.SourceRuntimeID] = receipt.GraphRunID
		if !receipt.GraphRunStartedAt.After(current.ObservedAt) {
			t.Fatalf("runtime %s receipt started at %s, current observed at %s", receipt.SourceRuntimeID, receipt.GraphRunStartedAt, current.ObservedAt)
		}
	}
	if receiptRuns["runtime-a"] != "fresh-runtime-a" || receiptRuns["runtime-b"] != "fresh-runtime-b" {
		t.Fatalf("fresh runtime receipt runs = %#v", receiptRuns)
	}
}

func TestCollectVerificationStopsBeforeReadsWhenContributorLeaseIsHeld(t *testing.T) {
	now := time.Now().UTC().Add(-2 * time.Minute)
	graph := &verificationGraph{now: now, checkpoints: map[string]graphstore.IngestCheckpoint{}}
	leases := &verificationLeaseStore{blockedRuntime: "runtime-b"}
	service := NewSecurityPathService(SecurityPathDependencies{
		AttackPaths: graph, AssertionCoverage: graph, AssertionMigrator: graph,
		GraphIngest: graph, Checkpoints: graph, RuntimeStore: verificationRuntimeStore(now), LeaseStore: leases,
	})

	_, err := service.collectVerification(context.Background(), verificationRequest{
		PrimaryRuntimeID: "runtime-a", LeaseOwner: "owner-a", Current: verificationCurrentSnapshot(now, nil),
		ContributingRuntimeIDs: []string{"runtime-b"},
	})
	if !errors.Is(err, sourceruntime.ErrSyncInProgress) {
		t.Fatalf("collectVerification() error = %v, want runtime lease conflict", err)
	}
	if len(graph.requests) != 0 {
		t.Fatalf("graph requests = %#v, want none before all contributor leases are held", graph.requests)
	}
}

func TestSecurityPathCaptureRejectsLeaseStoreWithoutFenceReaderBeforeSync(t *testing.T) {
	now := time.Now().UTC().Add(-2 * time.Minute)
	graph := &verificationGraph{now: now, checkpoints: map[string]graphstore.IngestCheckpoint{}}
	leases := &verificationLeaseStore{}
	syncer := &securityPathRuntimeSyncProbe{}
	service := NewSecurityPathService(SecurityPathDependencies{
		AttackPaths: graph, AssertionCoverage: graph, AssertionMigrator: graph,
		GraphIngest: graph, Checkpoints: graph, RuntimeStore: verificationRuntimeStore(now),
		LeaseStore: leases, RuntimeSync: syncer,
	})

	_, err := service.Capture(context.Background(), SecurityPathRequest{
		RuntimeID: "runtime-a", ObservationID: "observation-a", LeaseOwner: "owner-a",
	})
	if !errors.Is(err, sourceruntime.ErrRuntimeUnavailable) {
		t.Fatalf("Capture() error = %v, want %v", err, sourceruntime.ErrRuntimeUnavailable)
	}
	if syncer.syncCalls != 0 {
		t.Fatalf("source runtime sync calls = %d, want 0", syncer.syncCalls)
	}
	if !reflect.DeepEqual(leases.acquired, []string{"runtime-a"}) || !reflect.DeepEqual(leases.released, []string{"runtime-a"}) {
		t.Fatalf("leases acquired=%#v released=%#v, want runtime-a acquired and released", leases.acquired, leases.released)
	}
}

func TestSecurityPathCaptureReadsLeaseGenerationBeforeSync(t *testing.T) {
	now := time.Now().UTC().Add(-2 * time.Minute)
	graph := &verificationGraph{
		now: now, checkpoints: map[string]graphstore.IngestCheckpoint{},
		requests: []graphingest.RuntimeRequest{{RuntimeID: "baseline-ready"}},
	}
	leases := &fencedVerificationLeaseStore{verificationLeaseStore: &verificationLeaseStore{}, generation: 7}
	want := errors.New("stop after fenced sync entry")
	syncer := &securityPathRuntimeSyncProbe{leaseStore: leases, err: want}
	service := NewSecurityPathService(SecurityPathDependencies{
		AttackPaths: graph, AssertionCoverage: graph, AssertionMigrator: graph,
		GraphIngest: graph, Checkpoints: graph, RuntimeStore: verificationRuntimeStore(now),
		LeaseStore: leases, RuntimeSync: syncer,
	})

	_, err := service.Capture(context.Background(), SecurityPathRequest{
		RuntimeID: "runtime-a", ObservationID: "observation-a", LeaseOwner: "owner-a",
	})
	if !errors.Is(err, want) {
		t.Fatalf("Capture() error = %v, want %v", err, want)
	}
	if !leases.fenceRead || leases.readRuntimeID != "runtime-a" || leases.readOwner != "owner-a" {
		t.Fatalf("lease fence read = %t runtime=%q owner=%q, want current runtime owner", leases.fenceRead, leases.readRuntimeID, leases.readOwner)
	}
	if syncer.syncCalls != 1 {
		t.Fatalf("source runtime sync calls = %d, want 1", syncer.syncCalls)
	}
}

type verificationRuntimeMap map[string]*cerebrov1.SourceRuntime

func (s verificationRuntimeMap) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime := s[id]
	if runtime == nil {
		return nil, fmt.Errorf("runtime %s not found", id)
	}
	return runtime, nil
}

func (s verificationRuntimeMap) Ping(context.Context) error { return nil }
func (s verificationRuntimeMap) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func verificationRuntimeStore(now time.Time) verificationRuntimeMap {
	result := verificationRuntimeMap{}
	for _, id := range []string{"runtime-a", "runtime-b"} {
		result[id] = &cerebrov1.SourceRuntime{
			Id: id, SourceId: "aws", TenantId: "tenant-a",
			Config:     map[string]string{"family": "iam_role", "__cerebro_runtime_status": "completed", "__cerebro_runtime_records_rejected": "0"},
			Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-time.Minute))}, LastSyncedAt: timestamppb.New(now.Add(-time.Minute)),
		}
	}
	return result
}

type verificationLeaseStore struct {
	blockedRuntime string
	acquired       []string
	released       []string
}

type fencedVerificationLeaseStore struct {
	*verificationLeaseStore
	generation    uint64
	fenceRead     bool
	readRuntimeID string
	readOwner     string
}

func (s *fencedVerificationLeaseStore) ReadSourceRuntimeLeaseFence(_ context.Context, runtimeID, owner string) (ports.SourceRuntimeLeaseFence, error) {
	s.fenceRead = true
	s.readRuntimeID = runtimeID
	s.readOwner = owner
	return ports.SourceRuntimeLeaseFence{Owner: owner, Generation: s.generation, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

type securityPathRuntimeSyncProbe struct {
	leaseStore *fencedVerificationLeaseStore
	err        error
	syncCalls  int
}

func (s *securityPathRuntimeSyncProbe) Sync(context.Context, *cerebrov1.SyncSourceRuntimeRequest) (*cerebrov1.SyncSourceRuntimeResponse, error) {
	s.syncCalls++
	if s.leaseStore != nil && !s.leaseStore.fenceRead {
		return nil, errors.New("source runtime sync started before the lease fence was read")
	}
	return nil, s.err
}

func (s *securityPathRuntimeSyncProbe) SyncWithLease(context.Context, *cerebrov1.SyncSourceRuntimeRequest, sourceruntime.SyncWithLeaseOptions) (*cerebrov1.SyncSourceRuntimeResponse, error) {
	return nil, errors.New("unexpected SyncWithLease call")
}

func (s *verificationLeaseStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID, _ string, _ time.Duration) (bool, error) {
	s.acquired = append(s.acquired, runtimeID)
	return runtimeID != s.blockedRuntime, nil
}
func (s *verificationLeaseStore) RenewSourceRuntimeLease(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}
func (s *verificationLeaseStore) ReleaseSourceRuntimeLease(_ context.Context, runtimeID, _ string) error {
	s.released = append(s.released, runtimeID)
	return nil
}

type verificationGraph struct {
	now         time.Time
	requests    []graphingest.RuntimeRequest
	checkpoints map[string]graphstore.IngestCheckpoint
}

func (s *verificationGraph) Ping(context.Context) error { return nil }
func (s *verificationGraph) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, ports.ErrGraphEntityNotFound
}
func (s *verificationGraph) ListCloudAttackPaths(_ context.Context, request ports.CloudAttackPathRequest) (*ports.CloudAttackPathResult, error) {
	if len(s.requests) == 0 {
		return nil, errors.New("verification graph collection must precede path query")
	}
	return &ports.CloudAttackPathResult{TenantID: request.TenantID}, nil
}
func (s *verificationGraph) CountProjectedLinksMissingAssertions(context.Context, string, []string) (uint32, error) {
	return 0, nil
}
func (s *verificationGraph) MigrateProjectedLinkAssertions(context.Context, ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	return ports.ProjectionAssertionMigrationResult{}, nil
}
func (s *verificationGraph) RuntimeCheckpointStatus(_ context.Context, request graphingest.RuntimeRequest) (*graphingest.RuntimeCheckpointStatus, error) {
	return &graphingest.RuntimeCheckpointStatus{RuntimeID: request.RuntimeID, SourceID: "aws", TenantID: "tenant-a", CheckpointID: request.CheckpointID, Found: true, Completed: true, CheckpointCurrent: true}, nil
}
func (s *verificationGraph) ListRuns(context.Context, graphstore.IngestRunFilter) (*graphingest.ListResult, error) {
	return &graphingest.ListResult{}, nil
}
func (s *verificationGraph) RunRuntime(_ context.Context, request graphingest.RuntimeRequest) (*graphingest.RunResult, error) {
	s.requests = append(s.requests, request)
	started := s.now.Add(time.Minute)
	s.checkpoints[request.CheckpointID] = graphstore.IngestCheckpoint{ID: request.CheckpointID, SourceID: "aws", TenantID: "tenant-a", ConfigHash: "config-" + request.RuntimeID, Completed: true}
	return &graphingest.RunResult{Run: graphstore.IngestRun{
		ID: "fresh-" + request.RuntimeID, RuntimeID: request.RuntimeID, SourceID: "aws", TenantID: "tenant-a", CheckpointID: request.CheckpointID,
		CheckpointComplete: true, CheckpointCompleteKnown: true, Status: graphstore.IngestRunStatusCompleted,
		MaterialLinkReconciliationRequested: true, MaterialLinkReconciliationSupported: true, MaterialLinkReconciliationCompleted: true,
		StartedAt: started.Format(time.RFC3339Nano), FinishedAt: started.Add(time.Second).Format(time.RFC3339Nano),
	}}, nil
}
func (s *verificationGraph) GetIngestCheckpoint(_ context.Context, id string) (graphstore.IngestCheckpoint, bool, error) {
	checkpoint, ok := s.checkpoints[id]
	return checkpoint, ok, nil
}
func (s *verificationGraph) runtimeOrder() []string {
	result := make([]string, 0, len(s.requests))
	for _, request := range s.requests {
		result = append(result, request.RuntimeID)
	}
	return result
}

func verificationReferenceSnapshot(t *testing.T, now time.Time) securitypathdelta.Snapshot {
	t.Helper()
	path := verificationAttackPath(now)
	snapshot, err := securitypathdelta.NewSnapshot(securitypathdelta.SnapshotInput{
		TenantID: "tenant-a", ScopeID: "source-runtime:runtime-a", DetectorID: securityPathDetectorID, DetectorRevision: securityPathDetectorRevision,
		ObservationID: "job-a:before", ObservedAt: now,
		Receipt: completeReceipt(now, "current-a", []securitypathdelta.RuntimeCollectionReceiptInput{completeRuntimeReceipt(now, "runtime-b", "current-b")}),
		Paths:   []securitypathdelta.ObservedPath{{Path: path}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Completeness.State != securitypathdelta.CompletenessComplete {
		t.Fatalf("reference completeness = %#v", snapshot.Completeness)
	}
	return snapshot
}

func verificationCurrentSnapshot(now time.Time, runIDs map[string]string) securitypathdelta.Snapshot {
	receipts := make([]securitypathdelta.RuntimeCollectionReceipt, 0, len(runIDs))
	for runtimeID, runID := range runIDs {
		receipts = append(receipts, securitypathdelta.RuntimeCollectionReceipt{SourceRuntimeID: runtimeID, GraphRunID: runID})
	}
	return securitypathdelta.Snapshot{ObservedAt: now.Add(10 * time.Second), Receipt: securitypathdelta.CollectionReceipt{RuntimeReceipts: receipts}}
}

func completeReceipt(now time.Time, runID string, runtimeReceipts []securitypathdelta.RuntimeCollectionReceiptInput) securitypathdelta.CollectionReceiptInput {
	return securitypathdelta.CollectionReceiptInput{
		SourceRuntimeID: "runtime-a", SourceID: "aws", ProviderFamily: "iam_role", ConfigRevision: "config-runtime-a",
		RuntimeWatermark: now.Add(-time.Minute), LastSyncedAt: now.Add(-time.Minute), CollectionMode: securitypathdelta.CollectionModeCheckpointed,
		GraphCheckpointID: "checkpoint-a", GraphRunID: runID, GraphRunStartedAt: now.Add(-2 * time.Second), GraphRunFinishedAt: now.Add(-time.Second),
		GraphCheckpointComplete: true, GraphCheckpointCurrent: true, ObservedPathCount: 1, TotalPathCount: 1, LeaseHeld: true, RuntimeReceipts: runtimeReceipts,
	}
}

func completeRuntimeReceipt(now time.Time, runtimeID, runID string) securitypathdelta.RuntimeCollectionReceiptInput {
	return securitypathdelta.RuntimeCollectionReceiptInput{
		SourceRuntimeID: runtimeID, SourceID: "aws", ProviderFamily: "iam_role", ConfigRevision: "config-" + runtimeID,
		RuntimeWatermark: now.Add(-time.Minute), LastSyncedAt: now.Add(-time.Minute), GraphCheckpointID: "checkpoint-" + runtimeID,
		GraphRunID: runID, GraphRunStartedAt: now.Add(-2 * time.Second), GraphRunFinishedAt: now.Add(-time.Second), GraphCheckpointComplete: true, GraphCheckpointCurrent: true,
	}
}

func verificationAttackPath(observedAt time.Time) attackpath.Path {
	public := attackpath.NodeRef{URN: "urn:cerebro:tenant-a:public:internet", EntityType: "public", Label: "internet"}
	resource := attackpath.NodeRef{URN: "urn:cerebro:tenant-a:resource:edge", EntityType: "resource", Label: "edge"}
	account := attackpath.NodeRef{URN: "urn:cerebro:tenant-a:account:prod", EntityType: "cloud.account", Label: "prod"}
	principal := attackpath.NodeRef{URN: "urn:cerebro:tenant-a:principal:role", EntityType: "role", Label: "role"}
	permission := attackpath.NodeRef{URN: "urn:cerebro:tenant-a:permission:admin", EntityType: "policy", Label: "admin"}
	edge := func(from attackpath.NodeRef, relation string, to attackpath.NodeRef, eventID string) attackpath.Edge {
		return attackpath.Edge{From: from, Relation: relation, To: to, Direction: "forward", SourceID: "aws", SourceRuntimeID: "runtime-a", SourceEventID: eventID, ObservedAt: observedAt.Add(-time.Minute)}
	}
	exposure := edge(public, "can_reach", resource, "event-reach")
	exposure.AssertionRuntimeIDs = []string{"runtime-b", "runtime-a"}
	return attackpath.Path{
		PublicPrincipal: public, ExposedResource: resource, CloudAccount: account, Principal: principal, Permission: permission,
		ReachRelation: "can_reach", AccessRelation: "can_admin", RelationChain: []string{"runs_as"},
		ExposureEdge: exposure, ResourceAccountEdge: edge(resource, "belongs_to", account, "event-resource-account"),
		TraversalEdges: []attackpath.Edge{edge(resource, "runs_as", principal, "event-runtime")},
		PrivilegeEdge:  edge(principal, "can_admin", permission, "event-admin"), PermissionAccountEdge: edge(permission, "belongs_to", account, "event-permission-account"),
	}
}
