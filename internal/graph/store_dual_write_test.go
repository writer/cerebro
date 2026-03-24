package graph

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

type dualWriteTestStore struct {
	GraphStore
	failures      map[DualWriteMutationOperation]error
	calls         []DualWriteMutationOperation
	ensureCalls   int
	snapshotCalls int
}

func newDualWriteTestStore() *dualWriteTestStore {
	return &dualWriteTestStore{
		GraphStore: GraphStore(New()),
		failures:   make(map[DualWriteMutationOperation]error),
	}
}

func (s *dualWriteTestStore) record(op DualWriteMutationOperation) error {
	s.calls = append(s.calls, op)
	return s.failures[op]
}

func (s *dualWriteTestStore) UpsertNode(ctx context.Context, node *Node) error {
	if err := s.record(DualWriteMutationUpsertNode); err != nil {
		return err
	}
	return s.GraphStore.UpsertNode(ctx, node)
}

func (s *dualWriteTestStore) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	if err := s.record(DualWriteMutationUpsertNodesBatch); err != nil {
		return err
	}
	return s.GraphStore.UpsertNodesBatch(ctx, nodes)
}

func (s *dualWriteTestStore) UpsertEdge(ctx context.Context, edge *Edge) error {
	if err := s.record(DualWriteMutationUpsertEdge); err != nil {
		return err
	}
	return s.GraphStore.UpsertEdge(ctx, edge)
}

func (s *dualWriteTestStore) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	if err := s.record(DualWriteMutationUpsertEdgesBatch); err != nil {
		return err
	}
	return s.GraphStore.UpsertEdgesBatch(ctx, edges)
}

func (s *dualWriteTestStore) DeleteNode(ctx context.Context, id string) error {
	if err := s.record(DualWriteMutationDeleteNode); err != nil {
		return err
	}
	return s.GraphStore.DeleteNode(ctx, id)
}

func (s *dualWriteTestStore) DeleteEdge(ctx context.Context, id string) error {
	if err := s.record(DualWriteMutationDeleteEdge); err != nil {
		return err
	}
	return s.GraphStore.DeleteEdge(ctx, id)
}

func (s *dualWriteTestStore) EnsureIndexes(ctx context.Context) error {
	s.ensureCalls++
	return s.GraphStore.EnsureIndexes(ctx)
}

func (s *dualWriteTestStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	s.snapshotCalls++
	return s.GraphStore.Snapshot(ctx)
}

type recordingDualWriteQueue struct {
	items []DualWriteReconciliationItem
	err   error
}

func (q *recordingDualWriteQueue) Enqueue(_ context.Context, item DualWriteReconciliationItem) error {
	if q.err != nil {
		return q.err
	}
	q.items = append(q.items, item)
	return nil
}

func TestDualWriteGraphStoreBestEffortEnqueuesRetryableSecondaryMutations(t *testing.T) {
	t.Parallel()

	retryableErr := errors.New("secondary temporarily unavailable")
	ctx := context.Background()

	cases := []struct {
		name        string
		operation   DualWriteMutationOperation
		prepare     func(primary, secondary *dualWriteTestStore)
		apply       func(store GraphStore) error
		identifiers []string
		assert      func(t *testing.T, primary, secondary *dualWriteTestStore)
	}{
		{
			name:      "upsert_node",
			operation: DualWriteMutationUpsertNode,
			apply: func(store GraphStore) error {
				return store.UpsertNode(ctx, contractStoreTestNode("service:payments", NodeKindService, "payments"))
			},
			identifiers: []string{"service:payments"},
			assert: func(t *testing.T, primary, secondary *dualWriteTestStore) {
				t.Helper()
				if _, ok, err := primary.LookupNode(ctx, "service:payments"); err != nil || !ok {
					t.Fatalf("primary node missing after upsert: ok=%v err=%v", ok, err)
				}
				if _, ok, err := secondary.LookupNode(ctx, "service:payments"); err != nil || ok {
					t.Fatalf("secondary node should not persist on failed upsert: ok=%v err=%v", ok, err)
				}
			},
		},
		{
			name:      "upsert_nodes_batch",
			operation: DualWriteMutationUpsertNodesBatch,
			apply: func(store GraphStore) error {
				return store.UpsertNodesBatch(ctx, []*Node{
					contractStoreTestNode("service:payments", NodeKindService, "payments"),
					contractStoreTestNode("service:api", NodeKindService, "api"),
				})
			},
			identifiers: []string{"service:api", "service:payments"},
			assert: func(t *testing.T, primary, secondary *dualWriteTestStore) {
				t.Helper()
				if count, err := primary.CountNodes(ctx); err != nil || count != 2 {
					t.Fatalf("primary node count = %d err=%v, want 2", count, err)
				}
				if count, err := secondary.CountNodes(ctx); err != nil || count != 0 {
					t.Fatalf("secondary node count = %d err=%v, want 0", count, err)
				}
			},
		},
		{
			name:      "upsert_edge",
			operation: DualWriteMutationUpsertEdge,
			prepare: func(primary, secondary *dualWriteTestStore) {
				for _, store := range []*dualWriteTestStore{primary, secondary} {
					_ = store.UpsertNodesBatch(ctx, []*Node{
						contractStoreTestNode("service:api", NodeKindService, "api"),
						contractStoreTestNode("db:payments", NodeKindDatabase, "payments"),
					})
				}
				primary.calls = nil
				secondary.calls = nil
			},
			apply: func(store GraphStore) error {
				return store.UpsertEdge(ctx, contractStoreTestEdge("edge:api:payments", "service:api", "db:payments", EdgeKindCalls))
			},
			identifiers: []string{"edge:api:payments"},
			assert: func(t *testing.T, primary, secondary *dualWriteTestStore) {
				t.Helper()
				if _, ok, err := primary.LookupEdge(ctx, "edge:api:payments"); err != nil || !ok {
					t.Fatalf("primary edge missing after upsert: ok=%v err=%v", ok, err)
				}
				if _, ok, err := secondary.LookupEdge(ctx, "edge:api:payments"); err != nil || ok {
					t.Fatalf("secondary edge should not persist on failed upsert: ok=%v err=%v", ok, err)
				}
			},
		},
		{
			name:      "upsert_edges_batch",
			operation: DualWriteMutationUpsertEdgesBatch,
			prepare: func(primary, secondary *dualWriteTestStore) {
				for _, store := range []*dualWriteTestStore{primary, secondary} {
					_ = store.UpsertNodesBatch(ctx, []*Node{
						contractStoreTestNode("service:api", NodeKindService, "api"),
						contractStoreTestNode("service:worker", NodeKindService, "worker"),
						contractStoreTestNode("db:payments", NodeKindDatabase, "payments"),
					})
				}
				primary.calls = nil
				secondary.calls = nil
			},
			apply: func(store GraphStore) error {
				return store.UpsertEdgesBatch(ctx, []*Edge{
					contractStoreTestEdge("edge:api:payments", "service:api", "db:payments", EdgeKindCalls),
					contractStoreTestEdge("edge:worker:payments", "service:worker", "db:payments", EdgeKindCalls),
				})
			},
			identifiers: []string{"edge:api:payments", "edge:worker:payments"},
			assert: func(t *testing.T, primary, secondary *dualWriteTestStore) {
				t.Helper()
				if count, err := primary.CountEdges(ctx); err != nil || count != 2 {
					t.Fatalf("primary edge count = %d err=%v, want 2", count, err)
				}
				if count, err := secondary.CountEdges(ctx); err != nil || count != 0 {
					t.Fatalf("secondary edge count = %d err=%v, want 0", count, err)
				}
			},
		},
		{
			name:      "delete_node",
			operation: DualWriteMutationDeleteNode,
			prepare: func(primary, secondary *dualWriteTestStore) {
				for _, store := range []*dualWriteTestStore{primary, secondary} {
					_ = store.UpsertNode(ctx, contractStoreTestNode("service:payments", NodeKindService, "payments"))
				}
				primary.calls = nil
				secondary.calls = nil
			},
			apply: func(store GraphStore) error {
				return store.DeleteNode(ctx, "service:payments")
			},
			identifiers: []string{"service:payments"},
			assert: func(t *testing.T, primary, secondary *dualWriteTestStore) {
				t.Helper()
				if _, ok, err := primary.LookupNode(ctx, "service:payments"); err != nil || ok {
					t.Fatalf("primary node should be deleted: ok=%v err=%v", ok, err)
				}
				if _, ok, err := secondary.LookupNode(ctx, "service:payments"); err != nil || !ok {
					t.Fatalf("secondary node should remain after failed delete: ok=%v err=%v", ok, err)
				}
			},
		},
		{
			name:      "delete_edge",
			operation: DualWriteMutationDeleteEdge,
			prepare: func(primary, secondary *dualWriteTestStore) {
				for _, store := range []*dualWriteTestStore{primary, secondary} {
					_ = store.UpsertNodesBatch(ctx, []*Node{
						contractStoreTestNode("service:api", NodeKindService, "api"),
						contractStoreTestNode("db:payments", NodeKindDatabase, "payments"),
					})
					_ = store.UpsertEdge(ctx, contractStoreTestEdge("edge:api:payments", "service:api", "db:payments", EdgeKindCalls))
				}
				primary.calls = nil
				secondary.calls = nil
			},
			apply: func(store GraphStore) error {
				return store.DeleteEdge(ctx, "edge:api:payments")
			},
			identifiers: []string{"edge:api:payments"},
			assert: func(t *testing.T, primary, secondary *dualWriteTestStore) {
				t.Helper()
				if _, ok, err := primary.LookupEdge(ctx, "edge:api:payments"); err != nil || ok {
					t.Fatalf("primary edge should be deleted: ok=%v err=%v", ok, err)
				}
				if _, ok, err := secondary.LookupEdge(ctx, "edge:api:payments"); err != nil || !ok {
					t.Fatalf("secondary edge should remain after failed delete: ok=%v err=%v", ok, err)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			primary := newDualWriteTestStore()
			secondary := newDualWriteTestStore()
			if tc.prepare != nil {
				tc.prepare(primary, secondary)
			}
			secondary.failures[tc.operation] = retryableErr

			queue := &recordingDualWriteQueue{}
			var outcomes []DualWriteMutationOutcome
			store := NewDualWriteGraphStore(primary, secondary, DualWriteGraphStoreOptions{
				Mode:             DualWriteModeBestEffort,
				SecondaryBackend: StoreBackendSpanner,
				Queue:            queue,
				Observe: func(_ context.Context, outcome DualWriteMutationOutcome) {
					outcomes = append(outcomes, outcome)
				},
				ClassifyRetryable: func(err error) bool {
					return errors.Is(err, retryableErr)
				},
			})

			if err := tc.apply(store); err != nil {
				t.Fatalf("mutation returned error in best-effort mode: %v", err)
			}
			if !reflect.DeepEqual(primary.calls, []DualWriteMutationOperation{tc.operation}) {
				t.Fatalf("primary calls = %#v, want %q", primary.calls, tc.operation)
			}
			if !reflect.DeepEqual(secondary.calls, []DualWriteMutationOperation{tc.operation}) {
				t.Fatalf("secondary calls = %#v, want %q", secondary.calls, tc.operation)
			}
			if len(queue.items) != 1 {
				t.Fatalf("queue items = %#v, want 1 item", queue.items)
			}
			if got := queue.items[0]; got.Operation != tc.operation {
				t.Fatalf("queued operation = %q, want %q", got.Operation, tc.operation)
			} else {
				if got.TargetBackend != StoreBackendSpanner {
					t.Fatalf("queued target backend = %q, want %q", got.TargetBackend, StoreBackendSpanner)
				}
				if !got.Retryable {
					t.Fatalf("expected queued mutation to be retryable: %#v", got)
				}
				if got.RetryCount != 1 {
					t.Fatalf("queued retry count = %d, want 1", got.RetryCount)
				}
				if got.FirstFailureAt.IsZero() {
					t.Fatalf("expected first failure timestamp to be set: %#v", got)
				}
				if got.LastError != retryableErr.Error() {
					t.Fatalf("queued last error = %q, want %q", got.LastError, retryableErr.Error())
				}
				if !slices.Equal(got.Identifiers, tc.identifiers) {
					t.Fatalf("queued identifiers = %#v, want %#v", got.Identifiers, tc.identifiers)
				}
			}
			if len(outcomes) != 1 {
				t.Fatalf("outcomes = %#v, want 1", outcomes)
			}
			if outcome := outcomes[0]; outcome.Operation != tc.operation || !outcome.PrimarySucceeded || outcome.SecondarySucceeded {
				t.Fatalf("unexpected outcome = %#v", outcome)
			} else {
				if !outcome.SecondaryAttempted {
					t.Fatalf("expected secondary to be attempted: %#v", outcome)
				}
				if !outcome.SecondaryRetryable {
					t.Fatalf("expected secondary failure to be retryable: %#v", outcome)
				}
				if !outcome.ReconciliationEnqueued {
					t.Fatalf("expected reconciliation enqueue: %#v", outcome)
				}
			}
			tc.assert(t, primary, secondary)
		})
	}
}

func TestDualWriteGraphStoreStrictModeReturnsSecondaryErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	wantErr := errors.New("secondary write failed")
	primary := newDualWriteTestStore()
	secondary := newDualWriteTestStore()
	_ = primary.UpsertNodesBatch(ctx, []*Node{
		contractStoreTestNode("service:api", NodeKindService, "api"),
		contractStoreTestNode("db:payments", NodeKindDatabase, "payments"),
	})
	_ = secondary.UpsertNodesBatch(ctx, []*Node{
		contractStoreTestNode("service:api", NodeKindService, "api"),
		contractStoreTestNode("db:payments", NodeKindDatabase, "payments"),
	})
	primary.calls = nil
	secondary.calls = nil
	secondary.failures[DualWriteMutationUpsertEdge] = wantErr

	var outcomes []DualWriteMutationOutcome
	store := NewDualWriteGraphStore(primary, secondary, DualWriteGraphStoreOptions{
		Mode:             DualWriteModeStrict,
		SecondaryBackend: StoreBackendSpanner,
		Observe: func(_ context.Context, outcome DualWriteMutationOutcome) {
			outcomes = append(outcomes, outcome)
		},
	})

	err := store.UpsertEdge(ctx, contractStoreTestEdge("edge:api:payments", "service:api", "db:payments", EdgeKindCalls))
	if !errors.Is(err, wantErr) {
		t.Fatalf("UpsertEdge() error = %v, want %v", err, wantErr)
	}
	if _, ok, err := primary.LookupEdge(ctx, "edge:api:payments"); err != nil || !ok {
		t.Fatalf("primary edge should persist despite strict secondary failure: ok=%v err=%v", ok, err)
	}
	if len(outcomes) != 1 || outcomes[0].ReconciliationEnqueued {
		t.Fatalf("unexpected strict-mode outcomes = %#v", outcomes)
	}
}

func TestDualWriteGraphStorePrimaryOnlySkipsSecondaryWritesAndUsesPrimaryReads(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	primary := newDualWriteTestStore()
	secondary := newDualWriteTestStore()
	_ = secondary.UpsertNode(ctx, contractStoreTestNode("service:shadow-only", NodeKindService, "shadow-only"))
	secondary.calls = nil

	store := NewDualWriteGraphStore(primary, secondary, DualWriteGraphStoreOptions{
		Mode: DualWriteModePrimaryOnly,
	})

	if err := store.UpsertNode(ctx, contractStoreTestNode("service:primary", NodeKindService, "primary")); err != nil {
		t.Fatalf("UpsertNode() error = %v", err)
	}
	if len(secondary.calls) != 0 {
		t.Fatalf("expected secondary writes to be skipped, calls=%#v", secondary.calls)
	}
	if _, ok, err := store.LookupNode(ctx, "service:primary"); err != nil || !ok {
		t.Fatalf("LookupNode(primary) ok=%v err=%v, want ok", ok, err)
	}
	if _, ok, err := store.LookupNode(ctx, "service:shadow-only"); err != nil || ok {
		t.Fatalf("LookupNode(shadow-only) ok=%v err=%v, want primary-only miss", ok, err)
	}
}

func TestDualWriteGraphStoreEnsureIndexesFansOutToBothBackends(t *testing.T) {
	t.Parallel()

	primary := newDualWriteTestStore()
	secondary := newDualWriteTestStore()
	store := NewDualWriteGraphStore(primary, secondary, DualWriteGraphStoreOptions{
		Mode: DualWriteModePrimaryOnly,
	})

	if err := store.EnsureIndexes(context.Background()); err != nil {
		t.Fatalf("EnsureIndexes() error = %v", err)
	}
	if primary.ensureCalls != 1 || secondary.ensureCalls != 1 {
		t.Fatalf("ensure calls primary=%d secondary=%d, want 1 each", primary.ensureCalls, secondary.ensureCalls)
	}
}

func TestParseDualWriteModeDefaultsToPrimaryOnlyForEmptyAndInvalidValues(t *testing.T) {
	t.Parallel()

	if got := ParseDualWriteMode(""); got != DualWriteModePrimaryOnly {
		t.Fatalf("ParseDualWriteMode(\"\") = %q, want %q", got, DualWriteModePrimaryOnly)
	}
	if got := normalizeDualWriteMode("not-a-mode"); got != DualWriteModePrimaryOnly {
		t.Fatalf("normalizeDualWriteMode(invalid) = %q, want %q", got, DualWriteModePrimaryOnly)
	}
}

func TestNewDualWriteGraphStoreInvalidModeFallsBackToPrimaryOnly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	primary := newDualWriteTestStore()
	secondary := newDualWriteTestStore()
	store := NewDualWriteGraphStore(primary, secondary, DualWriteGraphStoreOptions{
		Mode: "definitely-invalid",
	})

	if err := store.UpsertNode(ctx, contractStoreTestNode("service:payments", NodeKindService, "payments")); err != nil {
		t.Fatalf("UpsertNode() error = %v", err)
	}
	if got := len(secondary.calls); got != 0 {
		t.Fatalf("secondary calls = %#v, want no secondary writes for invalid mode fallback", secondary.calls)
	}
	if _, ok, err := primary.LookupNode(ctx, "service:payments"); err != nil || !ok {
		t.Fatalf("primary node missing after invalid-mode write: ok=%v err=%v", ok, err)
	}
}

func TestApplyDualWriteReconciliationItemReplaysPersistedMutations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name      string
		item      DualWriteReconciliationItem
		assertion func(t *testing.T, store *dualWriteTestStore)
	}{
		{
			name: "upsert_node",
			item: DualWriteReconciliationItem{
				Operation:      DualWriteMutationUpsertNode,
				Identifiers:    []string{"service:payments"},
				Node:           contractStoreTestNode("service:payments", NodeKindService, "payments"),
				FirstFailureAt: time.Date(2026, 3, 23, 22, 0, 0, 0, time.UTC),
			},
			assertion: func(t *testing.T, store *dualWriteTestStore) {
				t.Helper()
				if _, ok, err := store.LookupNode(ctx, "service:payments"); err != nil || !ok {
					t.Fatalf("replayed node missing: ok=%v err=%v", ok, err)
				}
			},
		},
		{
			name: "delete_edge",
			item: DualWriteReconciliationItem{
				Operation:      DualWriteMutationDeleteEdge,
				Identifiers:    []string{"edge:api:payments"},
				DeleteID:       "edge:api:payments",
				FirstFailureAt: time.Date(2026, 3, 23, 22, 0, 0, 0, time.UTC),
			},
			assertion: func(t *testing.T, store *dualWriteTestStore) {
				t.Helper()
				if _, ok, err := store.LookupEdge(ctx, "edge:api:payments"); err != nil || ok {
					t.Fatalf("replayed delete edge should remove edge: ok=%v err=%v", ok, err)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newDualWriteTestStore()
			if tc.item.Operation == DualWriteMutationDeleteEdge {
				_ = store.UpsertNodesBatch(ctx, []*Node{
					contractStoreTestNode("service:api", NodeKindService, "api"),
					contractStoreTestNode("db:payments", NodeKindDatabase, "payments"),
				})
				_ = store.UpsertEdge(ctx, contractStoreTestEdge("edge:api:payments", "service:api", "db:payments", EdgeKindCalls))
				store.calls = nil
			}

			if err := ApplyDualWriteReconciliationItem(ctx, store, tc.item); err != nil {
				t.Fatalf("ApplyDualWriteReconciliationItem() error = %v", err)
			}
			tc.assertion(t, store)
		})
	}
}
