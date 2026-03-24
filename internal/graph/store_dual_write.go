package graph

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

type DualWriteMode string

const (
	DualWriteModePrimaryOnly DualWriteMode = "primary_only"
	DualWriteModeBestEffort  DualWriteMode = "best_effort_dual_write"
	DualWriteModeStrict      DualWriteMode = "strict_dual_write"
)

func ParseDualWriteMode(value string) DualWriteMode {
	switch DualWriteMode(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return DualWriteModePrimaryOnly
	case DualWriteModeBestEffort:
		return DualWriteModeBestEffort
	case DualWriteModePrimaryOnly:
		return DualWriteModePrimaryOnly
	case DualWriteModeStrict:
		return DualWriteModeStrict
	default:
		return DualWriteMode(strings.ToLower(strings.TrimSpace(value)))
	}
}

func (m DualWriteMode) Valid() bool {
	switch m {
	case DualWriteModePrimaryOnly, DualWriteModeBestEffort, DualWriteModeStrict:
		return true
	default:
		return false
	}
}

type DualWriteMutationOperation string

const (
	DualWriteMutationUpsertNode       DualWriteMutationOperation = "upsert_node"
	DualWriteMutationUpsertNodesBatch DualWriteMutationOperation = "upsert_nodes_batch"
	DualWriteMutationUpsertEdge       DualWriteMutationOperation = "upsert_edge"
	DualWriteMutationUpsertEdgesBatch DualWriteMutationOperation = "upsert_edges_batch"
	DualWriteMutationDeleteNode       DualWriteMutationOperation = "delete_node"
	DualWriteMutationDeleteEdge       DualWriteMutationOperation = "delete_edge"
)

type DualWriteMutationOutcome struct {
	Mode                   DualWriteMode              `json:"mode"`
	Operation              DualWriteMutationOperation `json:"operation"`
	Identifiers            []string                   `json:"identifiers,omitempty"`
	SecondaryBackend       StoreBackend               `json:"secondary_backend,omitempty"`
	PrimarySucceeded       bool                       `json:"primary_succeeded"`
	PrimaryLatency         time.Duration              `json:"primary_latency,omitempty"`
	PrimaryError           string                     `json:"primary_error,omitempty"`
	SecondaryAttempted     bool                       `json:"secondary_attempted"`
	SecondarySucceeded     bool                       `json:"secondary_succeeded"`
	SecondaryLatency       time.Duration              `json:"secondary_latency,omitempty"`
	SecondaryError         string                     `json:"secondary_error,omitempty"`
	SecondaryRetryable     bool                       `json:"secondary_retryable"`
	ReconciliationEnqueued bool                       `json:"reconciliation_enqueued"`
	ReconciliationError    string                     `json:"reconciliation_error,omitempty"`
}

type DualWriteReconciliationItem struct {
	Operation      DualWriteMutationOperation `json:"operation"`
	Identifiers    []string                   `json:"identifiers,omitempty"`
	Node           *Node                      `json:"node,omitempty"`
	Nodes          []*Node                    `json:"nodes,omitempty"`
	Edge           *Edge                      `json:"edge,omitempty"`
	Edges          []*Edge                    `json:"edges,omitempty"`
	DeleteID       string                     `json:"delete_id,omitempty"`
	TargetBackend  StoreBackend               `json:"target_backend,omitempty"`
	FirstFailureAt time.Time                  `json:"first_failure_at"`
	RetryCount     int                        `json:"retry_count"`
	LastError      string                     `json:"last_error,omitempty"`
	Retryable      bool                       `json:"retryable"`
}

type DualWriteReconciliationQueue interface {
	Enqueue(context.Context, DualWriteReconciliationItem) error
}

type DualWriteGraphStoreOptions struct {
	Mode              DualWriteMode
	SecondaryBackend  StoreBackend
	Queue             DualWriteReconciliationQueue
	Observe           func(context.Context, DualWriteMutationOutcome)
	ClassifyRetryable func(error) bool
}

type DualWriteGraphStore struct {
	GraphStore
	secondary GraphStore
	options   DualWriteGraphStoreOptions
}

var _ GraphStore = (*DualWriteGraphStore)(nil)
var _ TenantScopeAwareGraphStore = (*DualWriteGraphStore)(nil)

func NewDualWriteGraphStore(primary, secondary GraphStore, options DualWriteGraphStoreOptions) GraphStore {
	if primary == nil || secondary == nil {
		return primary
	}
	options.Mode = normalizeDualWriteMode(options.Mode)
	if options.ClassifyRetryable == nil {
		options.ClassifyRetryable = DefaultDualWriteRetryable
	}
	return &DualWriteGraphStore{
		GraphStore: primary,
		secondary:  secondary,
		options:    options,
	}
}

func (s *DualWriteGraphStore) SupportsTenantReadScope() bool {
	if s == nil {
		return false
	}
	return SupportsTenantReadScope(s.GraphStore)
}

func (s *DualWriteGraphStore) UpsertNode(ctx context.Context, node *Node) error {
	return s.applyMutation(ctx, DualWriteMutationUpsertNode, []string{strings.TrimSpace(nodeID(node))}, func(store GraphStore) error {
		return store.UpsertNode(ctx, cloneNode(node))
	}, DualWriteReconciliationItem{
		Operation:   DualWriteMutationUpsertNode,
		Identifiers: []string{strings.TrimSpace(nodeID(node))},
		Node:        cloneNode(node),
	})
}

func (s *DualWriteGraphStore) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	identifiers := dualWriteNodeIDs(nodes)
	return s.applyMutation(ctx, DualWriteMutationUpsertNodesBatch, identifiers, func(store GraphStore) error {
		return store.UpsertNodesBatch(ctx, cloneNodes(nodes))
	}, DualWriteReconciliationItem{
		Operation:   DualWriteMutationUpsertNodesBatch,
		Identifiers: identifiers,
		Nodes:       cloneNodes(nodes),
	})
}

func (s *DualWriteGraphStore) UpsertEdge(ctx context.Context, edge *Edge) error {
	return s.applyMutation(ctx, DualWriteMutationUpsertEdge, []string{strings.TrimSpace(edgeID(edge))}, func(store GraphStore) error {
		return store.UpsertEdge(ctx, cloneEdge(edge))
	}, DualWriteReconciliationItem{
		Operation:   DualWriteMutationUpsertEdge,
		Identifiers: []string{strings.TrimSpace(edgeID(edge))},
		Edge:        cloneEdge(edge),
	})
}

func (s *DualWriteGraphStore) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	identifiers := dualWriteEdgeIDs(edges)
	return s.applyMutation(ctx, DualWriteMutationUpsertEdgesBatch, identifiers, func(store GraphStore) error {
		return store.UpsertEdgesBatch(ctx, cloneEdges(edges))
	}, DualWriteReconciliationItem{
		Operation:   DualWriteMutationUpsertEdgesBatch,
		Identifiers: identifiers,
		Edges:       cloneEdges(edges),
	})
}

func (s *DualWriteGraphStore) DeleteNode(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	return s.applyMutation(ctx, DualWriteMutationDeleteNode, []string{id}, func(store GraphStore) error {
		return store.DeleteNode(ctx, id)
	}, DualWriteReconciliationItem{
		Operation:   DualWriteMutationDeleteNode,
		Identifiers: []string{id},
		DeleteID:    id,
	})
}

func (s *DualWriteGraphStore) DeleteEdge(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	return s.applyMutation(ctx, DualWriteMutationDeleteEdge, []string{id}, func(store GraphStore) error {
		return store.DeleteEdge(ctx, id)
	}, DualWriteReconciliationItem{
		Operation:   DualWriteMutationDeleteEdge,
		Identifiers: []string{id},
		DeleteID:    id,
	})
}

func (s *DualWriteGraphStore) EnsureIndexes(ctx context.Context) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if err := s.GraphStore.EnsureIndexes(ctx); err != nil {
		return err
	}
	return s.secondary.EnsureIndexes(ctx)
}

func ApplyDualWriteReconciliationItem(ctx context.Context, store GraphStore, item DualWriteReconciliationItem) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if store == nil {
		return ErrStoreUnavailable
	}
	switch item.Operation {
	case DualWriteMutationUpsertNode:
		return store.UpsertNode(ctx, cloneNode(item.Node))
	case DualWriteMutationUpsertNodesBatch:
		return store.UpsertNodesBatch(ctx, cloneNodes(item.Nodes))
	case DualWriteMutationUpsertEdge:
		return store.UpsertEdge(ctx, cloneEdge(item.Edge))
	case DualWriteMutationUpsertEdgesBatch:
		return store.UpsertEdgesBatch(ctx, cloneEdges(item.Edges))
	case DualWriteMutationDeleteNode:
		return store.DeleteNode(ctx, strings.TrimSpace(item.DeleteID))
	case DualWriteMutationDeleteEdge:
		return store.DeleteEdge(ctx, strings.TrimSpace(item.DeleteID))
	default:
		return fmt.Errorf("unsupported dual-write reconciliation operation %q", item.Operation)
	}
}

func (s *DualWriteGraphStore) applyMutation(ctx context.Context, operation DualWriteMutationOperation, identifiers []string, apply func(GraphStore) error, item DualWriteReconciliationItem) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	outcome := DualWriteMutationOutcome{
		Mode:             s.options.Mode,
		Operation:        operation,
		Identifiers:      append([]string(nil), identifiers...),
		SecondaryBackend: s.options.SecondaryBackend,
	}

	primaryStarted := time.Now()
	primaryErr := apply(s.GraphStore)
	outcome.PrimaryLatency = time.Since(primaryStarted)
	if primaryErr != nil {
		outcome.PrimaryError = primaryErr.Error()
		s.observe(ctx, outcome)
		return primaryErr
	}
	outcome.PrimarySucceeded = true

	if s.options.Mode == DualWriteModePrimaryOnly {
		s.observe(ctx, outcome)
		return nil
	}

	outcome.SecondaryAttempted = true
	secondaryStarted := time.Now()
	secondaryErr := apply(s.secondary)
	outcome.SecondaryLatency = time.Since(secondaryStarted)
	if secondaryErr == nil {
		outcome.SecondarySucceeded = true
		s.observe(ctx, outcome)
		return nil
	}

	outcome.SecondaryError = secondaryErr.Error()
	outcome.SecondaryRetryable = s.options.ClassifyRetryable(secondaryErr)

	if s.options.Mode == DualWriteModeBestEffort && s.options.Queue != nil {
		queueItem := item
		queueItem.Identifiers = append([]string(nil), identifiers...)
		queueItem.TargetBackend = s.options.SecondaryBackend
		queueItem.FirstFailureAt = time.Now().UTC()
		queueItem.RetryCount = 1
		queueItem.LastError = secondaryErr.Error()
		queueItem.Retryable = outcome.SecondaryRetryable
		if err := s.options.Queue.Enqueue(ctx, queueItem); err != nil {
			outcome.ReconciliationError = err.Error()
		} else {
			outcome.ReconciliationEnqueued = true
		}
	}

	s.observe(ctx, outcome)
	if s.options.Mode == DualWriteModeStrict {
		return fmt.Errorf("dual-write %s secondary backend %q: %w", operation, s.options.SecondaryBackend, secondaryErr)
	}
	return nil
}

func (s *DualWriteGraphStore) observe(ctx context.Context, outcome DualWriteMutationOutcome) {
	if s == nil || s.options.Observe == nil {
		return
	}
	s.options.Observe(ctx, outcome)
}

func normalizeDualWriteMode(mode DualWriteMode) DualWriteMode {
	parsed := ParseDualWriteMode(string(mode))
	if !parsed.Valid() {
		return DualWriteModePrimaryOnly
	}
	return parsed
}

// DefaultDualWriteRetryable classifies transient graph-store errors for dual-write retries.
func DefaultDualWriteRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	type temporary interface{ Temporary() bool }
	var tempErr temporary
	if errors.As(err, &tempErr) {
		return tempErr.Temporary()
	}
	return false
}

func nodeID(node *Node) string {
	if node == nil {
		return ""
	}
	return node.ID
}

func edgeID(edge *Edge) string {
	if edge == nil {
		return ""
	}
	return edge.ID
}

func dualWriteNodeIDs(nodes []*Node) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if id := strings.TrimSpace(nodeID(node)); id != "" {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func dualWriteEdgeIDs(edges []*Edge) []string {
	out := make([]string, 0, len(edges))
	for _, edge := range edges {
		if id := strings.TrimSpace(edgeID(edge)); id != "" {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}
