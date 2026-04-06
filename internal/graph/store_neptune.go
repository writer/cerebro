package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptunedata"
	neptunedatatypes "github.com/aws/aws-sdk-go-v2/service/neptunedata/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/document"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	neptuneNodeLabel = "CerebroNode"
	neptuneEdgeType  = "CEREBRO_EDGE"
)

// NeptuneOpenCypherExecutor abstracts Neptune openCypher execution so the store
// can be tested without talking to a live cluster.
type NeptuneOpenCypherExecutor interface {
	ExecuteOpenCypher(ctx context.Context, query string, params map[string]any) (any, error)
}

type NeptuneDataClient interface {
	ExecuteOpenCypherQuery(ctx context.Context, params *neptunedata.ExecuteOpenCypherQueryInput, optFns ...func(*neptunedata.Options)) (*neptunedata.ExecuteOpenCypherQueryOutput, error)
	ExecuteOpenCypherExplainQuery(ctx context.Context, params *neptunedata.ExecuteOpenCypherExplainQueryInput, optFns ...func(*neptunedata.Options)) (*neptunedata.ExecuteOpenCypherExplainQueryOutput, error)
}

type neptuneDataClient = NeptuneDataClient

type neptuneDataExecutor struct {
	client neptuneDataClient
	retry  neptuneRetryOptions
	sleep  func(context.Context, time.Duration) error
}

type neptuneRetryOptions struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
}

// NewNeptuneDataExecutor adapts the official Neptune Data API client to the
// executor interface used by NeptuneGraphStore.
func NewNeptuneDataExecutor(client neptuneDataClient) NeptuneOpenCypherExecutor {
	return &neptuneDataExecutor{
		client: client,
		retry:  defaultNeptuneRetryOptions(),
		sleep:  neptuneSleepWithContext,
	}
}

func (e *neptuneDataExecutor) ExecuteOpenCypher(ctx context.Context, query string, params map[string]any) (any, error) {
	if e == nil || e.client == nil {
		return nil, ErrStoreUnavailable
	}
	input := &neptunedata.ExecuteOpenCypherQueryInput{
		OpenCypherQuery: aws.String(query),
	}
	if len(params) > 0 {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal neptune parameters: %w", err)
		}
		input.Parameters = aws.String(string(encoded))
	}
	return neptuneExecuteWithRetry(ctx, e.retry, e.sleep, func() (any, error) {
		output, err := e.client.ExecuteOpenCypherQuery(ctx, input)
		if err != nil {
			return nil, err
		}
		if output == nil {
			return nil, nil
		}
		return neptuneDecodeExecuteResults(output.Results)
	})
}

func (e *neptuneDataExecutor) ExecuteOpenCypherExplain(ctx context.Context, query string, mode NeptuneExplainMode, params map[string]any) ([]byte, error) {
	if e == nil || e.client == nil {
		return nil, ErrStoreUnavailable
	}
	input := &neptunedata.ExecuteOpenCypherExplainQueryInput{
		OpenCypherQuery: aws.String(strings.TrimSpace(query)),
		ExplainMode:     neptunedatatypes.OpenCypherExplainMode(mode),
	}
	if len(params) > 0 {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal neptune explain parameters: %w", err)
		}
		input.Parameters = aws.String(string(encoded))
	}
	return neptuneExecuteWithRetry(ctx, e.retry, e.sleep, func() ([]byte, error) {
		output, err := e.client.ExecuteOpenCypherExplainQuery(ctx, input)
		if err != nil {
			return nil, err
		}
		if output == nil {
			return nil, nil
		}
		return output.Results, nil
	})
}

func defaultNeptuneRetryOptions() neptuneRetryOptions {
	return neptuneRetryOptions{
		Attempts:  4,
		BaseDelay: 200 * time.Millisecond,
		MaxDelay:  2 * time.Second,
	}
}

func neptuneDecodeExecuteResults(results any) (any, error) {
	if results == nil {
		return nil, nil
	}
	unmarshaler, ok := results.(document.Unmarshaler)
	if !ok {
		return results, nil
	}
	var decoded any
	if err := unmarshaler.UnmarshalSmithyDocument(&decoded); err != nil {
		return nil, fmt.Errorf("unmarshal neptune results: %w", err)
	}
	return neptuneNormalizeValue(decoded), nil
}

func normalizeNeptuneRetryOptions(opts neptuneRetryOptions) neptuneRetryOptions {
	defaults := defaultNeptuneRetryOptions()
	if opts.Attempts <= 0 {
		opts.Attempts = defaults.Attempts
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = defaults.BaseDelay
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = defaults.MaxDelay
	}
	if opts.MaxDelay < opts.BaseDelay {
		opts.MaxDelay = opts.BaseDelay
	}
	return opts
}

func neptuneExecuteWithRetry[T any](ctx context.Context, opts neptuneRetryOptions, sleep func(context.Context, time.Duration) error, op func() (T, error)) (T, error) {
	options := normalizeNeptuneRetryOptions(opts)
	if sleep == nil {
		sleep = neptuneSleepWithContext
	}

	var zero T
	var lastValue T
	for attempt := 1; attempt <= options.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return lastValue, err
		}
		value, err := op()
		lastValue = value
		if err == nil {
			return value, nil
		}
		if attempt == options.Attempts || !isRetryableNeptuneError(err) {
			return lastValue, err
		}
		if err := sleep(ctx, neptuneRetryDelay(attempt, options)); err != nil {
			return zero, err
		}
	}

	return lastValue, nil
}

func neptuneRetryDelay(attempt int, opts neptuneRetryOptions) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 30 {
		shift = 30
	}
	delay := opts.BaseDelay * time.Duration(1<<shift)
	if delay > opts.MaxDelay {
		return opts.MaxDelay
	}
	return delay
}

func isRetryableNeptuneError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return isNeptuneThrottleError(err) || isNeptuneServiceUnavailableError(err) || isRetryableNeptuneNetworkError(err)
}

func isNeptuneThrottleError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(strings.TrimSpace(apiErr.ErrorCode()))
		if strings.Contains(code, "throttl") ||
			strings.Contains(code, "toomanyrequests") ||
			code == "requestlimitexceeded" ||
			code == "slowdown" {
			return true
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == 429
	}

	return false
}

func isNeptuneServiceUnavailableError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(strings.TrimSpace(apiErr.ErrorCode()))
		switch code {
		case "internalfailure",
			"internalserverexception",
			"serviceunavailable",
			"temporarilyunavailable",
			"requesttimeout",
			"requesttimeoutexception":
			return true
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.HTTPStatusCode() {
		case 500, 502, 503, 504:
			return true
		}
	}

	return false
}

func isRetryableNeptuneNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	normalized := strings.ToLower(strings.TrimSpace(err.Error()))
	for _, token := range []string{
		"timeout",
		"timed out",
		"temporary unavailable",
		"temporarily unavailable",
		"connection reset",
		"connection refused",
		"connection closed",
		"broken pipe",
		"eof",
		"service unavailable",
		"net/http: tls handshake timeout",
	} {
		if strings.Contains(normalized, token) {
			return true
		}
	}

	return false
}

func neptuneSleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// NeptuneGraphStore persists graph records in Amazon Neptune via the
// openCypher data API. Traversal-oriented operations query Neptune for the
// bounded neighborhood needed by the analysis instead of materializing the
// entire graph.
type NeptuneGraphStore struct {
	exec NeptuneOpenCypherExecutor
}

type NeptuneExplainMode string

const (
	NeptuneExplainModeStatic  NeptuneExplainMode = "static"
	NeptuneExplainModeDynamic NeptuneExplainMode = "dynamic"
	NeptuneExplainModeDetails NeptuneExplainMode = "details"
)

type NeptuneQueryPlanOperator struct {
	ID            int
	DownstreamIDs []int
	Name          string
	Arguments     string
	Mode          string
	UnitsIn       int
	UnitsOut      int
	Ratio         float64
	TimeMillis    float64
	Children      []*NeptuneQueryPlanOperator
}

type NeptuneQueryHotspot struct {
	OperatorID     int
	OperatorName   string
	Severity       string
	Reason         string
	TimeMillis     float64
	UnitsIn        int
	UnitsOut       int
	Ratio          float64
	Recommendation string
}

type NeptuneQueryAnalysis struct {
	Mode            NeptuneExplainMode
	Query           string
	Operators       []*NeptuneQueryPlanOperator
	PlanRoots       []*NeptuneQueryPlanOperator
	Hotspots        []NeptuneQueryHotspot
	Recommendations []string
	TotalTimeMillis float64
}

type neptuneExplainExecutor interface {
	ExecuteOpenCypherExplain(ctx context.Context, query string, mode NeptuneExplainMode, params map[string]any) ([]byte, error)
}

var _ GraphStore = (*NeptuneGraphStore)(nil)

func NewNeptuneGraphStore(exec NeptuneOpenCypherExecutor) *NeptuneGraphStore {
	return &NeptuneGraphStore{exec: exec}
}

func (s *NeptuneGraphStore) ExplainQuery(ctx context.Context, query string, params map[string]any, mode NeptuneExplainMode) (*NeptuneQueryAnalysis, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.exec == nil {
		return nil, ErrStoreUnavailable
	}
	explainer, ok := s.exec.(neptuneExplainExecutor)
	if !ok {
		return nil, fmt.Errorf("neptune executor does not support explain queries")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("neptune explain query is empty")
	}
	if mode == "" {
		mode = NeptuneExplainModeDynamic
	}
	raw, err := explainer.ExecuteOpenCypherExplain(ctx, query, mode, params)
	if err != nil {
		return nil, err
	}
	analysis, err := AnalyzeNeptuneExplainOutput(raw, mode)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(analysis.Query) == "" {
		analysis.Query = query
	}
	return analysis, nil
}

func (s *NeptuneGraphStore) ProfileQuery(ctx context.Context, query string, params map[string]any) (*NeptuneQueryAnalysis, error) {
	return s.ExplainQuery(ctx, query, params, NeptuneExplainModeDetails)
}

func (s *NeptuneGraphStore) UpsertNode(ctx context.Context, node *Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return nil
	}
	if err := s.validateNodeWrite(node); err != nil {
		return err
	}
	_, err := s.exec.ExecuteOpenCypher(ctx, neptuneUpsertNodeQuery, neptuneNodeParams(node))
	return err
}

func (s *NeptuneGraphStore) UpsertNodesBatch(ctx context.Context, nodes []*Node) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	for _, node := range nodes {
		if node == nil || strings.TrimSpace(node.ID) == "" {
			continue
		}
		if err := s.validateNodeWrite(node); err != nil {
			return err
		}
	}
	params := neptuneBatchNodeParams(nodes)
	if len(params) == 0 {
		return nil
	}
	_, err := s.exec.ExecuteOpenCypher(ctx, neptuneUpsertNodesBatchQuery, params)
	return err
}

func (s *NeptuneGraphStore) UpsertEdge(ctx context.Context, edge *Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	if edge == nil || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
		return nil
	}
	if err := s.validateEdgeWrite(ctx, edge); err != nil {
		return err
	}
	_, err := s.exec.ExecuteOpenCypher(ctx, neptuneUpsertEdgeQuery, neptuneEdgeParams(edge))
	return err
}

func (s *NeptuneGraphStore) UpsertEdgesBatch(ctx context.Context, edges []*Edge) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	// Track batch-local cardinality offsets so edges within the same batch
	// are counted toward cardinality limits of subsequent edges.
	type cardinalityKey struct {
		nodeID string
		kind   EdgeKind
	}
	outOffsets := make(map[cardinalityKey]int)
	inOffsets := make(map[cardinalityKey]int)
	for _, edge := range edges {
		if edge == nil || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
			continue
		}
		// Canonicalize key fields so whitespace variants resolve to the same
		// cardinality bucket that schema validation uses after trimming.
		canonicalKind := EdgeKind(strings.TrimSpace(string(edge.Kind)))
		outKey := cardinalityKey{nodeID: strings.TrimSpace(edge.Source), kind: canonicalKind}
		inKey := cardinalityKey{nodeID: strings.TrimSpace(edge.Target), kind: canonicalKind}
		if err := s.validateEdgeWriteWithOffsets(ctx, edge, outOffsets[outKey], inOffsets[inKey]); err != nil {
			return err
		}
		outOffsets[outKey]++
		inOffsets[inKey]++
	}
	params := neptuneBatchEdgeParams(edges)
	if len(params) == 0 {
		return nil
	}
	_, err := s.exec.ExecuteOpenCypher(ctx, neptuneUpsertEdgesBatchQuery, params)
	return err
}

func (s *NeptuneGraphStore) validateNodeWrite(node *Node) error {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return nil
	}
	if issues := ValidateNodeAgainstSchema(node); len(issues) > 0 {
		return &SchemaValidationError{Issues: issues}
	}
	return nil
}

func (s *NeptuneGraphStore) validateEdgeWrite(ctx context.Context, edge *Edge) error {
	return s.validateEdgeWriteWithOffsets(ctx, edge, 0, 0)
}

// validateEdgeWriteWithOffsets validates an edge write with additional
// cardinality offsets to account for pending edges in a batch that have
// already passed validation but are not yet persisted.
func (s *NeptuneGraphStore) validateEdgeWriteWithOffsets(ctx context.Context, edge *Edge, outOffset, inOffset int) error {
	if edge == nil || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
		return nil
	}

	// Canonicalize identity fields so cardinality counting matches the
	// normalization used by schema validation and persistence.
	canonicalSource := strings.TrimSpace(edge.Source)
	canonicalTarget := strings.TrimSpace(edge.Target)
	canonicalKind := EdgeKind(strings.TrimSpace(string(edge.Kind)))

	source, _, err := s.LookupNode(ctx, canonicalSource)
	if err != nil {
		return err
	}
	target, _, err := s.LookupNode(ctx, canonicalTarget)
	if err != nil {
		return err
	}
	issues := ValidateEdgeAgainstSchema(edge, source, target)
	if len(issues) == 0 {
		outEdges, err := s.LookupOutEdges(ctx, canonicalSource)
		if err != nil {
			return err
		}
		inEdges, err := s.LookupInEdges(ctx, canonicalTarget)
		if err != nil {
			return err
		}
		issues = append(issues, ValidateEdgeCardinalityAgainstSchema(
			edge,
			source,
			target,
			countActiveEdgesByKind(outEdges, canonicalKind, strings.TrimSpace(edge.ID))+outOffset,
			countActiveEdgesByKind(inEdges, canonicalKind, strings.TrimSpace(edge.ID))+inOffset,
		)...)
	}
	if len(issues) > 0 {
		return &SchemaValidationError{Issues: issues}
	}
	return nil
}

func countActiveEdgesByKind(edges []*Edge, kind EdgeKind, excludeEdgeID string) int {
	count := 0
	for _, edge := range edges {
		if edge == nil || edge.DeletedAt != nil || edge.Kind != kind {
			continue
		}
		if excludeEdgeID != "" && edge.ID == excludeEdgeID {
			continue
		}
		count++
	}
	return count
}

func (s *NeptuneGraphStore) DeleteNode(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	if strings.TrimSpace(id) == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.exec.ExecuteOpenCypher(ctx, neptuneDeleteNodeQuery, map[string]any{
		"id":         strings.TrimSpace(id),
		"deleted_at": now,
	}); err != nil {
		return err
	}
	_, err := s.exec.ExecuteOpenCypher(ctx, neptuneDeleteNodeEdgesQuery, map[string]any{
		"id":         strings.TrimSpace(id),
		"deleted_at": now,
	})
	return err
}

func (s *NeptuneGraphStore) DeleteEdge(ctx context.Context, id string) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	if strings.TrimSpace(id) == "" {
		return nil
	}
	_, err := s.exec.ExecuteOpenCypher(ctx, neptuneDeleteEdgeQuery, map[string]any{
		"id":         strings.TrimSpace(id),
		"deleted_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
	return err
}

func (s *NeptuneGraphStore) LookupNode(ctx context.Context, id string) (*Node, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.exec == nil {
		return nil, false, ErrStoreUnavailable
	}
	rows, err := s.queryRows(ctx, neptuneLookupNodeQuery, map[string]any{"id": strings.TrimSpace(id)})
	if err != nil {
		return nil, false, err
	}
	record, ok := neptuneAliasedRecord(rows, "node")
	if !ok {
		return nil, false, nil
	}
	node, err := neptuneDecodeNode(record)
	if err != nil {
		return nil, false, err
	}
	return node, node != nil, nil
}

func (s *NeptuneGraphStore) LookupEdge(ctx context.Context, id string) (*Edge, bool, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, false, err
	}
	if s == nil || s.exec == nil {
		return nil, false, ErrStoreUnavailable
	}
	rows, err := s.queryRows(ctx, neptuneLookupEdgeQuery, map[string]any{"id": strings.TrimSpace(id)})
	if err != nil {
		return nil, false, err
	}
	record, ok := neptuneAliasedRecord(rows, "edge")
	if !ok {
		return nil, false, nil
	}
	edge, err := neptuneDecodeEdge(record)
	if err != nil {
		return nil, false, err
	}
	return edge, edge != nil, nil
}

func (s *NeptuneGraphStore) LookupOutEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	return s.lookupEdges(ctx, neptuneLookupOutEdgesQuery, map[string]any{"node_id": strings.TrimSpace(nodeID)})
}

func (s *NeptuneGraphStore) LookupInEdges(ctx context.Context, nodeID string) ([]*Edge, error) {
	return s.lookupEdges(ctx, neptuneLookupInEdgesQuery, map[string]any{"node_id": strings.TrimSpace(nodeID)})
}

func (s *NeptuneGraphStore) LookupOutEdgesBitemporal(ctx context.Context, nodeID string, validAt, recordedAt time.Time) ([]*Edge, error) {
	return s.lookupEdges(ctx, neptuneLookupOutEdgesBitemporalQuery, map[string]any{
		"node_id":     strings.TrimSpace(nodeID),
		"valid_at":    storeTimeParam(validAt),
		"recorded_at": storeTimeParam(recordedAt),
	})
}

func (s *NeptuneGraphStore) LookupInEdgesBitemporal(ctx context.Context, nodeID string, validAt, recordedAt time.Time) ([]*Edge, error) {
	return s.lookupEdges(ctx, neptuneLookupInEdgesBitemporalQuery, map[string]any{
		"node_id":     strings.TrimSpace(nodeID),
		"valid_at":    storeTimeParam(validAt),
		"recorded_at": storeTimeParam(recordedAt),
	})
}

func (s *NeptuneGraphStore) LookupOutEdgesBetween(ctx context.Context, nodeID string, from, to time.Time) ([]*Edge, error) {
	return s.lookupEdges(ctx, neptuneLookupOutEdgesBetweenQuery, map[string]any{
		"node_id": strings.TrimSpace(nodeID),
		"from":    storeTimeParam(from),
		"to":      storeTimeParam(to),
	})
}

func (s *NeptuneGraphStore) LookupInEdgesBetween(ctx context.Context, nodeID string, from, to time.Time) ([]*Edge, error) {
	return s.lookupEdges(ctx, neptuneLookupInEdgesBetweenQuery, map[string]any{
		"node_id": strings.TrimSpace(nodeID),
		"from":    storeTimeParam(from),
		"to":      storeTimeParam(to),
	})
}

func (s *NeptuneGraphStore) LookupNodesByKind(ctx context.Context, kinds ...NodeKind) ([]*Node, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.exec == nil {
		return nil, ErrStoreUnavailable
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	rawKinds := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		trimmed := strings.TrimSpace(string(kind))
		if trimmed != "" {
			rawKinds = append(rawKinds, trimmed)
		}
	}
	if len(rawKinds) == 0 {
		return nil, nil
	}
	rows, err := s.queryRows(ctx, neptuneLookupNodesByKindQuery, map[string]any{"kinds": rawKinds})
	if err != nil {
		return nil, err
	}
	nodes := make([]*Node, 0, len(rows))
	for _, row := range rows {
		record, ok := neptuneNestedRecord(row, "node")
		if !ok {
			continue
		}
		node, err := neptuneDecodeNode(record)
		if err != nil {
			return nil, err
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

func (s *NeptuneGraphStore) CountNodes(ctx context.Context) (int, error) {
	return s.countQuery(ctx, neptuneCountNodesQuery)
}

func (s *NeptuneGraphStore) CountEdges(ctx context.Context) (int, error) {
	return s.countQuery(ctx, neptuneCountEdgesQuery)
}

func (s *NeptuneGraphStore) EnsureIndexes(ctx context.Context) error {
	if err := graphStoreContextErr(ctx); err != nil {
		return err
	}
	if s == nil || s.exec == nil {
		return ErrStoreUnavailable
	}
	// Neptune openCypher does not support CREATE INDEX DDL.
	return nil
}

func (s *NeptuneGraphStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.exec == nil {
		return nil, ErrStoreUnavailable
	}
	nodeRows, err := s.queryRows(ctx, neptuneSnapshotNodesQuery, nil)
	if err != nil {
		return nil, err
	}
	nodes := make([]*Node, 0, len(nodeRows))
	for _, row := range nodeRows {
		record, ok := neptuneNestedRecord(row, "node")
		if !ok {
			continue
		}
		node, err := neptuneDecodeNode(record)
		if err != nil {
			return nil, err
		}
		if node == nil {
			continue
		}
		if node.DeletedAt != nil {
			continue
		}
		nodes = append(nodes, node)
	}
	edgeRows, err := s.queryRows(ctx, neptuneSnapshotEdgesQuery, nil)
	if err != nil {
		return nil, err
	}
	edges := make([]*Edge, 0, len(edgeRows))
	for _, row := range edgeRows {
		record, ok := neptuneNestedRecord(row, "edge")
		if !ok {
			continue
		}
		edge, err := neptuneDecodeEdge(record)
		if err != nil {
			return nil, err
		}
		if edge == nil {
			continue
		}
		if edge.DeletedAt != nil {
			continue
		}
		edges = append(edges, edge)
	}
	return &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: time.Now().UTC(),
		Metadata: Metadata{
			BuiltAt:   time.Now().UTC(),
			NodeCount: len(nodes),
			EdgeCount: len(edges),
		},
		Nodes: nodes,
		Edges: edges,
	}, nil
}

func (s *NeptuneGraphStore) BlastRadius(ctx context.Context, principalID string, maxDepth int) (*BlastRadiusResult, error) {
	view, err := s.traversalGraph(ctx, principalID, neptuneTraversalDirectionOutgoing, normalizeTraversalDepth(maxDepth))
	if err != nil {
		return nil, err
	}
	return view.BlastRadius(ctx, principalID, maxDepth)
}

func (s *NeptuneGraphStore) ReverseAccess(ctx context.Context, resourceID string, maxDepth int) (*ReverseAccessResult, error) {
	view, err := s.traversalGraph(ctx, resourceID, neptuneTraversalDirectionIncoming, normalizeTraversalDepth(maxDepth))
	if err != nil {
		return nil, err
	}
	return view.ReverseAccess(ctx, resourceID, maxDepth)
}

func (s *NeptuneGraphStore) EffectiveAccess(ctx context.Context, principalID, resourceID string, maxDepth int) (*EffectiveAccessResult, error) {
	view, err := s.traversalGraph(ctx, principalID, neptuneTraversalDirectionOutgoing, normalizeTraversalDepth(maxDepth))
	if err != nil {
		return nil, err
	}
	return view.EffectiveAccess(ctx, principalID, resourceID, maxDepth)
}

func (s *NeptuneGraphStore) CascadingBlastRadius(ctx context.Context, sourceID string, maxDepth int) (*CascadingBlastRadiusResult, error) {
	view, err := s.traversalGraph(ctx, sourceID, neptuneTraversalDirectionOutgoing, normalizeTraversalDepthWithDefault(maxDepth, defaultExtractSubgraphMaxDepth))
	if err != nil {
		return nil, err
	}
	return view.CascadingBlastRadius(ctx, sourceID, maxDepth)
}

func (s *NeptuneGraphStore) ExtractSubgraph(ctx context.Context, rootID string, opts ExtractSubgraphOptions) (*Graph, error) {
	view, err := s.traversalGraph(ctx, rootID, neptuneTraversalDirectionFromExtractSubgraph(opts.Direction), normalizeTraversalDepthWithDefault(opts.MaxDepth, defaultExtractSubgraphMaxDepth))
	if err != nil {
		return nil, err
	}
	return view.ExtractSubgraph(ctx, rootID, opts)
}

func (s *NeptuneGraphStore) ExtractSubgraphBitemporal(ctx context.Context, rootID string, opts ExtractSubgraphOptions, validAt, recordedAt time.Time) (*Graph, error) {
	view, err := s.temporalTraversalGraph(ctx, rootID, neptuneTraversalDirectionFromExtractSubgraph(opts.Direction), normalizeTraversalDepthWithDefault(opts.MaxDepth, defaultExtractSubgraphMaxDepth), map[string]any{
		"root_id":     strings.TrimSpace(rootID),
		"valid_at":    storeTimeParam(validAt),
		"recorded_at": storeTimeParam(recordedAt),
	}, neptuneTemporalBitemporalTraversalNodeQuery, neptuneTemporalBitemporalTraversalEdgeQuery)
	if err != nil {
		return nil, err
	}
	return view.ExtractSubgraph(ctx, rootID, opts)
}

func (s *NeptuneGraphStore) ExtractSubgraphBetween(ctx context.Context, rootID string, opts ExtractSubgraphOptions, from, to time.Time) (*Graph, error) {
	view, err := s.temporalTraversalGraph(ctx, rootID, neptuneTraversalDirectionFromExtractSubgraph(opts.Direction), normalizeTraversalDepthWithDefault(opts.MaxDepth, defaultExtractSubgraphMaxDepth), map[string]any{
		"root_id": strings.TrimSpace(rootID),
		"from":    storeTimeParam(from),
		"to":      storeTimeParam(to),
	}, neptuneTemporalRangeTraversalNodeQuery, neptuneTemporalRangeTraversalEdgeQuery)
	if err != nil {
		return nil, err
	}
	return view.ExtractSubgraph(ctx, rootID, opts)
}

func (s *NeptuneGraphStore) lookupEdges(ctx context.Context, query string, params map[string]any) ([]*Edge, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.exec == nil {
		return nil, ErrStoreUnavailable
	}
	rows, err := s.queryRows(ctx, query, params)
	if err != nil {
		return nil, err
	}
	edges := make([]*Edge, 0, len(rows))
	for _, row := range rows {
		record, ok := neptuneNestedRecord(row, "edge")
		if !ok {
			continue
		}
		edge, err := neptuneDecodeEdge(record)
		if err != nil {
			return nil, err
		}
		if edge != nil {
			edges = append(edges, edge)
		}
	}
	return edges, nil
}

func (s *NeptuneGraphStore) countQuery(ctx context.Context, query string) (int, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return 0, err
	}
	if s == nil || s.exec == nil {
		return 0, ErrStoreUnavailable
	}
	rows, err := s.queryRows(ctx, query, nil)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return neptuneInt(rows[0]["total"]), nil
}

func (s *NeptuneGraphStore) traversalGraph(ctx context.Context, rootID string, direction neptuneTraversalDirection, maxDepth int) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.exec == nil {
		return nil, ErrStoreUnavailable
	}
	rootID = strings.TrimSpace(rootID)
	if rootID == "" {
		return New(), nil
	}

	nodeRows, err := s.queryRows(ctx, neptuneTraversalNodesQuery(direction, maxDepth), map[string]any{"root_id": rootID})
	if err != nil {
		return nil, err
	}
	view := New()
	for _, row := range nodeRows {
		record, ok := neptuneNestedRecord(row, "node")
		if !ok {
			continue
		}
		node, err := neptuneDecodeNode(record)
		if err != nil {
			return nil, err
		}
		if node != nil {
			view.AddNode(node)
		}
	}

	edgeRows, err := s.queryRows(ctx, neptuneTraversalEdgesQuery(direction, maxDepth), map[string]any{"root_id": rootID})
	if err != nil {
		return nil, err
	}
	for _, row := range edgeRows {
		record, ok := neptuneNestedRecord(row, "edge")
		if !ok {
			continue
		}
		edge, err := neptuneDecodeEdge(record)
		if err != nil {
			return nil, err
		}
		if edge == nil {
			continue
		}
		if _, ok := view.GetNode(edge.Source); !ok {
			continue
		}
		if _, ok := view.GetNode(edge.Target); !ok {
			continue
		}
		view.AddEdge(edge)
	}
	return view, nil
}

func (s *NeptuneGraphStore) temporalTraversalGraph(
	ctx context.Context,
	rootID string,
	direction neptuneTraversalDirection,
	maxDepth int,
	params map[string]any,
	nodeQuery func(neptuneTraversalDirection, int) string,
	edgeQuery func(neptuneTraversalDirection, int) string,
) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.exec == nil {
		return nil, ErrStoreUnavailable
	}
	rootID = strings.TrimSpace(rootID)
	if rootID == "" {
		return New(), nil
	}
	if params == nil {
		params = map[string]any{}
	}
	params["root_id"] = rootID

	nodeRows, err := s.queryRows(ctx, nodeQuery(direction, maxDepth), params)
	if err != nil {
		return nil, err
	}
	view := New()
	for _, row := range nodeRows {
		record, ok := neptuneNestedRecord(row, "node")
		if !ok {
			continue
		}
		node, err := neptuneDecodeNode(record)
		if err != nil {
			return nil, err
		}
		if node != nil {
			view.AddNode(node)
		}
	}

	edgeRows, err := s.queryRows(ctx, edgeQuery(direction, maxDepth), params)
	if err != nil {
		return nil, err
	}
	for _, row := range edgeRows {
		record, ok := neptuneNestedRecord(row, "edge")
		if !ok {
			continue
		}
		edge, err := neptuneDecodeEdge(record)
		if err != nil {
			return nil, err
		}
		if edge == nil {
			continue
		}
		if _, ok := view.GetNode(edge.Source); !ok {
			continue
		}
		if _, ok := view.GetNode(edge.Target); !ok {
			continue
		}
		view.AddEdge(edge)
	}
	return view, nil
}

func (s *NeptuneGraphStore) queryRows(ctx context.Context, query string, params map[string]any) ([]map[string]any, error) {
	results, err := s.exec.ExecuteOpenCypher(ctx, query, neptuneTenantScopedParams(ctx, params))
	if err != nil {
		return nil, err
	}
	return neptuneRows(results)
}

func neptuneTenantScopedParams(ctx context.Context, params map[string]any) map[string]any {
	scoped := make(map[string]any, len(params)+2)
	for key, value := range params {
		scoped[key] = value
	}
	tenantIDs := neptuneTenantIDsFromContext(ctx)
	scoped["tenant_scope_disabled"] = len(tenantIDs) == 0
	scoped["tenant_ids"] = tenantIDs
	return scoped
}

func neptuneTenantIDsFromContext(ctx context.Context) []string {
	scope, ok := TenantReadScopeFromContext(ctx)
	if !ok {
		return nil
	}
	scope = normalizeTenantReadScope(scope)
	if len(scope.TenantIDs) == 0 {
		return nil
	}
	return append([]string(nil), scope.TenantIDs...)
}

func neptuneTenantNodePredicate(alias string) string {
	alias = strings.TrimSpace(alias)
	return fmt.Sprintf("($tenant_scope_disabled OR %s.tenant_id IS NULL OR %s.tenant_id = '' OR %s.tenant_id IN $tenant_ids)", alias, alias, alias)
}

func AnalyzeNeptuneExplainOutput(raw []byte, mode NeptuneExplainMode) (*NeptuneQueryAnalysis, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, fmt.Errorf("neptune explain output is empty")
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	query := neptuneExplainQueryText(lines)
	headerIndex, headerCells, err := neptuneExplainHeader(lines)
	if err != nil {
		return nil, err
	}
	operators, err := neptuneExplainOperators(lines[headerIndex+1:], headerCells)
	if err != nil {
		return nil, err
	}
	roots := neptuneLinkPlanOperators(operators)
	totalTime := 0.0
	for _, operator := range operators {
		totalTime += operator.TimeMillis
	}
	hotspots, recommendations := neptuneAnalyzeExplainHotspots(operators, totalTime)
	return &NeptuneQueryAnalysis{
		Mode:            mode,
		Query:           query,
		Operators:       operators,
		PlanRoots:       roots,
		Hotspots:        hotspots,
		Recommendations: recommendations,
		TotalTimeMillis: totalTime,
	}, nil
}

func neptuneRows(results any) ([]map[string]any, error) {
	switch typed := results.(type) {
	case nil:
		return nil, nil
	case []any:
		rows := make([]map[string]any, 0, len(typed))
		for _, row := range typed {
			normalized := neptuneNormalizeValue(row)
			record, ok := normalized.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("unexpected neptune row type %T", normalized)
			}
			rows = append(rows, record)
		}
		return rows, nil
	case []map[string]any:
		return typed, nil
	default:
		normalized := neptuneNormalizeValue(typed)
		record, ok := normalized.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unexpected neptune results type %T", normalized)
		}
		return []map[string]any{record}, nil
	}
}

func neptuneExplainQueryText(lines []string) string {
	for index, line := range lines {
		if strings.TrimSpace(line) != "Query:" {
			continue
		}
		collected := make([]string, 0, 4)
		for _, candidate := range lines[index+1:] {
			trimmed := strings.TrimSpace(candidate)
			switch {
			case trimmed == "":
				if len(collected) > 0 {
					return strings.Join(collected, "\n")
				}
			case neptuneExplainTableSeparator(candidate) != "" || neptuneExplainBorderLine(candidate):
				return strings.Join(collected, "\n")
			default:
				collected = append(collected, trimmed)
			}
		}
		return strings.Join(collected, "\n")
	}
	return ""
}

func neptuneExplainHeader(lines []string) (int, []string, error) {
	for index, line := range lines {
		cells := neptuneExplainTableCells(line)
		if len(cells) == 0 {
			continue
		}
		if cells[0] == "ID" && neptuneContainsExactString(cells, "Name") && neptuneContainsExactString(cells, "Arguments") {
			return index, cells, nil
		}
	}
	return 0, nil, fmt.Errorf("neptune explain output did not contain a plan table")
}

func neptuneExplainOperators(lines []string, header []string) ([]*NeptuneQueryPlanOperator, error) {
	operators := make([]*NeptuneQueryPlanOperator, 0)
	for _, line := range lines {
		cells := neptuneExplainTableCells(line)
		if len(cells) == 0 || len(cells) != len(header) {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSpace(cells[0])); err != nil {
			continue
		}
		row := make(map[string]string, len(header))
		for index, key := range header {
			row[key] = cells[index]
		}
		operator := &NeptuneQueryPlanOperator{
			ID:            neptuneParseExplainInt(row["ID"]),
			DownstreamIDs: neptuneParseExplainOutIDs(row["Out #1"], row["Out #2"]),
			Name:          strings.TrimSpace(row["Name"]),
			Arguments:     strings.TrimSpace(row["Arguments"]),
			Mode:          strings.TrimSpace(row["Mode"]),
			UnitsIn:       neptuneParseExplainInt(row["Units In"]),
			UnitsOut:      neptuneParseExplainInt(row["Units Out"]),
			Ratio:         neptuneParseExplainFloat(row["Ratio"]),
			TimeMillis:    neptuneParseExplainFloat(row["Time (ms)"]),
		}
		operators = append(operators, operator)
	}
	if len(operators) == 0 {
		return nil, fmt.Errorf("neptune explain output did not contain any operator rows")
	}
	sort.Slice(operators, func(i, j int) bool {
		return operators[i].ID < operators[j].ID
	})
	return operators, nil
}

func neptuneLinkPlanOperators(operators []*NeptuneQueryPlanOperator) []*NeptuneQueryPlanOperator {
	byID := make(map[int]*NeptuneQueryPlanOperator, len(operators))
	incoming := make(map[int]int, len(operators))
	for _, operator := range operators {
		operator.Children = nil
		byID[operator.ID] = operator
	}
	for _, operator := range operators {
		for _, downstreamID := range operator.DownstreamIDs {
			child, ok := byID[downstreamID]
			if !ok {
				continue
			}
			operator.Children = append(operator.Children, child)
			incoming[downstreamID]++
		}
		sort.Slice(operator.Children, func(i, j int) bool {
			return operator.Children[i].ID < operator.Children[j].ID
		})
	}
	roots := make([]*NeptuneQueryPlanOperator, 0, len(operators))
	for _, operator := range operators {
		if incoming[operator.ID] == 0 {
			roots = append(roots, operator)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].ID < roots[j].ID
	})
	return roots
}

func neptuneAnalyzeExplainHotspots(operators []*NeptuneQueryPlanOperator, totalTime float64) ([]NeptuneQueryHotspot, []string) {
	hotspots := make([]NeptuneQueryHotspot, 0)
	recommendations := make([]string, 0)
	seenRecommendations := make(map[string]struct{})
	for _, operator := range operators {
		hotspot, ok := neptuneHotspotForOperator(operator, totalTime)
		if !ok {
			continue
		}
		hotspots = append(hotspots, hotspot)
		if recommendation := strings.TrimSpace(hotspot.Recommendation); recommendation != "" {
			if _, seen := seenRecommendations[recommendation]; !seen {
				seenRecommendations[recommendation] = struct{}{}
				recommendations = append(recommendations, recommendation)
			}
		}
	}
	sort.Slice(hotspots, func(i, j int) bool {
		if hotspots[i].TimeMillis == hotspots[j].TimeMillis {
			return hotspots[i].OperatorID < hotspots[j].OperatorID
		}
		return hotspots[i].TimeMillis > hotspots[j].TimeMillis
	})
	return hotspots, recommendations
}

func neptuneHotspotForOperator(operator *NeptuneQueryPlanOperator, totalTime float64) (NeptuneQueryHotspot, bool) {
	if operator == nil {
		return NeptuneQueryHotspot{}, false
	}
	timeShare := 0.0
	if totalTime > 0 {
		timeShare = operator.TimeMillis / totalTime
	}
	isBlocking := neptuneExplainBlockingOperator(operator.Name)
	isScan := neptuneExplainScanOperator(operator.Name)
	isJoin := neptuneExplainJoinOperator(operator.Name)
	highTime := operator.TimeMillis >= 10 || timeShare >= 0.18
	highAmplification := operator.Ratio >= 10 || (operator.UnitsIn > 0 && operator.UnitsOut >= operator.UnitsIn*10)
	blockingPressure := isBlocking && operator.UnitsIn >= 1000
	if !highTime && !highAmplification && !blockingPressure {
		return NeptuneQueryHotspot{}, false
	}

	severity := "medium"
	switch {
	case timeShare >= 0.45 || operator.Ratio >= 100 || operator.UnitsOut >= 50000:
		severity = "critical"
	case timeShare >= 0.25 || operator.Ratio >= 20 || operator.UnitsIn >= 10000:
		severity = "high"
	}

	reasonParts := make([]string, 0, 3)
	switch {
	case isScan && highTime:
		reasonParts = append(reasonParts, "broad scan work")
	case isJoin && highAmplification:
		reasonParts = append(reasonParts, "high intermediate binding amplification")
	case isBlocking && blockingPressure:
		reasonParts = append(reasonParts, "blocking operator over a large input set")
	default:
		if highTime {
			reasonParts = append(reasonParts, "high CPU time")
		}
		if highAmplification {
			reasonParts = append(reasonParts, "high row amplification")
		}
		if blockingPressure {
			reasonParts = append(reasonParts, "large blocking input")
		}
	}
	recommendation := neptuneExplainRecommendation(operator.Name)
	return NeptuneQueryHotspot{
		OperatorID:     operator.ID,
		OperatorName:   operator.Name,
		Severity:       severity,
		Reason:         strings.Join(reasonParts, "; "),
		TimeMillis:     operator.TimeMillis,
		UnitsIn:        operator.UnitsIn,
		UnitsOut:       operator.UnitsOut,
		Ratio:          operator.Ratio,
		Recommendation: recommendation,
	}, true
}

func neptuneExplainRecommendation(operatorName string) string {
	switch {
	case neptuneExplainScanOperator(operatorName):
		return "Add more selective MATCH/WHERE predicates or index-backed lookups to reduce scan volume."
	case neptuneExplainJoinOperator(operatorName):
		return "Constrain relationship expansions and joins earlier to reduce intermediate bindings."
	case neptuneExplainBlockingOperator(operatorName):
		return "Push down filters, projections, or LIMIT before blocking operators to shrink intermediate results."
	default:
		return "Reduce intermediate result volume before expensive downstream operators."
	}
}

func neptuneExplainScanOperator(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	return strings.Contains(name, "SCAN")
}

func neptuneExplainJoinOperator(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	return strings.Contains(name, "JOIN") || strings.Contains(name, "EXPAND")
}

func neptuneExplainBlockingOperator(name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	for _, fragment := range []string{"SORT", "DISTINCT", "GROUPBY", "MERGECHUNKS", "HASHINDEXBUILD"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func neptuneExplainBorderLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	return !strings.ContainsAny(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
}

func neptuneExplainTableSeparator(line string) string {
	switch {
	case strings.Contains(line, "│"):
		return "│"
	case strings.Contains(line, "|"):
		return "|"
	default:
		return ""
	}
}

func neptuneExplainTableCells(line string) []string {
	separator := neptuneExplainTableSeparator(line)
	if separator == "" {
		return nil
	}
	parts := strings.Split(line, separator)
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cell := strings.TrimSpace(strings.Trim(part, "║|"))
		cells = append(cells, cell)
	}
	for len(cells) > 0 && cells[0] == "" {
		cells = cells[1:]
	}
	for len(cells) > 0 && cells[len(cells)-1] == "" {
		cells = cells[:len(cells)-1]
	}
	return cells
}

func neptuneParseExplainOutIDs(values ...string) []int {
	out := make([]int, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || trimmed == "-" {
			continue
		}
		if parsed, err := strconv.Atoi(trimmed); err == nil {
			out = append(out, parsed)
		}
	}
	return out
}

func neptuneParseExplainInt(value string) int {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "-" {
		return 0
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0
	}
	return parsed
}

func neptuneParseExplainFloat(value string) float64 {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "-" {
		return 0
	}
	parsed, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func neptuneContainsExactString(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func neptuneNormalizeValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = neptuneNormalizeValue(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, neptuneNormalizeValue(item))
		}
		return out
	case document.Number:
		if asInt, err := typed.Int64(); err == nil {
			return asInt
		}
		if asFloat, err := typed.Float64(); err == nil {
			return asFloat
		}
		return typed.String()
	default:
		return typed
	}
}

func neptuneAliasedRecord(rows []map[string]any, alias string) (map[string]any, bool) {
	if len(rows) == 0 {
		return nil, false
	}
	return neptuneNestedRecord(rows[0], alias)
}

func neptuneNestedRecord(row map[string]any, alias string) (map[string]any, bool) {
	if row == nil {
		return nil, false
	}
	value, ok := row[alias]
	if !ok {
		return nil, false
	}
	record, ok := value.(map[string]any)
	return record, ok
}

func neptuneNodeParams(node *Node) map[string]any {
	if node == nil {
		return nil
	}
	normalizeNodeTenantID(node)
	return map[string]any{
		"id":                       strings.TrimSpace(node.ID),
		"kind":                     strings.TrimSpace(string(node.Kind)),
		"name":                     node.Name,
		"tenant_id":                node.TenantID,
		"provider":                 node.Provider,
		"account":                  node.Account,
		"region":                   node.Region,
		"properties_json":          mustJSON(node.PropertyMap()),
		"tags_json":                mustJSON(node.Tags),
		"risk":                     string(node.Risk),
		"findings_json":            mustJSON(node.Findings),
		"created_at":               storeTimeParam(node.CreatedAt),
		"updated_at":               storeTimeParam(node.UpdatedAt),
		"deleted_at":               nullableStoreTimeParam(node.DeletedAt),
		"version":                  node.Version,
		"previous_properties_json": mustJSON(node.PreviousProperties),
		"property_history_json":    mustJSON(node.PropertyHistory),
	}
}

func neptuneBatchNodeParams(nodes []*Node) map[string]any {
	rows := make([]map[string]any, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || strings.TrimSpace(node.ID) == "" {
			continue
		}
		rows = append(rows, neptuneNodeParams(node))
	}
	if len(rows) == 0 {
		return nil
	}
	return map[string]any{"rows": rows}
}

func neptuneEdgeParams(edge *Edge) map[string]any {
	if edge == nil {
		return nil
	}
	params := map[string]any{
		"id":              strings.TrimSpace(edge.ID),
		"source":          strings.TrimSpace(edge.Source),
		"target":          strings.TrimSpace(edge.Target),
		"kind":            strings.TrimSpace(string(edge.Kind)),
		"effect":          string(edge.Effect),
		"priority":        edge.Priority,
		"properties_json": mustJSON(edge.Properties),
		"risk":            string(edge.Risk),
		"created_at":      storeTimeParam(edge.CreatedAt),
		"deleted_at":      nullableStoreTimeParam(edge.DeletedAt),
		"version":         edge.Version,
	}
	for key, value := range neptuneTemporalEdgeParams(edge) {
		params[key] = value
	}
	return params
}

func neptuneTemporalEdgeParams(edge *Edge) map[string]any {
	if edge == nil {
		return nil
	}
	return map[string]any{
		"observed_at":      neptuneTemporalPropertyParam(edge.Properties, "observed_at"),
		"valid_from":       neptuneTemporalPropertyParam(edge.Properties, "valid_from"),
		"valid_to":         neptuneTemporalPropertyParam(edge.Properties, "valid_to"),
		"expires_at":       neptuneTemporalPropertyParam(edge.Properties, "expires_at"),
		"recorded_at":      neptuneTemporalPropertyParam(edge.Properties, "recorded_at"),
		"transaction_from": neptuneTemporalPropertyParam(edge.Properties, "transaction_from"),
		"transaction_to":   neptuneTemporalPropertyParam(edge.Properties, "transaction_to"),
	}
}

func neptuneTemporalPropertyParam(properties map[string]any, key string) any {
	value, ok := temporalPropertyTime(properties, key)
	if !ok || value.IsZero() {
		return nil
	}
	return storeTimeParam(value)
}

func neptuneBatchEdgeParams(edges []*Edge) map[string]any {
	rows := make([]map[string]any, 0, len(edges))
	for _, edge := range edges {
		if edge == nil || strings.TrimSpace(edge.Source) == "" || strings.TrimSpace(edge.Target) == "" {
			continue
		}
		rows = append(rows, neptuneEdgeParams(edge))
	}
	if len(rows) == 0 {
		return nil
	}
	return map[string]any{"rows": rows}
}

func neptuneDecodeNode(record map[string]any) (*Node, error) {
	if len(record) == 0 {
		return nil, nil
	}
	node := &Node{
		ID:                 strings.TrimSpace(readString(record, "id")),
		Kind:               NodeKind(strings.TrimSpace(readString(record, "kind"))),
		Name:               readString(record, "name"),
		TenantID:           readString(record, "tenant_id"),
		Provider:           readString(record, "provider"),
		Account:            readString(record, "account"),
		Region:             readString(record, "region"),
		Risk:               RiskLevel(strings.TrimSpace(readString(record, "risk"))),
		CreatedAt:          parseStoreTime(readString(record, "created_at")),
		UpdatedAt:          parseStoreTime(readString(record, "updated_at")),
		DeletedAt:          parseNullableStoreTime(readString(record, "deleted_at")),
		Version:            neptuneInt(record["version"]),
		Properties:         nil,
		Tags:               nil,
		Findings:           nil,
		PreviousProperties: nil,
		PropertyHistory:    nil,
	}
	if node.ID == "" {
		return nil, nil
	}
	if err := decodeJSONString(readString(record, "properties_json"), &node.Properties); err != nil {
		return nil, fmt.Errorf("decode node properties: %w", err)
	}
	if err := decodeJSONString(readString(record, "tags_json"), &node.Tags); err != nil {
		return nil, fmt.Errorf("decode node tags: %w", err)
	}
	if err := decodeJSONString(readString(record, "findings_json"), &node.Findings); err != nil {
		return nil, fmt.Errorf("decode node findings: %w", err)
	}
	if err := decodeJSONString(readString(record, "previous_properties_json"), &node.PreviousProperties); err != nil {
		return nil, fmt.Errorf("decode previous node properties: %w", err)
	}
	if err := decodeJSONString(readString(record, "property_history_json"), &node.PropertyHistory); err != nil {
		return nil, fmt.Errorf("decode node property history: %w", err)
	}
	normalizeNodeTenantID(node)
	return node, nil
}

func neptuneDecodeEdge(record map[string]any) (*Edge, error) {
	if len(record) == 0 {
		return nil, nil
	}
	edge := &Edge{
		ID:        strings.TrimSpace(readString(record, "id")),
		Source:    strings.TrimSpace(readString(record, "source")),
		Target:    strings.TrimSpace(readString(record, "target")),
		Kind:      EdgeKind(strings.TrimSpace(readString(record, "kind"))),
		Effect:    EdgeEffect(strings.TrimSpace(readString(record, "effect"))),
		Priority:  neptuneInt(record["priority"]),
		Risk:      RiskLevel(strings.TrimSpace(readString(record, "risk"))),
		CreatedAt: parseStoreTime(readString(record, "created_at")),
		DeletedAt: parseNullableStoreTime(readString(record, "deleted_at")),
		Version:   neptuneInt(record["version"]),
	}
	if edge.Source == "" || edge.Target == "" {
		return nil, nil
	}
	if err := decodeJSONString(readString(record, "properties_json"), &edge.Properties); err != nil {
		return nil, fmt.Errorf("decode edge properties: %w", err)
	}
	return edge, nil
}

func neptuneInt(value any) int {
	switch typed := value.(type) {
	case nil:
		return 0
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		return int(int64FromValue(typed))
	default:
		return int(int64FromValue(typed))
	}
}

func decodeJSONString(raw string, target any) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), target)
}

func mustJSON(value any) string {
	if value == nil {
		return ""
	}
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func formatStoreTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func formatNullableStoreTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func storeTimeParam(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return formatStoreTime(value)
}

func nullableStoreTimeParam(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return formatNullableStoreTime(value)
}

func parseStoreTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func parseNullableStoreTime(value string) *time.Time {
	parsed := parseStoreTime(value)
	if parsed.IsZero() {
		return nil
	}
	return &parsed
}

type neptuneTraversalDirection int

const (
	neptuneTraversalDirectionBoth neptuneTraversalDirection = iota
	neptuneTraversalDirectionOutgoing
	neptuneTraversalDirectionIncoming
)

func neptuneTraversalDirectionFromExtractSubgraph(direction ExtractSubgraphDirection) neptuneTraversalDirection {
	switch direction {
	case ExtractSubgraphDirectionOutgoing:
		return neptuneTraversalDirectionOutgoing
	case ExtractSubgraphDirectionIncoming:
		return neptuneTraversalDirectionIncoming
	default:
		return neptuneTraversalDirectionBoth
	}
}

func normalizeTraversalDepth(maxDepth int) int {
	if maxDepth < 0 {
		return 0
	}
	return maxDepth
}

func normalizeTraversalDepthWithDefault(maxDepth, fallback int) int {
	if maxDepth <= 0 {
		return fallback
	}
	return maxDepth
}

func neptuneTraversalNodesQuery(direction neptuneTraversalDirection, maxDepth int) string {
	return fmt.Sprintf(`
MATCH p = %s
WHERE ALL(node IN nodes(p) WHERE node.deleted_at IS NULL)
  AND ALL(node IN nodes(p) WHERE %s)
  AND ALL(edge IN relationships(p) WHERE edge.deleted_at IS NULL)
UNWIND nodes(p) AS n
WITH DISTINCT n
RETURN {
  id: n.id,
  kind: n.kind,
  name: n.name,
  tenant_id: n.tenant_id,
  provider: n.provider,
  account: n.account,
  region: n.region,
  properties_json: n.properties_json,
  tags_json: n.tags_json,
  risk: n.risk,
  findings_json: n.findings_json,
  created_at: n.created_at,
  updated_at: n.updated_at,
  deleted_at: n.deleted_at,
  version: n.version,
  previous_properties_json: n.previous_properties_json,
  property_history_json: n.property_history_json
} AS node
`, neptuneTraversalPattern(direction, maxDepth), neptuneTenantNodePredicate("node"))
}

func neptuneTraversalEdgesQuery(direction neptuneTraversalDirection, maxDepth int) string {
	return fmt.Sprintf(`
MATCH p = %s
WHERE ALL(node IN nodes(p) WHERE node.deleted_at IS NULL)
  AND ALL(node IN nodes(p) WHERE %s)
  AND ALL(edge IN relationships(p) WHERE edge.deleted_at IS NULL)
UNWIND relationships(p) AS r
WITH DISTINCT r, startNode(r) AS src, endNode(r) AS dst
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneTraversalPattern(direction, maxDepth), neptuneTenantNodePredicate("node"), neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))
}

func neptuneTemporalBitemporalTraversalNodeQuery(direction neptuneTraversalDirection, maxDepth int) string {
	return fmt.Sprintf(`
MATCH p = %s
WHERE ALL(node IN nodes(p) WHERE node.deleted_at IS NULL)
  AND ALL(node IN nodes(p) WHERE %s)
  AND ALL(edge IN relationships(p) WHERE edge.deleted_at IS NULL AND %s)
UNWIND nodes(p) AS n
WITH DISTINCT n
RETURN {
  id: n.id,
  kind: n.kind,
  name: n.name,
  tenant_id: n.tenant_id,
  provider: n.provider,
  account: n.account,
  region: n.region,
  properties_json: n.properties_json,
  tags_json: n.tags_json,
  risk: n.risk,
  findings_json: n.findings_json,
  created_at: n.created_at,
  updated_at: n.updated_at,
  deleted_at: n.deleted_at,
  version: n.version,
  previous_properties_json: n.previous_properties_json,
  property_history_json: n.property_history_json
} AS node
`, neptuneTraversalPattern(direction, maxDepth), neptuneTenantNodePredicate("node"), neptuneTemporalBitemporalPredicate("edge"))
}

func neptuneTemporalBitemporalTraversalEdgeQuery(direction neptuneTraversalDirection, maxDepth int) string {
	return fmt.Sprintf(`
MATCH p = %s
WHERE ALL(node IN nodes(p) WHERE node.deleted_at IS NULL)
  AND ALL(node IN nodes(p) WHERE %s)
  AND ALL(edge IN relationships(p) WHERE edge.deleted_at IS NULL AND %s)
UNWIND relationships(p) AS r
WITH DISTINCT r, startNode(r) AS src, endNode(r) AS dst
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneTraversalPattern(direction, maxDepth), neptuneTenantNodePredicate("node"), neptuneTemporalBitemporalPredicate("edge"), neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"), neptuneTemporalBitemporalPredicate("r"))
}

func neptuneTemporalRangeTraversalNodeQuery(direction neptuneTraversalDirection, maxDepth int) string {
	return fmt.Sprintf(`
MATCH p = %s
WHERE ALL(node IN nodes(p) WHERE node.deleted_at IS NULL)
  AND ALL(node IN nodes(p) WHERE %s)
  AND ALL(edge IN relationships(p) WHERE edge.deleted_at IS NULL AND %s)
UNWIND nodes(p) AS n
WITH DISTINCT n
RETURN {
  id: n.id,
  kind: n.kind,
  name: n.name,
  tenant_id: n.tenant_id,
  provider: n.provider,
  account: n.account,
  region: n.region,
  properties_json: n.properties_json,
  tags_json: n.tags_json,
  risk: n.risk,
  findings_json: n.findings_json,
  created_at: n.created_at,
  updated_at: n.updated_at,
  deleted_at: n.deleted_at,
  version: n.version,
  previous_properties_json: n.previous_properties_json,
  property_history_json: n.property_history_json
} AS node
`, neptuneTraversalPattern(direction, maxDepth), neptuneTenantNodePredicate("node"), neptuneTemporalRangePredicate("edge"))
}

func neptuneTemporalRangeTraversalEdgeQuery(direction neptuneTraversalDirection, maxDepth int) string {
	return fmt.Sprintf(`
MATCH p = %s
WHERE ALL(node IN nodes(p) WHERE node.deleted_at IS NULL)
  AND ALL(node IN nodes(p) WHERE %s)
  AND ALL(edge IN relationships(p) WHERE edge.deleted_at IS NULL AND %s)
UNWIND relationships(p) AS r
WITH DISTINCT r, startNode(r) AS src, endNode(r) AS dst
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneTraversalPattern(direction, maxDepth), neptuneTenantNodePredicate("node"), neptuneTemporalRangePredicate("edge"), neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"), neptuneTemporalRangePredicate("r"))
}

func neptuneTraversalPattern(direction neptuneTraversalDirection, maxDepth int) string {
	maxDepth = normalizeTraversalDepth(maxDepth)
	switch direction {
	case neptuneTraversalDirectionOutgoing:
		return fmt.Sprintf("(root:%s {id: $root_id})-[:%s*0..%d]->(n:%s)", neptuneNodeLabel, neptuneEdgeType, maxDepth, neptuneNodeLabel)
	case neptuneTraversalDirectionIncoming:
		return fmt.Sprintf("(root:%s {id: $root_id})<-[:%s*0..%d]-(n:%s)", neptuneNodeLabel, neptuneEdgeType, maxDepth, neptuneNodeLabel)
	default:
		return fmt.Sprintf("(root:%s {id: $root_id})-[:%s*0..%d]-(n:%s)", neptuneNodeLabel, neptuneEdgeType, maxDepth, neptuneNodeLabel)
	}
}

const neptuneUpsertNodeQuery = `
MERGE (n:` + neptuneNodeLabel + ` {id: $id})
SET n.kind = $kind,
    n.name = $name,
    n.tenant_id = $tenant_id,
    n.provider = $provider,
    n.account = $account,
    n.region = $region,
    n.properties_json = $properties_json,
    n.tags_json = $tags_json,
    n.risk = $risk,
    n.findings_json = $findings_json,
    n.created_at = $created_at,
    n.updated_at = $updated_at,
    n.deleted_at = $deleted_at,
    n.version = $version,
    n.previous_properties_json = $previous_properties_json,
    n.property_history_json = $property_history_json
RETURN n.id AS id
`

const neptuneUpsertNodesBatchQuery = `
UNWIND $rows AS row
MERGE (n:` + neptuneNodeLabel + ` {id: row.id})
SET n.kind = row.kind,
    n.name = row.name,
    n.tenant_id = row.tenant_id,
    n.provider = row.provider,
    n.account = row.account,
    n.region = row.region,
    n.properties_json = row.properties_json,
    n.tags_json = row.tags_json,
    n.risk = row.risk,
    n.findings_json = row.findings_json,
    n.created_at = row.created_at,
    n.updated_at = row.updated_at,
    n.deleted_at = row.deleted_at,
    n.version = row.version,
    n.previous_properties_json = row.previous_properties_json,
    n.property_history_json = row.property_history_json
RETURN count(n) AS total
`

const neptuneUpsertEdgeQuery = `
MERGE (src:` + neptuneNodeLabel + ` {id: $source})
MERGE (dst:` + neptuneNodeLabel + ` {id: $target})
MERGE (src)-[r:` + neptuneEdgeType + ` {id: $id}]->(dst)
SET r.kind = $kind,
    r.effect = $effect,
    r.priority = $priority,
    r.properties_json = $properties_json,
    r.observed_at = $observed_at,
    r.valid_from = $valid_from,
    r.valid_to = $valid_to,
    r.expires_at = $expires_at,
    r.recorded_at = $recorded_at,
    r.transaction_from = $transaction_from,
    r.transaction_to = $transaction_to,
    r.risk = $risk,
    r.created_at = $created_at,
    r.deleted_at = $deleted_at,
    r.version = $version
RETURN r.id AS id
`

const neptuneUpsertEdgesBatchQuery = `
UNWIND $rows AS row
MERGE (src:` + neptuneNodeLabel + ` {id: row.source})
MERGE (dst:` + neptuneNodeLabel + ` {id: row.target})
MERGE (src)-[r:` + neptuneEdgeType + ` {id: row.id}]->(dst)
SET r.kind = row.kind,
    r.effect = row.effect,
    r.priority = row.priority,
    r.properties_json = row.properties_json,
    r.risk = row.risk,
    r.created_at = row.created_at,
    r.deleted_at = row.deleted_at,
    r.version = row.version
RETURN count(r) AS total
`

const neptuneDeleteNodeQuery = `
MATCH (n:` + neptuneNodeLabel + ` {id: $id})
SET n.deleted_at = $deleted_at,
    n.updated_at = $deleted_at,
    n.version = coalesce(n.version, 0) + 1
RETURN count(n) AS total
`

const neptuneDeleteNodeEdgesQuery = `
MATCH (n:` + neptuneNodeLabel + ` {id: $id})-[r]-()
SET r.deleted_at = $deleted_at,
    r.version = coalesce(r.version, 0) + 1
RETURN count(r) AS total
`

const neptuneDeleteEdgeQuery = `
MATCH ()-[r:` + neptuneEdgeType + ` {id: $id}]->()
SET r.deleted_at = $deleted_at,
    r.version = coalesce(r.version, 0) + 1
RETURN count(r) AS total
`

var neptuneLookupNodeQuery = fmt.Sprintf(`
MATCH (n:%s {id: $id})
WHERE n.deleted_at IS NULL
  AND %s
RETURN {
  id: n.id,
  kind: n.kind,
  name: n.name,
  tenant_id: n.tenant_id,
  provider: n.provider,
  account: n.account,
  region: n.region,
  properties_json: n.properties_json,
  tags_json: n.tags_json,
  risk: n.risk,
  findings_json: n.findings_json,
  created_at: n.created_at,
  updated_at: n.updated_at,
  deleted_at: n.deleted_at,
  version: n.version,
  previous_properties_json: n.previous_properties_json,
  property_history_json: n.property_history_json
} AS node
LIMIT 1
`, neptuneNodeLabel, neptuneTenantNodePredicate("n"))

var neptuneLookupEdgeQuery = fmt.Sprintf(`
MATCH (src:%s)-[r:%s {id: $id}]->(dst:%s)
WHERE r.deleted_at IS NULL
  AND src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
LIMIT 1
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupOutEdgesQuery = fmt.Sprintf(`
MATCH (src:%s {id: $node_id})-[r:%s]->(dst:%s)
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupOutEdgesBitemporalQuery = fmt.Sprintf(`
MATCH (src:%s {id: $node_id})-[r:%s]->(dst:%s)
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
  AND `+neptuneLookupEdgeBitemporalPredicate+`
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupInEdgesQuery = fmt.Sprintf(`
MATCH (src:%s)-[r:%s]->(dst:%s {id: $node_id})
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupInEdgesBitemporalQuery = fmt.Sprintf(`
MATCH (src:%s)-[r:%s]->(dst:%s {id: $node_id})
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
  AND `+neptuneLookupEdgeBitemporalPredicate+`
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupOutEdgesBetweenQuery = fmt.Sprintf(`
MATCH (src:%s {id: $node_id})-[r:%s]->(dst:%s)
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
  AND `+neptuneLookupEdgeRangePredicate+`
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupInEdgesBetweenQuery = fmt.Sprintf(`
MATCH (src:%s)-[r:%s]->(dst:%s {id: $node_id})
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
  AND `+neptuneLookupEdgeRangePredicate+`
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneLookupNodesByKindQuery = fmt.Sprintf(`
MATCH (n:%s)
WHERE n.deleted_at IS NULL
  AND n.kind IN $kinds
  AND %s
RETURN {
  id: n.id,
  kind: n.kind,
  name: n.name,
  tenant_id: n.tenant_id,
  provider: n.provider,
  account: n.account,
  region: n.region,
  properties_json: n.properties_json,
  tags_json: n.tags_json,
  risk: n.risk,
  findings_json: n.findings_json,
  created_at: n.created_at,
  updated_at: n.updated_at,
  deleted_at: n.deleted_at,
  version: n.version,
  previous_properties_json: n.previous_properties_json,
  property_history_json: n.property_history_json
} AS node
`, neptuneNodeLabel, neptuneTenantNodePredicate("n"))

var neptuneCountNodesQuery = fmt.Sprintf(`
MATCH (n:%s)
WHERE n.deleted_at IS NULL
  AND %s
RETURN count(n) AS total
`, neptuneNodeLabel, neptuneTenantNodePredicate("n"))

var neptuneCountEdgesQuery = fmt.Sprintf(`
MATCH (src:%s)-[r:%s]->(dst:%s)
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
RETURN count(r) AS total
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

var neptuneSnapshotNodesQuery = fmt.Sprintf(`
MATCH (n:%s)
WHERE n.deleted_at IS NULL
  AND %s
RETURN {
  id: n.id,
  kind: n.kind,
  name: n.name,
  tenant_id: n.tenant_id,
  provider: n.provider,
  account: n.account,
  region: n.region,
  properties_json: n.properties_json,
  tags_json: n.tags_json,
  risk: n.risk,
  findings_json: n.findings_json,
  created_at: n.created_at,
  updated_at: n.updated_at,
  deleted_at: n.deleted_at,
  version: n.version,
  previous_properties_json: n.previous_properties_json,
  property_history_json: n.property_history_json
} AS node
`, neptuneNodeLabel, neptuneTenantNodePredicate("n"))

var neptuneSnapshotEdgesQuery = fmt.Sprintf(`
MATCH (src:%s)-[r:%s]->(dst:%s)
WHERE src.deleted_at IS NULL
  AND dst.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND %s
  AND %s
RETURN {
  id: r.id,
  source: src.id,
  target: dst.id,
  kind: r.kind,
  effect: r.effect,
  priority: r.priority,
  properties_json: r.properties_json,
  risk: r.risk,
  created_at: r.created_at,
  deleted_at: r.deleted_at,
  version: r.version
} AS edge
`, neptuneNodeLabel, neptuneEdgeType, neptuneNodeLabel, neptuneTenantNodePredicate("src"), neptuneTenantNodePredicate("dst"))

const neptuneLookupEdgeBitemporalPredicate = `
coalesce(r.valid_from, r.observed_at, r.created_at) <= $valid_at
  AND (coalesce(r.valid_to, r.expires_at, r.deleted_at) IS NULL OR coalesce(r.valid_to, r.expires_at, r.deleted_at) >= $valid_at)
  AND coalesce(r.transaction_from, r.recorded_at, r.created_at) <= $recorded_at
  AND (coalesce(r.transaction_to, r.deleted_at) IS NULL OR coalesce(r.transaction_to, r.deleted_at) >= $recorded_at)
`

const neptuneLookupEdgeRangePredicate = `
coalesce(r.valid_from, r.observed_at, r.created_at) <= $to
  AND (coalesce(r.valid_to, r.expires_at, r.deleted_at) IS NULL OR coalesce(r.valid_to, r.expires_at, r.deleted_at) >= $from)
`

func neptuneTemporalBitemporalPredicate(alias string) string {
	return fmt.Sprintf(
		"coalesce(%[1]s.valid_from, %[1]s.observed_at, %[1]s.created_at) <= $valid_at AND (coalesce(%[1]s.valid_to, %[1]s.expires_at, %[1]s.deleted_at) IS NULL OR coalesce(%[1]s.valid_to, %[1]s.expires_at, %[1]s.deleted_at) >= $valid_at) AND coalesce(%[1]s.transaction_from, %[1]s.recorded_at, %[1]s.created_at) <= $recorded_at AND (coalesce(%[1]s.transaction_to, %[1]s.deleted_at) IS NULL OR coalesce(%[1]s.transaction_to, %[1]s.deleted_at) >= $recorded_at)",
		alias,
	)
}

func neptuneTemporalRangePredicate(alias string) string {
	return fmt.Sprintf(
		"coalesce(%[1]s.valid_from, %[1]s.observed_at, %[1]s.created_at) <= $to AND (coalesce(%[1]s.valid_to, %[1]s.expires_at, %[1]s.deleted_at) IS NULL OR coalesce(%[1]s.valid_to, %[1]s.expires_at, %[1]s.deleted_at) >= $from)",
		alias,
	)
}
