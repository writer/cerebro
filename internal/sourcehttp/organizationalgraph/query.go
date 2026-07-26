// Package organizationalgraph makes the Rust-owned generated graph contract
// the product read authority. A legacy store is optional and exists only for
// callers that have not yet moved from raw Cypher to typed operations.
package organizationalgraph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel/trace"

	cerebrographv1 "github.com/writer/cerebro/gen/cerebro/graph/v1"
	"github.com/writer/cerebro/gen/cerebro/graph/v1/cerebrographv1connect"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	maxResponseBytes = 4 << 20
	maxBatchRoots    = 100
)

type readMode uint8

const (
	readModeAuthority readMode = iota
	readModeShadow
	readModeCanary
)

// QueryStore serves bounded product reads from Rust. When a compatibility
// reader is present, callers not yet moved from raw Cypher can still use it.
// Without one, those callers fail explicitly instead of falling back.
type QueryStore struct {
	compatibility ports.GraphQueryStore
	baseURL       string
	httpClient    *http.Client
	graph         cerebrographv1connect.OrganizationalGraphServiceClient
	auth          tenantAuthenticator
	mode          readMode
	samplePercent uint32
	verifyPercent uint32
}

// ReadinessStore selects the product read authority when configured.
func ReadinessStore(compatibility, authority ports.GraphStore) ports.GraphStore {
	if authority != nil {
		return authority
	}
	return compatibility
}

func NewQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration) (*QueryStore, error) {
	return newQueryStore(compatibility, baseURL, sharedSecret, timeout, readModeAuthority, 100)
}

// NewConfiguredQueryStore selects one validated deployment read strategy.
func NewConfiguredQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, mode string, shadowPercent, authorityPercent, canaryVerifyPercent int) (*QueryStore, error) {
	switch mode {
	case "shadow":
		return NewShadowQueryStore(compatibility, baseURL, sharedSecret, timeout, shadowPercent)
	case "canary":
		return NewVerifiedCanaryQueryStore(compatibility, baseURL, sharedSecret, timeout, authorityPercent, canaryVerifyPercent)
	default:
		return NewQueryStore(compatibility, baseURL, sharedSecret, timeout)
	}
}

func NewShadowQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, shadowPercent int) (*QueryStore, error) {
	if compatibility == nil {
		return nil, errors.New("shadow graph reads require the legacy compatibility store")
	}
	if shadowPercent <= 0 || shadowPercent > 100 {
		return nil, errors.New("shadow graph read percent must be between 1 and 100")
	}
	return newQueryStore(compatibility, baseURL, sharedSecret, timeout, readModeShadow, uint32(shadowPercent)) // #nosec G115 -- validated above.
}

// NewCanaryQueryStore returns Rust responses for one stable sample of typed
// reads and the compatibility response for the rest. A sampled Rust failure
// fails closed; it never retries the same request against Go.
func NewCanaryQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, authorityPercent int) (*QueryStore, error) {
	return NewVerifiedCanaryQueryStore(compatibility, baseURL, sharedSecret, timeout, authorityPercent, 0)
}

// NewVerifiedCanaryQueryStore also compares a stable sample of Rust-authority
// reads with the compatibility result. Verification never changes the selected
// authority or falls back after a Rust failure.
func NewVerifiedCanaryQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, authorityPercent, verifyPercent int) (*QueryStore, error) {
	if compatibility == nil {
		return nil, errors.New("canary graph reads require the legacy compatibility store")
	}
	if authorityPercent <= 0 || authorityPercent >= 100 {
		return nil, errors.New("canary graph read percent must be between 1 and 99")
	}
	if verifyPercent < 0 || verifyPercent > 100 {
		return nil, errors.New("canary graph verification percent must be between 0 and 100")
	}
	store, err := newQueryStore(compatibility, baseURL, sharedSecret, timeout, readModeCanary, uint32(authorityPercent)) // #nosec G115 -- validated above.
	if err != nil {
		return nil, err
	}
	store.verifyPercent = uint32(verifyPercent) // #nosec G115 -- validated above.
	return store, nil
}

func newQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, mode readMode, samplePercent uint32) (*QueryStore, error) {
	baseURL, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, errors.New("rust organizational graph timeout must be positive")
	}
	auth, err := newTenantAuthenticator(sharedSecret)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: timeout}
	return &QueryStore{
		compatibility: compatibility,
		baseURL:       baseURL,
		httpClient:    httpClient,
		graph:         cerebrographv1connect.NewOrganizationalGraphServiceClient(httpClient, baseURL),
		auth:          auth,
		mode:          mode,
		samplePercent: samplePercent,
	}, nil
}

func (s *QueryStore) Ping(ctx context.Context) (err error) {
	if s.compatibility != nil {
		if err := s.compatibility.Ping(ctx); err != nil {
			return fmt.Errorf("compatibility graph health: %w", err)
		}
	}
	if s.mode == readModeShadow || s.mode == readModeCanary {
		started := time.Now()
		err := s.pingRust(ctx)
		status := "match"
		if err != nil {
			status = "rust_error"
		}
		observability.RecordOrganizationalGraphShadow(ctx, observability.OrganizationalGraphShadowMetrics{
			Operation: "readiness",
			Status:    status,
			Duration:  time.Since(started),
		})
		return nil
	}
	return s.pingRust(ctx)
}

func (s *QueryStore) pingRust(ctx context.Context) (err error) {
	// #nosec G704 -- normalizeBaseURL validates and freezes the operator-set
	// HTTP(S) origin; this package supplies the constant request path.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/readyz", nil)
	if err != nil {
		return fmt.Errorf("build Rust graph health request: %w", err)
	}
	// #nosec G704 -- request uses the validated, frozen origin and constant path above.
	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("read Rust graph health: %w", err)
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()
	_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("rust graph health returned %s", response.Status)
	}
	return copyErr
}

func (s *QueryStore) GetEntityNeighborhood(ctx context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	if s.mode == readModeCanary {
		tenantID := cerebrourn.TenantID(strings.TrimSpace(rootURN))
		if tenantID == "" {
			return nil, errors.New("root is not a tenant-scoped Cerebro URN")
		}
		started := time.Now()
		if !s.sample(tenantID) {
			result, err := s.compatibility.GetEntityNeighborhood(ctx, rootURN, limit)
			s.recordCanaryRoute(ctx, "expand", "go", err, started)
			return result, err
		}
		result, err := s.getRustEntityNeighborhood(ctx, rootURN, limit)
		if err == nil && s.verifyCanary("expand", rootURN) {
			verificationStarted := time.Now()
			legacy, legacyErr := s.compatibility.GetEntityNeighborhood(ctx, rootURN, limit)
			s.recordCanaryVerification(ctx, "expand", legacy, legacyErr, result, verificationStarted)
		}
		s.recordCanaryRoute(ctx, "expand", "rust", err, started)
		return result, err
	}
	if s.mode == readModeAuthority {
		return s.getRustEntityNeighborhood(ctx, rootURN, limit)
	}
	legacy, err := s.compatibility.GetEntityNeighborhood(ctx, rootURN, limit)
	if err != nil || !s.sample(rootURN) {
		return legacy, err
	}
	started := time.Now()
	rust, rustErr := s.getRustEntityNeighborhood(ctx, rootURN, limit)
	s.recordComparison(ctx, "expand", legacy, rust, rustErr, started)
	return legacy, nil
}

func (s *QueryStore) getRustEntityNeighborhood(ctx context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	rootURN = strings.TrimSpace(rootURN)
	if cerebrourn.TenantID(rootURN) == "" {
		return nil, errors.New("root is not a tenant-scoped Cerebro URN")
	}
	rootOnly := limit <= 0
	tenantID := cerebrourn.TenantID(rootURN)
	request := connect.NewRequest(&cerebrographv1.ExpandRequest{
		TenantId: tenantID,
		RootKey:  rootURN,
		Depth:    1,
		Limit:    uint32(normalizedLimit(limit)), // #nosec G115 -- normalizedLimit is bounded to 500.
	})
	if err := s.auth.authorizeHeader(request.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.graph.Expand(ctx, request)
	if err != nil {
		return nil, graphRPCError("expand", err)
	}
	product, err := productNeighborhood(rootURN, response.Msg)
	if err != nil {
		return nil, err
	}
	if rootOnly {
		product.Neighbors = []*ports.NeighborhoodNode{}
		product.Relations = []*ports.NeighborhoodRelation{}
	}
	return product, nil
}

func (s *QueryStore) GetEntityNeighborhoods(ctx context.Context, rootURNs []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
	sampleKey := strings.Join(rootURNs, "\x00")
	if s.mode == readModeCanary {
		tenantID, err := graphRootsTenant(rootURNs)
		if err != nil {
			return nil, err
		}
		started := time.Now()
		if !s.sample(tenantID) {
			result, err := legacyNeighborhoods(ctx, s.compatibility, rootURNs, limit)
			s.recordCanaryRoute(ctx, "expand_batch", "go", err, started)
			return result, err
		}
		result, err := s.getRustEntityNeighborhoods(ctx, rootURNs, limit)
		if err == nil && s.verifyCanary("expand_batch", sampleKey) {
			verificationStarted := time.Now()
			legacy, legacyErr := legacyNeighborhoods(ctx, s.compatibility, rootURNs, limit)
			s.recordCanaryVerification(ctx, "expand_batch", legacy, legacyErr, result, verificationStarted)
		}
		s.recordCanaryRoute(ctx, "expand_batch", "rust", err, started)
		return result, err
	}
	if s.mode == readModeAuthority {
		return s.getRustEntityNeighborhoods(ctx, rootURNs, limit)
	}
	legacy, err := legacyNeighborhoods(ctx, s.compatibility, rootURNs, limit)
	if err != nil || !s.sample(sampleKey) {
		return legacy, err
	}
	started := time.Now()
	rust, rustErr := s.getRustEntityNeighborhoods(ctx, rootURNs, limit)
	s.recordComparison(ctx, "expand_batch", legacy, rust, rustErr, started)
	return legacy, nil
}

func (s *QueryStore) getRustEntityNeighborhoods(ctx context.Context, rootURNs []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
	if len(rootURNs) == 0 {
		return map[string]*ports.EntityNeighborhood{}, nil
	}
	if len(rootURNs) > maxBatchRoots {
		return nil, fmt.Errorf("graph root count exceeds %d", maxBatchRoots)
	}
	rootOnly := limit <= 0
	tenantID := ""
	roots := make([]string, 0, len(rootURNs))
	seen := make(map[string]struct{}, len(rootURNs))
	for _, rootURN := range rootURNs {
		rootURN = strings.TrimSpace(rootURN)
		rootTenantID := cerebrourn.TenantID(rootURN)
		if rootTenantID == "" {
			return nil, errors.New("root is not a tenant-scoped Cerebro URN")
		}
		if tenantID == "" {
			tenantID = rootTenantID
		} else if rootTenantID != tenantID {
			return nil, errors.New("graph roots belong to different tenants")
		}
		if _, exists := seen[rootURN]; exists {
			continue
		}
		seen[rootURN] = struct{}{}
		roots = append(roots, rootURN)
	}
	request := connect.NewRequest(&cerebrographv1.ExpandBatchRequest{
		TenantId: tenantID,
		RootKeys: roots,
		Depth:    1,
		Limit:    uint32(normalizedLimit(limit)), // #nosec G115 -- normalizedLimit is bounded to 500.
	})
	if err := s.auth.authorizeHeader(request.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.graph.ExpandBatch(ctx, request)
	if err != nil {
		return nil, graphRPCError("expand batch", err)
	}
	result := make(map[string]*ports.EntityNeighborhood, len(response.Msg.GetNeighborhoods()))
	for rootURN, neighborhood := range response.Msg.GetNeighborhoods() {
		if _, requested := seen[rootURN]; !requested {
			return nil, errors.New("rust graph returned an unrequested root")
		}
		product, err := productNeighborhood(rootURN, neighborhood)
		if err != nil {
			return nil, err
		}
		if rootOnly {
			product.Neighbors = []*ports.NeighborhoodNode{}
			product.Relations = []*ports.NeighborhoodRelation{}
		}
		result[rootURN] = product
	}
	return result, nil
}

func graphRootsTenant(rootURNs []string) (string, error) {
	if len(rootURNs) == 0 {
		return "", nil
	}
	tenantID := ""
	for _, rootURN := range rootURNs {
		rootTenantID := cerebrourn.TenantID(strings.TrimSpace(rootURN))
		if rootTenantID == "" {
			return "", errors.New("root is not a tenant-scoped Cerebro URN")
		}
		if tenantID == "" {
			tenantID = rootTenantID
		} else if rootTenantID != tenantID {
			return "", errors.New("graph roots belong to different tenants")
		}
	}
	return tenantID, nil
}

func legacyNeighborhoods(ctx context.Context, store ports.GraphQueryStore, roots []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
	if batch, ok := store.(ports.GraphNeighborhoodBatchStore); ok {
		return batch.GetEntityNeighborhoods(ctx, roots, limit)
	}
	result := make(map[string]*ports.EntityNeighborhood, len(roots))
	for _, root := range roots {
		if _, exists := result[root]; exists {
			continue
		}
		neighborhood, err := store.GetEntityNeighborhood(ctx, root, limit)
		if err != nil {
			return nil, err
		}
		result[root] = neighborhood
	}
	return result, nil
}

func (s *QueryStore) sample(key string) bool {
	return sampleAtPercent(key, s.samplePercent)
}

func (s *QueryStore) verifyCanary(operation, key string) bool {
	return sampleAtPercent("canary-verify\x00"+operation+"\x00"+key, s.verifyPercent)
}

func sampleAtPercent(key string, percent uint32) bool {
	if percent == 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	digest := sha256.Sum256([]byte(key))
	return binary.BigEndian.Uint32(digest[:4])%100 < percent
}

func (s *QueryStore) recordCanaryRoute(ctx context.Context, operation, authority string, err error, started time.Time) {
	status := "success"
	if err != nil {
		status = "error"
		// #nosec G706 -- operation and authority use closed vocabularies; the
		// percentage is validated configuration and the error is emitted only
		// as a locally generated digest.
		log.Printf(
			"organizational graph canary route operation=%s authority=%s status=error configured_percent=%d error_sha256=%s",
			operation,
			authority,
			s.samplePercent,
			digestString(err.Error()),
		)
	}
	observability.RecordOrganizationalGraphCanaryRoute(ctx, observability.OrganizationalGraphCanaryRouteMetrics{
		Operation:         operation,
		Authority:         authority,
		Status:            status,
		ConfiguredPercent: int(s.samplePercent),
		Duration:          time.Since(started),
	})
}

func (s *QueryStore) recordCanaryVerification(ctx context.Context, operation string, legacy any, legacyErr error, rust any, started time.Time) {
	status := comparisonStatus(legacy, legacyErr, rust, nil)
	if status != "match" {
		logComparisonReceipt(ctx, operation, status, legacy, rust, legacyErr)
	}
	observability.RecordOrganizationalGraphCanaryVerification(ctx, observability.OrganizationalGraphCanaryVerificationMetrics{
		Operation: operation,
		Status:    status,
		Duration:  time.Since(started),
	})
}

func (s *QueryStore) recordComparison(ctx context.Context, operation string, legacy, rust any, rustErr error, started time.Time) {
	status := comparisonStatus(legacy, nil, rust, rustErr)
	if status != "match" {
		logComparisonReceipt(ctx, operation, status, legacy, rust, rustErr)
	}
	observability.RecordOrganizationalGraphShadow(ctx, observability.OrganizationalGraphShadowMetrics{
		Operation: operation,
		Status:    status,
		Duration:  time.Since(started),
	})
}

func comparisonStatus(legacy any, legacyErr error, rust any, rustErr error) string {
	switch {
	case rustErr != nil:
		return "rust_error"
	case legacyErr != nil:
		return "legacy_error"
	}
	legacyJSON, legacyMarshalErr := json.Marshal(legacy)
	rustJSON, rustMarshalErr := json.Marshal(rust)
	if legacyMarshalErr != nil || rustMarshalErr != nil {
		return "comparison_error"
	}
	if !bytes.Equal(legacyJSON, rustJSON) {
		return "mismatch"
	}
	return "match"
}

func logComparisonReceipt(ctx context.Context, operation, status string, legacy, rust any, comparisonErr error) {
	legacyDigest, legacyShape := comparisonReceipt(legacy)
	rustDigest, rustShape := comparisonReceipt(rust)
	errorDigest := ""
	if comparisonErr != nil {
		errorDigest = digestString(comparisonErr.Error())
	}
	traceID := trace.SpanContextFromContext(ctx).TraceID().String()
	// #nosec G706 -- operation and status use closed vocabularies; trace IDs
	// and every receipt value are locally generated hex, counts, or type names.
	log.Printf(
		"organizational graph parity operation=%s status=%s trace_id=%s legacy_sha256=%s rust_sha256=%s legacy_shape=%q rust_shape=%q error_sha256=%s",
		operation,
		status,
		traceID,
		legacyDigest,
		rustDigest,
		legacyShape,
		rustShape,
		errorDigest,
	)
}

func comparisonReceipt(value any) (string, string) {
	if value == nil {
		return "", "nil"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", "unencodable"
	}
	shape := fmt.Sprintf("type=%T", value)
	switch typed := value.(type) {
	case *ports.EntityNeighborhood:
		if typed == nil {
			return digestBytes(encoded), "neighborhood:nil"
		}
		shape = fmt.Sprintf(
			"neighborhood:root=%t,neighbors=%d,relations=%d",
			typed.Root != nil,
			len(typed.Neighbors),
			len(typed.Relations),
		)
	case map[string]*ports.EntityNeighborhood:
		neighbors, relations := 0, 0
		for _, neighborhood := range typed {
			if neighborhood != nil {
				neighbors += len(neighborhood.Neighbors)
				relations += len(neighborhood.Relations)
			}
		}
		shape = fmt.Sprintf(
			"neighborhood_batch:roots=%d,neighbors=%d,relations=%d",
			len(typed),
			neighbors,
			relations,
		)
	}
	return digestBytes(encoded), shape
}

func digestString(value string) string {
	return digestBytes([]byte(value))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest)
}

func (s *QueryStore) ExecuteReadCypher(ctx context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	if s.compatibility == nil {
		return nil, ports.ErrGraphTypedOperationRequired
	}
	return s.compatibility.ExecuteReadCypher(ctx, request)
}

func (s *QueryStore) CountProjectedLinksMissingAssertions(ctx context.Context, tenantID string, relations []string) (uint32, error) {
	if s.compatibility == nil {
		return 0, ports.ErrGraphTypedOperationRequired
	}
	store, ok := s.compatibility.(ports.ProjectionAssertionCoverageStore)
	if !ok {
		return 0, errors.New("compatibility graph store does not support projection assertion coverage")
	}
	return store.CountProjectedLinksMissingAssertions(ctx, tenantID, relations)
}

func (s *QueryStore) MigrateProjectedLinkAssertions(ctx context.Context, request ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	if s.compatibility == nil {
		return ports.ProjectionAssertionMigrationResult{}, ports.ErrGraphTypedOperationRequired
	}
	store, ok := s.compatibility.(ports.ProjectionAssertionMigrator)
	if !ok {
		return ports.ProjectionAssertionMigrationResult{}, errors.New("compatibility graph store does not support projection assertion migration")
	}
	return store.MigrateProjectedLinkAssertions(ctx, request)
}

func graphRPCError(operation string, err error) error {
	if connect.CodeOf(err) == connect.CodeNotFound {
		return ports.ErrGraphEntityNotFound
	}
	return fmt.Errorf("rust graph %s: %w", operation, err)
}

func productNeighborhood(rootKey string, rust *cerebrographv1.ExpandResponse) (*ports.EntityNeighborhood, error) {
	if rust == nil || rust.GetRoot() == nil {
		return nil, errors.New("rust graph neighborhood is missing its root")
	}
	if rust.GetTenantId() != cerebrourn.TenantID(rootKey) {
		return nil, errors.New("rust graph neighborhood belongs to a different tenant")
	}
	if !cerebrourn.SameTenant(productEntityKey(rust.GetRoot()), rust.GetTenantId()) {
		return nil, errors.New("rust graph root is missing its tenant-scoped agent key")
	}
	keys := make(map[string]string, len(rust.GetEntities())+1)
	entityIDs := map[string]string{rootKey: rust.GetRoot().GetEntityId()}
	keys[rust.GetRoot().GetEntityId()] = rootKey
	for _, entity := range rust.GetEntities() {
		if entity == nil {
			return nil, errors.New("rust graph neighborhood contains an empty entity")
		}
		key := productEntityKey(entity)
		if !cerebrourn.SameTenant(key, rust.GetTenantId()) {
			return nil, errors.New("rust graph entity is missing its tenant-scoped agent key")
		}
		if existing, exists := entityIDs[key]; exists && existing != entity.GetEntityId() {
			return nil, errors.New("rust graph returned duplicate product entity keys")
		}
		entityIDs[key] = entity.GetEntityId()
		keys[entity.GetEntityId()] = key
	}
	result := &ports.EntityNeighborhood{
		Root:      productNode(rootKey, rust.GetRoot()),
		Neighbors: make([]*ports.NeighborhoodNode, 0, len(rust.GetEntities())),
		Relations: make([]*ports.NeighborhoodRelation, 0, len(rust.GetEdges())),
	}
	for _, entity := range rust.GetEntities() {
		key := keys[entity.GetEntityId()]
		result.Neighbors = append(result.Neighbors, productNode(key, entity))
	}
	seenRelations := make(map[string]struct{}, len(rust.GetEdges()))
	for _, edge := range rust.GetEdges() {
		if edge == nil {
			return nil, errors.New("rust graph neighborhood contains an empty edge")
		}
		from, fromOK := keys[edge.GetFromEntityId()]
		to, toOK := keys[edge.GetToEntityId()]
		if !fromOK || !toOK {
			return nil, errors.New("rust graph edge references an entity outside its neighborhood")
		}
		relationKey := from + "\x00" + edge.GetRelation() + "\x00" + to
		if _, seen := seenRelations[relationKey]; seen {
			continue
		}
		seenRelations[relationKey] = struct{}{}
		attributes := map[string]string{"source_runtime_id": edge.GetSourceRuntimeId()}
		if edge.GetIdentityBinding() {
			attributes["identity_binding"] = "true"
		}
		result.Relations = append(result.Relations, &ports.NeighborhoodRelation{
			FromURN:    from,
			Relation:   edge.GetRelation(),
			ToURN:      to,
			Attributes: attributes,
		})
	}
	return result, nil
}

func productNode(key string, entity *cerebrographv1.GraphEntity) *ports.NeighborhoodNode {
	entityType := entity.GetProperties()["entity_type"]
	if entityType == "" {
		entityType = entity.GetEntityKind()
	}
	return &ports.NeighborhoodNode{URN: key, EntityType: entityType, Label: entity.GetLabel()}
}

func productEntityKey(entity *cerebrographv1.GraphEntity) string {
	return strings.TrimSpace(entity.GetAgentKey())
}

func normalizedLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	if limit > 500 {
		return 500
	}
	return limit
}
