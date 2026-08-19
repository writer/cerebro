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
	"net/http"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"

	cerebrographv1 "github.com/writer/cerebro/gen/cerebro/graph/v1"
	"github.com/writer/cerebro/gen/cerebro/graph/v1/cerebrographv1connect"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/parityrun"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	maxResponseBytes         = 4 << 20
	maxBatchRoots            = 100
	maxConcurrentComparisons = 32
)

var (
	errComparisonCapacity         = errors.New("organizational graph comparison capacity exhausted")
	errRustGraphOmittedRoot       = errors.New("rust graph omitted a requested root")
	errRustGraphDifferentRoot     = errors.New("rust graph returned a different root")
	errRustGraphMissingRootID     = errors.New("rust graph root is missing its entity ID")
	errRustGraphDuplicateEntityID = errors.New("rust graph returned duplicate entity IDs")
)

type readMode uint8

const (
	readModeAuthority readMode = iota
	readModeShadow
	readModeLegacy
)

// QueryStore serves bounded product reads from Rust. When a compatibility
// reader is present, callers not yet moved from raw Cypher can still use it.
// Without one, those callers fail explicitly instead of falling back.
type QueryStore struct {
	compatibility ports.GraphNeighborhoodStore
	rawCypher     ports.RawCypherQueryStore
	baseURL       string
	httpClient    *http.Client
	graph         cerebrographv1connect.OrganizationalGraphServiceClient
	lifecycle     cerebrov1connect.SecurityLifecycleServiceClient
	auth          tenantAuthenticator
	mode          readMode
	samplePercent uint32
	timeout       time.Duration
	comparisons   chan struct{}
}

// ReadinessStore selects the product read authority when configured.
func ReadinessStore(compatibility, authority ports.GraphStore) ports.GraphStore {
	if authority != nil {
		return authority
	}
	return compatibility
}

func NewQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration) (*QueryStore, error) {
	return newQueryStore(compatibility, compatibility, baseURL, sharedSecret, timeout, readModeAuthority, 100)
}

// NewConfiguredQueryStore selects one validated deployment read strategy.
func NewConfiguredQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, mode string, shadowPercent int) (*QueryStore, error) {
	return NewConfiguredQueryStoreWithCompatibility(
		compatibility,
		compatibility,
		baseURL,
		sharedSecret,
		timeout,
		mode,
		shadowPercent,
	)
}

// NewConfiguredQueryStoreWithCompatibility keeps typed Go rollback reads
// separate from raw Cypher compatibility. Authority mode needs only the raw
// compatibility port; legacy and shadow also require typed Go reads.
func NewConfiguredQueryStoreWithCompatibility(
	compatibility ports.GraphNeighborhoodStore,
	rawCypher ports.RawCypherQueryStore,
	baseURL, sharedSecret string,
	timeout time.Duration,
	mode string,
	shadowPercent int,
) (*QueryStore, error) {
	switch mode {
	case "legacy":
		if compatibility == nil {
			return nil, errors.New("legacy graph reads require the compatibility store")
		}
		return newQueryStore(compatibility, rawCypher, baseURL, sharedSecret, timeout, readModeLegacy, 0)
	case "shadow":
		if compatibility == nil {
			return nil, errors.New("shadow graph reads require the legacy compatibility store")
		}
		if shadowPercent <= 0 || shadowPercent > 100 {
			return nil, errors.New("shadow graph read percent must be between 1 and 100")
		}
		return newQueryStore(compatibility, rawCypher, baseURL, sharedSecret, timeout, readModeShadow, uint32(shadowPercent)) // #nosec G115 -- validated above.
	case "canary":
		return nil, errors.New("canary graph reads are no longer supported")
	case "", "authority":
		// Config.Load normalizes an omitted mode to authority. Accept the zero
		// value here as well for callers that construct Config directly.
		return newQueryStore(compatibility, rawCypher, baseURL, sharedSecret, timeout, readModeAuthority, 100)
	default:
		return nil, fmt.Errorf("unsupported organizational graph read mode %q", mode)
	}
}

// NewLegacyQueryStore keeps Go as the explicit product-read authority while a
// deployment rolls back or completes Rust qualification. It does not call the
// Rust read plane.
func NewLegacyQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration) (*QueryStore, error) {
	if compatibility == nil {
		return nil, errors.New("legacy graph reads require the compatibility store")
	}
	return newQueryStore(compatibility, compatibility, baseURL, sharedSecret, timeout, readModeLegacy, 0)
}

func NewShadowQueryStore(compatibility ports.GraphQueryStore, baseURL, sharedSecret string, timeout time.Duration, shadowPercent int) (*QueryStore, error) {
	if compatibility == nil {
		return nil, errors.New("shadow graph reads require the legacy compatibility store")
	}
	if shadowPercent <= 0 || shadowPercent > 100 {
		return nil, errors.New("shadow graph read percent must be between 1 and 100")
	}
	return newQueryStore(compatibility, compatibility, baseURL, sharedSecret, timeout, readModeShadow, uint32(shadowPercent)) // #nosec G115 -- validated above.
}

func newQueryStore(compatibility ports.GraphNeighborhoodStore, rawCypher ports.RawCypherQueryStore, baseURL, sharedSecret string, timeout time.Duration, mode readMode, samplePercent uint32) (*QueryStore, error) {
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
		rawCypher:     rawCypher,
		baseURL:       baseURL,
		httpClient:    httpClient,
		graph:         cerebrographv1connect.NewOrganizationalGraphServiceClient(httpClient, baseURL),
		lifecycle:     cerebrov1connect.NewSecurityLifecycleServiceClient(httpClient, baseURL),
		auth:          auth,
		mode:          mode,
		samplePercent: samplePercent,
		timeout:       timeout,
		comparisons:   make(chan struct{}, maxConcurrentComparisons),
	}, nil
}

// ListSecurityLifecycle reads the Rust-owned credential and certificate
// lifecycle projection. The bootstrap remains a transport and authentication
// adapter; it does not re-evaluate lifecycle policy.
func (s *QueryStore) ListSecurityLifecycle(ctx context.Context, query *cerebrov1.SecurityLifecycleQuery) (*cerebrov1.SecurityLifecycleQueryResult, error) {
	if query == nil {
		return nil, errors.New("security lifecycle query is required")
	}
	tenantID := strings.TrimSpace(query.GetTenantId())
	if tenantID == "" {
		return nil, errors.New("security lifecycle tenant_id is required")
	}
	request := connect.NewRequest(&cerebrov1.ListSecurityLifecycleRequest{Query: query})
	if err := s.auth.authorizeHeader(request.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.lifecycle.ListSecurityLifecycle(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("list Rust security lifecycle: %w", err)
	}
	if response.Msg.GetResult() == nil {
		return nil, errors.New("rust security lifecycle response omitted result")
	}
	return response.Msg.GetResult(), nil
}

// ResolveSecurityLifecycleFinding resolves only the Rust durable graph
// boundary. It does not create or read GRC findings, evidence, or audit packets.
func (s *QueryStore) ResolveSecurityLifecycleFinding(ctx context.Context, tenantID, findingURN string) (*cerebrov1.ResolveSecurityLifecycleFindingResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	findingURN = strings.TrimSpace(findingURN)
	if tenantID == "" {
		return nil, errors.New("security lifecycle tenant_id is required")
	}
	if findingURN == "" {
		return nil, errors.New("security lifecycle finding_urn is required")
	}
	if len(findingURN) > 4096 {
		return nil, errors.New("security lifecycle finding_urn exceeds 4096 bytes")
	}
	request := connect.NewRequest(&cerebrov1.ResolveSecurityLifecycleFindingRequest{
		TenantId:   tenantID,
		FindingUrn: findingURN,
	})
	if err := s.auth.authorizeHeader(request.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.lifecycle.ResolveSecurityLifecycleFinding(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("resolve Rust security lifecycle finding: %w", err)
	}
	if response.Msg.GetRecord() == nil {
		return nil, errors.New("rust security lifecycle finding response omitted record")
	}
	return response.Msg, nil
}

func (s *QueryStore) Ping(ctx context.Context) (err error) {
	switch s.mode {
	case readModeAuthority:
		return s.pingRust(ctx)
	case readModeLegacy:
		return s.pingCompatibility(ctx)
	case readModeShadow:
		if err := s.pingCompatibility(ctx); err != nil {
			return err
		}
		s.scheduleShadowComparison(ctx, "readiness", nil, func(comparisonCtx context.Context) (any, error) {
			return nil, s.pingRust(comparisonCtx)
		})
		return nil
	default:
		return errors.New("organizational graph read mode is invalid")
	}
}

func (s *QueryStore) pingCompatibility(ctx context.Context) error {
	if s.compatibility == nil {
		return errors.New("compatibility graph is unavailable")
	}
	if err := s.compatibility.Ping(ctx); err != nil {
		return fmt.Errorf("compatibility graph health: %w", err)
	}
	return nil
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
	if s.mode == readModeLegacy {
		return s.compatibility.GetEntityNeighborhood(ctx, rootURN, limit)
	}
	if s.mode == readModeAuthority {
		return s.getRustEntityNeighborhood(ctx, rootURN, limit)
	}
	legacy, err := s.compatibility.GetEntityNeighborhood(ctx, rootURN, limit)
	if err != nil || !s.sample(rootURN) {
		return legacy, err
	}
	s.scheduleShadowComparison(ctx, "expand", legacy, func(comparisonCtx context.Context) (any, error) {
		return s.getRustEntityNeighborhood(comparisonCtx, rootURN, limit)
	})
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
	if s.mode == readModeLegacy {
		return legacyNeighborhoods(ctx, s.compatibility, rootURNs, limit)
	}
	sampleKey := strings.Join(rootURNs, "\x00")
	if s.mode == readModeAuthority {
		return s.getRustEntityNeighborhoods(ctx, rootURNs, limit)
	}
	legacy, err := legacyNeighborhoods(ctx, s.compatibility, rootURNs, limit)
	if err != nil || !s.sample(sampleKey) {
		return legacy, err
	}
	s.scheduleShadowComparison(ctx, "expand_batch", legacy, func(comparisonCtx context.Context) (any, error) {
		return s.getRustEntityNeighborhoods(comparisonCtx, rootURNs, limit)
	})
	return legacy, nil
}

// CompareExposureCoverage reads one bounded comparison from Rust. It never
// delegates to the legacy raw-Cypher compatibility store.
func (s *QueryStore) CompareExposureCoverage(ctx context.Context, request ports.ExposureCoverageRequest) (*ports.ExposureCoverageResult, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, errors.New("exposure coverage tenant_id is required")
	}
	if request.Limit < 1 || request.Limit > 100 {
		return nil, errors.New("exposure coverage limit must be between 1 and 100")
	}
	message := &cerebrographv1.CompareExposureCoverageRequest{
		TenantId: tenantID,
		Profile: &cerebrographv1.ExposureCoverageProfile{
			PrimarySourceId:              request.Profile.PrimarySourceID,
			PrimaryEntityKindPrefix:      request.Profile.PrimaryEntityKindPrefix,
			CorroboratingSourceId:        request.Profile.CorroboratingSourceID,
			CorroboratingEntityKind:      request.Profile.CorroboratingEntityKind,
			IndicatorKinds:               append([]string(nil), request.Profile.IndicatorKinds...),
			AccountKind:                  request.Profile.AccountKind,
			CorroboratingObservationKind: request.Profile.CorroboratingObservationKind,
		},
		AccountId: strings.TrimSpace(request.AccountID),
		Region:    strings.TrimSpace(request.Region),
		Query:     strings.TrimSpace(request.Query),
		Limit:     uint32(request.Limit), // #nosec G115 -- validated above to 1..100.
	}
	rpcRequest := connect.NewRequest(message)
	if err := s.auth.authorizeHeader(rpcRequest.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.graph.CompareExposureCoverage(ctx, rpcRequest)
	if err != nil {
		return nil, graphRPCError("compare exposure coverage", err)
	}
	return productExposureCoverage(tenantID, request.Limit, response.Msg)
}

func productExposureCoverage(tenantID string, limit int, response *cerebrographv1.CompareExposureCoverageResponse) (*ports.ExposureCoverageResult, error) {
	if response == nil || response.GetCounts() == nil || response.GetCompleteness() == nil {
		return nil, errors.New("rust exposure coverage response is incomplete")
	}
	if response.GetTenantId() != tenantID {
		return nil, errors.New("rust exposure coverage response belongs to a different tenant")
	}
	if len(response.GetTypeCounts()) > 50 || len(response.GetOverlaps()) > limit || len(response.GetPrimaryOnly()) > limit || len(response.GetCorroboratingOnly()) > limit || len(response.GetAccounts()) > limit {
		return nil, errors.New("rust exposure coverage response exceeds its bound")
	}
	result := &ports.ExposureCoverageResult{
		TenantID:      tenantID,
		GraphRevision: response.GetGraphRevision(),
		Counts: ports.ExposureCoverageCounts{
			PrimaryEntities:                  response.GetCounts().GetPrimaryEntities(),
			Indicators:                       response.GetCounts().GetIndicators(),
			HostIndicators:                   response.GetCounts().GetHostIndicators(),
			IPIndicators:                     response.GetCounts().GetIpIndicators(),
			OverlappingPrimaryEntities:       response.GetCounts().GetOverlappingPrimaryEntities(),
			OverlappingIndicators:            response.GetCounts().GetOverlappingIndicators(),
			OverlappingCorroboratingEntities: response.GetCounts().GetOverlappingCorroboratingEntities(),
		},
		Completeness: ports.ExposureCoverageCompleteness{
			TypeCountsTruncated:        response.GetCompleteness().GetTypeCountsTruncated(),
			OverlapsTruncated:          response.GetCompleteness().GetOverlapsTruncated(),
			PrimaryOnlyTruncated:       response.GetCompleteness().GetPrimaryOnlyTruncated(),
			CorroboratingOnlyTruncated: response.GetCompleteness().GetCorroboratingOnlyTruncated(),
			AccountsTruncated:          response.GetCompleteness().GetAccountsTruncated(),
		},
	}
	for _, value := range response.GetTypeCounts() {
		if value == nil || strings.TrimSpace(value.GetEntityKind()) == "" {
			return nil, errors.New("rust exposure coverage response contains an invalid kind count")
		}
		result.TypeCounts = append(result.TypeCounts, ports.ExposureCoverageKindCount{EntityKind: value.GetEntityKind(), Count: value.GetCount()})
	}
	for _, value := range response.GetOverlaps() {
		if value == nil {
			return nil, errors.New("rust exposure coverage response contains an empty overlap")
		}
		primary, err := productExposureEntity(tenantID, value.GetPrimary())
		if err != nil {
			return nil, err
		}
		indicator, err := productExposureEntity(tenantID, value.GetIndicator())
		if err != nil {
			return nil, err
		}
		corroborating, err := productExposureEntity(tenantID, value.GetCorroborating())
		if err != nil {
			return nil, err
		}
		result.Overlaps = append(result.Overlaps, ports.ExposureCoverageOverlap{Primary: primary, Indicator: indicator, Corroborating: corroborating})
	}
	for _, value := range response.GetPrimaryOnly() {
		if value == nil {
			return nil, errors.New("rust exposure coverage response contains an empty primary-only sample")
		}
		primary, err := productExposureEntity(tenantID, value.GetPrimary())
		if err != nil {
			return nil, err
		}
		indicator, err := productExposureEntity(tenantID, value.GetIndicator())
		if err != nil {
			return nil, err
		}
		result.PrimaryOnly = append(result.PrimaryOnly, ports.ExposureCoveragePair{Primary: primary, Indicator: indicator})
	}
	for _, value := range response.GetCorroboratingOnly() {
		if value == nil {
			return nil, errors.New("rust exposure coverage response contains an empty corroborating-only sample")
		}
		corroborating, err := productExposureEntity(tenantID, value.GetCorroborating())
		if err != nil {
			return nil, err
		}
		indicator, err := productExposureEntity(tenantID, value.GetIndicator())
		if err != nil {
			return nil, err
		}
		result.CorroboratingOnly = append(result.CorroboratingOnly, ports.ExposureCoverageCorroboratingOnly{Corroborating: corroborating, Indicator: indicator})
	}
	for _, value := range response.GetAccounts() {
		if value == nil {
			return nil, errors.New("rust exposure coverage response contains an empty account")
		}
		account, err := productExposureEntity(tenantID, value.GetAccount())
		if err != nil {
			return nil, err
		}
		result.Accounts = append(result.Accounts, ports.ExposureCoverageAccount{Account: account, PrimaryEntities: value.GetPrimaryEntities(), CorroboratingObservations: value.GetCorroboratingObservations()})
	}
	return result, nil
}

func productExposureEntity(tenantID string, entity *cerebrographv1.GraphEntity) (ports.ExposureCoverageEntity, error) {
	if entity == nil || !cerebrourn.SameTenant(entity.GetAgentKey(), tenantID) || strings.TrimSpace(entity.GetEntityKind()) == "" {
		return ports.ExposureCoverageEntity{}, errors.New("rust exposure coverage response contains an invalid entity")
	}
	return ports.ExposureCoverageEntity{URN: entity.GetAgentKey(), EntityType: entity.GetEntityKind(), Label: entity.GetLabel()}, nil
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
	if len(result) != len(seen) {
		return nil, errRustGraphOmittedRoot
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

func legacyNeighborhoods(ctx context.Context, store ports.GraphNeighborhoodStore, roots []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
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

func (s *QueryStore) scheduleShadowComparison(ctx context.Context, operation string, legacy any, compare func(context.Context) (any, error)) {
	if !s.scheduleComparison(ctx, func(comparisonCtx context.Context) {
		started := time.Now()
		rust, rustErr := compare(comparisonCtx)
		s.recordComparison(comparisonCtx, operation, legacy, rust, rustErr, started)
	}) {
		logComparisonReceipt(ctx, operation, "dropped", legacy, nil, errComparisonCapacity)
		observability.RecordOrganizationalGraphShadow(ctx, observability.OrganizationalGraphShadowMetrics{
			Operation: operation,
			Status:    "dropped",
		})
	}
}

func (s *QueryStore) scheduleComparison(ctx context.Context, compare func(context.Context)) bool {
	select {
	case s.comparisons <- struct{}{}:
	default:
		return false
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		defer func() { <-s.comparisons }()
		comparisonCtx, cancel := context.WithTimeout(detached, s.timeout)
		defer cancel()
		compare(comparisonCtx)
	}()
	return true
}

func (s *QueryStore) recordComparison(ctx context.Context, operation string, legacy, rust any, rustErr error, started time.Time) {
	status := comparisonStatus(legacy, nil, rust, rustErr)
	logComparisonReceipt(ctx, operation, status, legacy, rust, rustErr)
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
	legacyJSON, legacyMarshalErr := canonicalComparisonJSON(legacy)
	rustJSON, rustMarshalErr := canonicalComparisonJSON(rust)
	if legacyMarshalErr != nil || rustMarshalErr != nil {
		return "comparison_error"
	}
	if !bytes.Equal(legacyJSON, rustJSON) {
		return "mismatch"
	}
	return "match"
}

func logComparisonReceipt(ctx context.Context, operation, status string, legacy, rust any, comparisonErr error) {
	parity := parityrun.FromContext(ctx)
	legacyDigest, legacyShape := comparisonReceipt(legacy)
	rustDigest, rustShape := comparisonReceipt(rust)
	errorDigest := ""
	if comparisonErr != nil {
		errorDigest = digestString(comparisonErr.Error())
	}
	telemetry.Event(ctx, "organizational_graph.parity_receipt", telemetry.Attrs(
		telemetry.Field{Key: "operation", Value: operation},
		telemetry.Field{Key: "status", Value: status},
		telemetry.Field{Key: "parity_run_id", Value: parity.RunID},
		telemetry.Field{Key: "parity_observation_id", Value: parity.ObservationID},
		telemetry.Field{Key: "legacy_sha256", Value: legacyDigest},
		telemetry.Field{Key: "rust_sha256", Value: rustDigest},
		telemetry.Field{Key: "legacy_shape", Value: legacyShape},
		telemetry.Field{Key: "rust_shape", Value: rustShape},
		telemetry.Field{Key: "error_sha256", Value: errorDigest},
	))
}

func comparisonReceipt(value any) (string, string) {
	if value == nil {
		return "", "nil"
	}
	encoded, err := canonicalComparisonJSON(value)
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

func canonicalComparisonJSON(value any) ([]byte, error) {
	return json.Marshal(canonicalComparisonValue(value))
}

func canonicalComparisonValue(value any) any {
	switch typed := value.(type) {
	case *ports.EntityNeighborhood:
		return canonicalNeighborhood(typed)
	case map[string]*ports.EntityNeighborhood:
		canonical := make(map[string]*ports.EntityNeighborhood, len(typed))
		for root, neighborhood := range typed {
			canonical[root] = canonicalNeighborhood(neighborhood)
		}
		return canonical
	default:
		return value
	}
}

func canonicalNeighborhood(neighborhood *ports.EntityNeighborhood) *ports.EntityNeighborhood {
	if neighborhood == nil {
		return nil
	}
	canonical := &ports.EntityNeighborhood{
		Root:      neighborhood.Root,
		Neighbors: append([]*ports.NeighborhoodNode(nil), neighborhood.Neighbors...),
		Relations: append([]*ports.NeighborhoodRelation(nil), neighborhood.Relations...),
	}
	sort.Slice(canonical.Neighbors, func(i, j int) bool {
		left, right := canonical.Neighbors[i], canonical.Neighbors[j]
		if left == nil || right == nil {
			return left == nil && right != nil
		}
		if left.URN != right.URN {
			return left.URN < right.URN
		}
		if left.EntityType != right.EntityType {
			return left.EntityType < right.EntityType
		}
		return left.Label < right.Label
	})
	sort.Slice(canonical.Relations, func(i, j int) bool {
		left, right := canonical.Relations[i], canonical.Relations[j]
		if left == nil || right == nil {
			return left == nil && right != nil
		}
		leftKey, _ := json.Marshal(left)
		rightKey, _ := json.Marshal(right)
		return bytes.Compare(leftKey, rightKey) < 0
	})
	return canonical
}

func digestString(value string) string {
	return digestBytes([]byte(value))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest)
}

func (s *QueryStore) ListEntities(ctx context.Context, request ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error) {
	filter, tenantID, err := entityCatalogFilter(request.Filter)
	if err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > 500 {
		return nil, errors.New("entity catalog limit must be between 1 and 500")
	}
	message := connect.NewRequest(&cerebrographv1.ListEntitiesRequest{Filter: filter, Limit: uint32(request.Limit), AfterAgentKey: strings.TrimSpace(request.AfterAgentKey)}) // #nosec G115 -- bounded above.
	if err := s.auth.authorizeHeader(message.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.graph.ListEntities(ctx, message)
	if err != nil {
		return nil, graphRPCError("list entities", err)
	}
	if response.Msg.GetTenantId() != tenantID || len(response.Msg.GetEntities()) > request.Limit {
		return nil, errors.New("rust entity catalog returned an invalid tenant or bound")
	}
	page := &ports.EntityCatalogPage{TenantID: tenantID, GraphRevision: response.Msg.GetGraphRevision(), Truncated: response.Msg.GetTruncated(), NextAfterAgentKey: response.Msg.GetNextAfterAgentKey()}
	seenEntities := make(map[string]struct{}, len(response.Msg.GetEntities()))
	for _, entity := range response.Msg.GetEntities() {
		converted, err := catalogEntity(tenantID, entity)
		if err != nil {
			return nil, err
		}
		if _, exists := seenEntities[converted.URN]; exists || (filter.GetExactAgentKey() != "" && converted.URN != filter.GetExactAgentKey()) {
			return nil, errors.New("rust entity catalog returned duplicate or non-exact entities")
		}
		seenEntities[converted.URN] = struct{}{}
		page.Entities = append(page.Entities, converted)
	}
	if filter.GetExactAgentKey() != "" && len(page.Entities) > 1 {
		return nil, errors.New("rust entity catalog returned an ambiguous exact key")
	}
	pageKeys := make(map[string]struct{}, len(page.Entities))
	for _, entity := range page.Entities {
		pageKeys[entity.URN] = struct{}{}
	}
	seenCounts := make(map[string]struct{}, len(response.Msg.GetRelationCounts()))
	for _, count := range response.Msg.GetRelationCounts() {
		if count == nil || count.GetCount() == 0 || strings.TrimSpace(count.GetRelation()) == "" || strings.TrimSpace(count.GetNeighborKind()) == "" {
			return nil, errors.New("rust entity catalog returned an invalid relation count")
		}
		if _, ok := pageKeys[count.GetAgentKey()]; !ok || !cerebrourn.SameTenant(count.GetAgentKey(), tenantID) {
			return nil, errors.New("rust entity catalog returned an out-of-page relation count")
		}
		direction, err := catalogRelationDirection(count.GetDirection())
		if err != nil {
			return nil, err
		}
		countKey := count.GetAgentKey() + "\x00" + string(direction) + "\x00" + count.GetRelation() + "\x00" + count.GetNeighborKind()
		if _, exists := seenCounts[countKey]; exists {
			return nil, errors.New("rust entity catalog returned duplicate relation counts")
		}
		seenCounts[countKey] = struct{}{}
		page.RelationCounts = append(page.RelationCounts, ports.EntityRelationCount{AgentKey: count.GetAgentKey(), Direction: direction, Relation: count.GetRelation(), NeighborKind: count.GetNeighborKind(), Count: count.GetCount()})
	}
	if page.Truncated && (page.NextAfterAgentKey == "" || len(page.Entities) != request.Limit) {
		return nil, errors.New("rust entity catalog returned an invalid continuation")
	}
	return page, nil
}

func (s *QueryStore) CountEntityKinds(ctx context.Context, request ports.EntityKindCountRequest) (*ports.EntityKindCountPage, error) {
	filter, tenantID, err := entityCatalogFilter(request.Filter)
	if err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > 500 {
		return nil, errors.New("entity kind count limit must be between 1 and 500")
	}
	message := connect.NewRequest(&cerebrographv1.CountEntityKindsRequest{Filter: filter, Limit: uint32(request.Limit), AfterEntityKind: strings.TrimSpace(request.AfterEntityKind)}) // #nosec G115 -- bounded above.
	if err := s.auth.authorizeHeader(message.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.graph.CountEntityKinds(ctx, message)
	if err != nil {
		return nil, graphRPCError("count entity kinds", err)
	}
	if response.Msg.GetTenantId() != tenantID || len(response.Msg.GetCounts()) > request.Limit {
		return nil, errors.New("rust entity kind counts returned an invalid tenant or bound")
	}
	page := &ports.EntityKindCountPage{TenantID: tenantID, GraphRevision: response.Msg.GetGraphRevision(), Truncated: response.Msg.GetTruncated(), NextAfterEntityKind: response.Msg.GetNextAfterEntityKind()}
	for _, count := range response.Msg.GetCounts() {
		if count == nil || strings.TrimSpace(count.GetEntityKind()) == "" {
			return nil, errors.New("rust entity kind counts returned an invalid kind")
		}
		page.Counts = append(page.Counts, ports.EntityKindCount{EntityKind: count.GetEntityKind(), Count: count.GetCount()})
	}
	if page.Truncated && (page.NextAfterEntityKind == "" || len(page.Counts) != request.Limit) {
		return nil, errors.New("rust entity kind counts returned an invalid continuation")
	}
	return page, nil
}

func (s *QueryStore) ListEntityRelations(ctx context.Context, request ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, errors.New("entity relation tenant_id is required")
	}
	if request.Limit < 1 || request.Limit > 500 {
		return nil, errors.New("entity relation limit must be between 1 and 500")
	}
	directions := make([]cerebrographv1.EntityRelationDirection, 0, len(request.Directions))
	for _, direction := range request.Directions {
		switch direction {
		case ports.EntityRelationIncoming:
			directions = append(directions, cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING)
		case ports.EntityRelationOutgoing:
			directions = append(directions, cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING)
		default:
			return nil, errors.New("entity relation direction is invalid")
		}
	}
	afterDirection := cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_UNSPECIFIED
	switch request.AfterDirection {
	case ports.EntityRelationIncoming:
		afterDirection = cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING
	case ports.EntityRelationOutgoing:
		afterDirection = cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING
	case "":
	default:
		return nil, errors.New("entity relation continuation direction is invalid")
	}
	message := connect.NewRequest(&cerebrographv1.ListEntityRelationsRequest{TenantId: tenantID, AgentKey: strings.TrimSpace(request.AgentKey), Directions: directions, Relations: append([]string(nil), request.Relations...), NeighborKinds: append([]string(nil), request.NeighborKinds...), Limit: uint32(request.Limit), AfterAgentKey: strings.TrimSpace(request.AfterAgentKey), ExpectedGraphRevision: request.ExpectedRevision, AfterRelation: strings.TrimSpace(request.AfterRelation), AfterDirection: afterDirection}) // #nosec G115 -- bounded above.
	if err := s.auth.authorizeHeader(message.Header(), tenantID); err != nil {
		return nil, err
	}
	response, err := s.graph.ListEntityRelations(ctx, message)
	if err != nil {
		return nil, graphRPCError("list entity relations", err)
	}
	if response.Msg.GetTenantId() != tenantID || len(response.Msg.GetRelations()) > request.Limit {
		return nil, errors.New("rust entity relations returned an invalid tenant or bound")
	}
	page := &ports.EntityRelationPage{TenantID: tenantID, GraphRevision: response.Msg.GetGraphRevision(), Truncated: response.Msg.GetTruncated(), NextAfterAgentKey: response.Msg.GetNextAfterAgentKey(), NextAfterRelation: response.Msg.GetNextAfterRelation()}
	for _, relation := range response.Msg.GetRelations() {
		if relation == nil || strings.TrimSpace(relation.GetRelation()) == "" {
			return nil, errors.New("rust entity relations returned an invalid relation")
		}
		entity, err := catalogEntity(tenantID, relation.GetEntity())
		if err != nil {
			return nil, err
		}
		direction := ports.EntityRelationDirection("")
		switch relation.GetDirection() {
		case cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING:
			direction = ports.EntityRelationIncoming
		case cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING:
			direction = ports.EntityRelationOutgoing
		default:
			return nil, errors.New("rust entity relations returned an invalid direction")
		}
		page.Relations = append(page.Relations, ports.EntityCatalogRelation{Direction: direction, Relation: relation.GetRelation(), Entity: entity})
	}
	switch response.Msg.GetNextAfterDirection() {
	case cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING:
		page.NextAfterDirection = ports.EntityRelationIncoming
	case cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING:
		page.NextAfterDirection = ports.EntityRelationOutgoing
	}
	if page.Truncated && (page.NextAfterAgentKey == "" || page.NextAfterRelation == "" || page.NextAfterDirection == "" || len(page.Relations) != request.Limit) {
		return nil, errors.New("rust entity relations returned an invalid continuation")
	}
	return page, nil
}

func entityCatalogFilter(filter ports.EntityCatalogFilter) (*cerebrographv1.EntityCatalogFilter, string, error) {
	tenantID := strings.TrimSpace(filter.TenantID)
	if tenantID == "" {
		return nil, "", errors.New("entity catalog tenant_id is required")
	}
	message := &cerebrographv1.EntityCatalogFilter{TenantId: tenantID, SourceId: strings.TrimSpace(filter.SourceID), RuntimeIds: append([]string(nil), filter.RuntimeIDs...), ExactAgentKey: strings.TrimSpace(filter.ExactAgentKey), IncludeKinds: append([]string(nil), filter.IncludeKinds...), IncludeKindPrefixes: append([]string(nil), filter.IncludeKindPrefixes...), ExcludeKinds: append([]string(nil), filter.ExcludeKinds...), ExcludeKindPrefixes: append([]string(nil), filter.ExcludeKindPrefixes...), Query: strings.TrimSpace(filter.Query), ExpectedGraphRevision: filter.ExpectedRevision, QueryAttributes: filter.QueryAttributes}
	if filter.RelationCounts != nil {
		directions := make([]cerebrographv1.EntityRelationDirection, 0, len(filter.RelationCounts.Directions))
		for _, direction := range filter.RelationCounts.Directions {
			switch direction {
			case ports.EntityRelationIncoming:
				directions = append(directions, cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING)
			case ports.EntityRelationOutgoing:
				directions = append(directions, cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING)
			default:
				return nil, "", errors.New("entity catalog relation-count direction is invalid")
			}
		}
		message.RelationCounts = &cerebrographv1.EntityRelationCountFilter{Directions: directions, Relations: append([]string(nil), filter.RelationCounts.Relations...), NeighborKinds: append([]string(nil), filter.RelationCounts.NeighborKinds...)}
	}
	return message, tenantID, nil
}

func catalogRelationDirection(direction cerebrographv1.EntityRelationDirection) (ports.EntityRelationDirection, error) {
	switch direction {
	case cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_INCOMING:
		return ports.EntityRelationIncoming, nil
	case cerebrographv1.EntityRelationDirection_ENTITY_RELATION_DIRECTION_OUTGOING:
		return ports.EntityRelationOutgoing, nil
	default:
		return "", errors.New("rust entity catalog returned an invalid relation direction")
	}
}

func catalogEntity(tenantID string, entity *cerebrographv1.GraphEntity) (ports.CatalogEntity, error) {
	if entity == nil || !cerebrourn.SameTenant(entity.GetAgentKey(), tenantID) || strings.TrimSpace(entity.GetEntityKind()) == "" {
		return ports.CatalogEntity{}, errors.New("rust entity catalog returned an invalid entity")
	}
	properties := mapsClone(entity.GetProperties())
	return ports.CatalogEntity{URN: entity.GetAgentKey(), TenantID: tenantID, EntityType: entity.GetEntityKind(), Label: entity.GetLabel(), SourceID: properties["source_id"], RuntimeID: entity.GetSourceRuntimeId(), Attributes: properties}, nil
}

func mapsClone(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func (s *QueryStore) ExecuteReadCypher(ctx context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	if s.rawCypher == nil {
		return nil, ports.ErrGraphTypedOperationRequired
	}
	return s.rawCypher.ExecuteReadCypher(ctx, request)
}

func (s *QueryStore) CountProjectedLinksMissingAssertions(ctx context.Context, tenantID string, relations []string) (uint32, error) {
	if s.rawCypher == nil {
		return 0, ports.ErrGraphTypedOperationRequired
	}
	store, ok := s.rawCypher.(ports.ProjectionAssertionCoverageStore)
	if !ok {
		return 0, errors.New("compatibility graph store does not support projection assertion coverage")
	}
	return store.CountProjectedLinksMissingAssertions(ctx, tenantID, relations)
}

func (s *QueryStore) MigrateProjectedLinkAssertions(ctx context.Context, request ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	if s.rawCypher == nil {
		return ports.ProjectionAssertionMigrationResult{}, ports.ErrGraphTypedOperationRequired
	}
	store, ok := s.rawCypher.(ports.ProjectionAssertionMigrator)
	if !ok {
		return ports.ProjectionAssertionMigrationResult{}, errors.New("compatibility graph store does not support projection assertion migration")
	}
	return store.MigrateProjectedLinkAssertions(ctx, request)
}

func graphRPCError(operation string, err error) error {
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		return ports.ErrGraphEntityNotFound
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return fmt.Errorf("%w: rust graph %s: %w", ports.ErrGraphRuntimeUnavailable, operation, err)
	default:
		return fmt.Errorf("rust graph %s: %w", operation, err)
	}
}

func productNeighborhood(rootKey string, rust *cerebrographv1.ExpandResponse) (*ports.EntityNeighborhood, error) {
	if rust == nil || rust.GetRoot() == nil {
		return nil, errors.New("rust graph neighborhood is missing its root")
	}
	if rust.GetTenantId() != cerebrourn.TenantID(rootKey) {
		return nil, errors.New("rust graph neighborhood belongs to a different tenant")
	}
	if productEntityKey(rust.GetRoot()) != strings.TrimSpace(rootKey) {
		return nil, errRustGraphDifferentRoot
	}
	if !cerebrourn.SameTenant(productEntityKey(rust.GetRoot()), rust.GetTenantId()) {
		return nil, errors.New("rust graph root is missing its tenant-scoped agent key")
	}
	if strings.TrimSpace(rust.GetRoot().GetEntityId()) == "" {
		return nil, errRustGraphMissingRootID
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
		if strings.TrimSpace(entity.GetEntityId()) == "" {
			return nil, errors.New("rust graph entity is missing its entity ID")
		}
		if _, exists := keys[entity.GetEntityId()]; exists {
			return nil, errRustGraphDuplicateEntityID
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
