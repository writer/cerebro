// Package organizationalgraph makes the Rust-owned bounded graph API the
// product read authority while retaining the legacy store only for raw Cypher
// compatibility during migration.
package organizationalgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	maxResponseBytes = 4 << 20
	maxBatchRoots    = 100
)

// QueryStore serves bounded product reads from Rust. Raw Cypher remains on the
// compatibility reader until those queries have typed Rust operations.
type QueryStore struct {
	compatibility ports.GraphQueryStore
	baseURL       string
	client        *http.Client
}

// ReadinessStore selects the product read authority when configured. Its Ping
// also checks the compatibility store needed for raw reads during migration.
func ReadinessStore(compatibility, authority ports.GraphStore) ports.GraphStore {
	if authority != nil {
		return authority
	}
	return compatibility
}

func NewQueryStore(compatibility ports.GraphQueryStore, baseURL string, timeout time.Duration) (*QueryStore, error) {
	if compatibility == nil {
		return nil, errors.New("compatibility graph query store is required")
	}
	baseURL, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, errors.New("rust organizational graph timeout must be positive")
	}
	return &QueryStore{
		compatibility: compatibility,
		baseURL:       baseURL,
		client:        &http.Client{Timeout: timeout},
	}, nil
}

func (s *QueryStore) Ping(ctx context.Context) error {
	if err := s.compatibility.Ping(ctx); err != nil {
		return fmt.Errorf("compatibility graph health: %w", err)
	}
	// #nosec G704 -- normalizeBaseURL validates and freezes the operator-set
	// HTTP(S) origin; this package supplies the constant request path.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("build Rust graph health request: %w", err)
	}
	return s.do(request, nil)
}

func (s *QueryStore) GetEntityNeighborhood(ctx context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	rootURN = strings.TrimSpace(rootURN)
	if cerebrourn.TenantID(rootURN) == "" {
		return nil, errors.New("root is not a tenant-scoped Cerebro URN")
	}
	rootOnly := limit <= 0
	request := expandRequest{
		TenantID: cerebrourn.TenantID(rootURN),
		RootKey:  rootURN,
		Depth:    1,
		Limit:    normalizedLimit(limit),
	}
	var neighborhood rustNeighborhood
	if err := s.post(ctx, "/v1/graph/expand", request, &neighborhood); err != nil {
		return nil, err
	}
	product, err := productNeighborhood(rootURN, neighborhood)
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
	var response expandBatchResponse
	if err := s.post(ctx, "/v1/graph/expand-batch", expandBatchRequest{
		TenantID: tenantID,
		RootKeys: roots,
		Depth:    1,
		Limit:    normalizedLimit(limit),
	}, &response); err != nil {
		return nil, err
	}
	result := make(map[string]*ports.EntityNeighborhood, len(response.Neighborhoods))
	for rootURN, neighborhood := range response.Neighborhoods {
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

func (s *QueryStore) ExecuteReadCypher(ctx context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return s.compatibility.ExecuteReadCypher(ctx, request)
}

func (s *QueryStore) CountProjectedLinksMissingAssertions(ctx context.Context, tenantID string, relations []string) (uint32, error) {
	store, ok := s.compatibility.(ports.ProjectionAssertionCoverageStore)
	if !ok {
		return 0, errors.New("compatibility graph store does not support projection assertion coverage")
	}
	return store.CountProjectedLinksMissingAssertions(ctx, tenantID, relations)
}

func (s *QueryStore) MigrateProjectedLinkAssertions(ctx context.Context, request ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	store, ok := s.compatibility.(ports.ProjectionAssertionMigrator)
	if !ok {
		return ports.ProjectionAssertionMigrationResult{}, errors.New("compatibility graph store does not support projection assertion migration")
	}
	return store.MigrateProjectedLinkAssertions(ctx, request)
}

type expandRequest struct {
	TenantID string `json:"tenant_id"`
	RootKey  string `json:"root_key"`
	Depth    int    `json:"depth"`
	Limit    int    `json:"limit"`
}

type expandBatchRequest struct {
	TenantID string   `json:"tenant_id"`
	RootKeys []string `json:"root_keys"`
	Depth    int      `json:"depth"`
	Limit    int      `json:"limit"`
}

type expandBatchResponse struct {
	Neighborhoods map[string]rustNeighborhood `json:"neighborhoods"`
}

type rustEntity struct {
	EntityID   string            `json:"entity_id"`
	AgentKey   string            `json:"agent_key"`
	EntityKind string            `json:"entity_kind"`
	Authority  json.RawMessage   `json:"authority"`
	Label      string            `json:"label"`
	Properties map[string]string `json:"properties"`
}

type rustEdge struct {
	AssertionID     string `json:"assertion_id"`
	From            string `json:"from"`
	Relation        string `json:"relation"`
	To              string `json:"to"`
	SourceRuntimeID string `json:"source_runtime_id"`
	IdentityBinding bool   `json:"identity_binding"`
}

type rustNeighborhood struct {
	TenantID      string       `json:"tenant_id"`
	GraphRevision uint64       `json:"graph_revision"`
	Root          rustEntity   `json:"root"`
	Entities      []rustEntity `json:"entities"`
	Edges         []rustEdge   `json:"edges"`
	Truncated     bool         `json:"truncated"`
}

func (s *QueryStore) post(ctx context.Context, path string, payload any, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode Rust graph request: %w", err)
	}
	// #nosec G704 -- normalizeBaseURL validates and freezes the operator-set
	// HTTP(S) origin; callers in this package supply constant request paths.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build Rust graph request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	return s.do(request, target)
}

func (s *QueryStore) do(request *http.Request, target any) (err error) {
	// #nosec G704 -- requests are constructed only from the validated, frozen
	// sidecar origin and constant paths in this package.
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("read Rust graph: %w", err)
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return ports.ErrGraphEntityNotFound
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return fmt.Errorf("rust graph returned %s", response.Status)
	}
	if target == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode Rust graph response: %w", err)
	}
	return nil
}

func productNeighborhood(rootKey string, rust rustNeighborhood) (*ports.EntityNeighborhood, error) {
	if rust.TenantID != cerebrourn.TenantID(rootKey) {
		return nil, errors.New("rust graph neighborhood belongs to a different tenant")
	}
	if !cerebrourn.SameTenant(productEntityKey(rust.Root), rust.TenantID) {
		return nil, errors.New("rust graph root is missing its tenant-scoped agent key")
	}
	keys := make(map[string]string, len(rust.Entities)+1)
	entityIDs := map[string]string{rootKey: rust.Root.EntityID}
	keys[rust.Root.EntityID] = rootKey
	for _, entity := range rust.Entities {
		key := productEntityKey(entity)
		if !cerebrourn.SameTenant(key, rust.TenantID) {
			return nil, errors.New("rust graph entity is missing its tenant-scoped agent key")
		}
		if existing, exists := entityIDs[key]; exists && existing != entity.EntityID {
			return nil, errors.New("rust graph returned duplicate product entity keys")
		}
		entityIDs[key] = entity.EntityID
		keys[entity.EntityID] = key
	}
	result := &ports.EntityNeighborhood{
		Root:      productNode(rootKey, rust.Root),
		Neighbors: make([]*ports.NeighborhoodNode, 0, len(rust.Entities)),
		Relations: make([]*ports.NeighborhoodRelation, 0, len(rust.Edges)),
	}
	for _, entity := range rust.Entities {
		key := keys[entity.EntityID]
		result.Neighbors = append(result.Neighbors, productNode(key, entity))
	}
	for _, edge := range rust.Edges {
		from, fromOK := keys[edge.From]
		to, toOK := keys[edge.To]
		if !fromOK || !toOK {
			return nil, errors.New("rust graph edge references an entity outside its neighborhood")
		}
		attributes := map[string]string{"source_runtime_id": edge.SourceRuntimeID}
		if edge.IdentityBinding {
			attributes["identity_binding"] = "true"
		}
		result.Relations = append(result.Relations, &ports.NeighborhoodRelation{
			FromURN:    from,
			Relation:   edge.Relation,
			ToURN:      to,
			Attributes: attributes,
		})
	}
	return result, nil
}

func productNode(key string, entity rustEntity) *ports.NeighborhoodNode {
	entityType := entity.Properties["entity_type"]
	if entityType == "" {
		entityType = entity.EntityKind
	}
	return &ports.NeighborhoodNode{URN: key, EntityType: entityType, Label: entity.Label}
}

func productEntityKey(entity rustEntity) string {
	return strings.TrimSpace(entity.AgentKey)
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
