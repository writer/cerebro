// Package organizationalgraph shadows existing graph reads against the
// Rust-owned bounded graph API without changing the response seen by callers.
package organizationalgraph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const maxResponseBytes = 4 << 20

// ShadowReceipt records one semantic comparison without retaining graph data.
type ShadowReceipt struct {
	Status           string
	RootDigest       string
	PrimaryRootFound bool
	RustRootFound    bool
	PrimaryNodes     int
	RustNodes        int
	PrimaryRelations int
	RustRelations    int
}

// ReceiptSink receives bounded comparison receipts.
type ReceiptSink interface {
	Record(context.Context, ShadowReceipt)
}

type logReceiptSink struct{}

func (logReceiptSink) Record(_ context.Context, receipt ShadowReceipt) {
	log.Printf(
		"organizational graph shadow status=%s root_digest=%s primary_root_found=%t rust_root_found=%t primary_nodes=%d rust_nodes=%d primary_relations=%d rust_relations=%d",
		receipt.Status,
		receipt.RootDigest,
		receipt.PrimaryRootFound,
		receipt.RustRootFound,
		receipt.PrimaryNodes,
		receipt.RustNodes,
		receipt.PrimaryRelations,
		receipt.RustRelations,
	)
}

// ShadowQueryStore preserves the existing graph as read authority and compares
// bounded neighborhood reads with the Rust graph in the background.
type ShadowQueryStore struct {
	primary ports.GraphQueryStore
	baseURL string
	client  *http.Client
	sink    ReceiptSink
}

func NewShadowQueryStore(primary ports.GraphQueryStore, baseURL string, timeout time.Duration) (*ShadowQueryStore, error) {
	return newShadowQueryStore(primary, baseURL, timeout, logReceiptSink{})
}

func newShadowQueryStore(primary ports.GraphQueryStore, baseURL string, timeout time.Duration, sink ReceiptSink) (*ShadowQueryStore, error) {
	if primary == nil {
		return nil, errors.New("primary graph query store is required")
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("Rust organizational graph URL is required")
	}
	if timeout <= 0 {
		return nil, errors.New("Rust organizational graph timeout must be positive")
	}
	if sink == nil {
		return nil, errors.New("shadow receipt sink is required")
	}
	return &ShadowQueryStore{
		primary: primary,
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
		sink:    sink,
	}, nil
}

func (s *ShadowQueryStore) Ping(ctx context.Context) error {
	return s.primary.Ping(ctx)
}

func (s *ShadowQueryStore) GetEntityNeighborhood(ctx context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	primary, err := s.primary.GetEntityNeighborhood(ctx, rootURN, limit)
	if err != nil {
		return nil, err
	}
	s.shadow(ctx, rootURN, limit, primary)
	return primary, nil
}

func (s *ShadowQueryStore) GetEntityNeighborhoods(ctx context.Context, rootURNs []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
	batch, ok := s.primary.(ports.GraphNeighborhoodBatchStore)
	if !ok {
		result := make(map[string]*ports.EntityNeighborhood, len(rootURNs))
		for _, rootURN := range rootURNs {
			neighborhood, err := s.GetEntityNeighborhood(ctx, rootURN, limit)
			if err != nil {
				return nil, err
			}
			result[rootURN] = neighborhood
		}
		return result, nil
	}
	result, err := batch.GetEntityNeighborhoods(ctx, rootURNs, limit)
	if err != nil {
		return nil, err
	}
	for _, rootURN := range rootURNs {
		s.shadow(ctx, rootURN, limit, result[rootURN])
	}
	return result, nil
}

func (s *ShadowQueryStore) ExecuteReadCypher(ctx context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return s.primary.ExecuteReadCypher(ctx, request)
}

func (s *ShadowQueryStore) shadow(parent context.Context, rootURN string, limit int, primary *ports.EntityNeighborhood) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.client.Timeout)
	go func() {
		defer cancel()
		receipt := compare(primary, nil, rootURN)
		rust, err := s.expand(ctx, rootURN, limit)
		if err != nil {
			receipt.Status = "unavailable"
		} else {
			receipt = compare(primary, rust, rootURN)
		}
		s.sink.Record(ctx, receipt)
	}()
}

type expandRequest struct {
	TenantID string `json:"tenant_id"`
	RootKey  string `json:"root_key"`
	Depth    int    `json:"depth"`
	Limit    int    `json:"limit"`
}

type rustEntity struct {
	EntityID   string            `json:"entity_id"`
	EntityKind string            `json:"entity_kind"`
	Label      string            `json:"label"`
	Properties map[string]string `json:"properties"`
}

type rustEdge struct {
	From     string `json:"from"`
	Relation string `json:"relation"`
	To       string `json:"to"`
}

type rustNeighborhood struct {
	Root     rustEntity   `json:"root"`
	Entities []rustEntity `json:"entities"`
	Edges    []rustEdge   `json:"edges"`
}

func (s *ShadowQueryStore) expand(ctx context.Context, rootURN string, limit int) (*rustNeighborhood, error) {
	tenantID := cerebrourn.TenantID(rootURN)
	if tenantID == "" {
		return nil, errors.New("root is not a tenant-scoped Cerebro URN")
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	payload, err := json.Marshal(expandRequest{TenantID: tenantID, RootKey: rootURN, Depth: 1, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("encode Rust graph request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/graph/expand", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build Rust graph request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read Rust graph: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return nil, fmt.Errorf("Rust graph returned %s", response.Status)
	}
	var neighborhood rustNeighborhood
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&neighborhood); err != nil {
		return nil, fmt.Errorf("decode Rust graph response: %w", err)
	}
	return &neighborhood, nil
}

func compare(primary *ports.EntityNeighborhood, rust *rustNeighborhood, rootURN string) ShadowReceipt {
	receipt := ShadowReceipt{Status: "mismatch", RootDigest: digest(rootURN)}
	if primary != nil {
		receipt.PrimaryRootFound = primary.Root != nil
		receipt.PrimaryNodes = len(primary.Neighbors)
		receipt.PrimaryRelations = len(primary.Relations)
	}
	if rust != nil {
		receipt.RustRootFound = rust.Root.EntityID != ""
		receipt.RustNodes = len(rust.Entities)
		receipt.RustRelations = len(rust.Edges)
	}
	if receipt.PrimaryRootFound == receipt.RustRootFound &&
		receipt.PrimaryNodes == receipt.RustNodes &&
		receipt.PrimaryRelations == receipt.RustRelations {
		receipt.Status = "match"
	}
	return receipt
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}
