package organizationalgraph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type queryStoreStub struct {
	neighborhood *ports.EntityNeighborhood
}

func (s queryStoreStub) Ping(context.Context) error { return nil }

func (s queryStoreStub) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return s.neighborhood, nil
}

func (s queryStoreStub) ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return []ports.CypherRow{{Values: map[string]any{"authority": "go"}}}, nil
}

type receiptSink struct {
	receipts chan ShadowReceipt
}

func (s receiptSink) Record(_ context.Context, receipt ShadowReceipt) {
	s.receipts <- receipt
}

func TestShadowQueryStoreReturnsPrimaryAndRecordsRustComparison(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/graph/expand" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var request expandRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.TenantID != "tenant-a" || request.RootKey != "urn:cerebro:tenant-a:runtime_file:asset-1" || request.Depth != 1 {
			t.Fatalf("request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(rustNeighborhood{
			Root:     rustEntity{EntityID: "entity-1"},
			Entities: []rustEntity{{EntityID: "entity-2"}},
			Edges:    []rustEdge{{From: "entity-1", Relation: "contains", To: "entity-2"}},
		})
	}))
	defer server.Close()

	primary := &ports.EntityNeighborhood{
		Root:      &ports.NeighborhoodNode{URN: "urn:cerebro:tenant-a:runtime_file:asset-1"},
		Neighbors: []*ports.NeighborhoodNode{{URN: "urn:cerebro:tenant-a:runtime_file:asset-2"}},
		Relations: []*ports.NeighborhoodRelation{{FromURN: "one", Relation: "contains", ToURN: "two"}},
	}
	receipts := make(chan ShadowReceipt, 1)
	store, err := newShadowQueryStore(queryStoreStub{neighborhood: primary}, server.URL, time.Second, receiptSink{receipts: receipts})
	if err != nil {
		t.Fatalf("newShadowQueryStore() error = %v", err)
	}
	got, err := store.GetEntityNeighborhood(context.Background(), primary.Root.URN, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got != primary {
		t.Fatal("GetEntityNeighborhood() did not preserve the primary response")
	}
	select {
	case receipt := <-receipts:
		if receipt.Status != "match" || receipt.RootDigest == "" {
			t.Fatalf("receipt = %#v", receipt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shadow comparison was not recorded")
	}

	rows, err := store.ExecuteReadCypher(context.Background(), ports.CypherQueryRequest{Query: "RETURN 1"})
	if err != nil || len(rows) != 1 || rows[0].Values["authority"] != "go" {
		t.Fatalf("ExecuteReadCypher() = %#v, %v", rows, err)
	}
}

func TestShadowQueryStoreDoesNotChangePrimaryOnRustFailure(t *testing.T) {
	primary := &ports.EntityNeighborhood{
		Root:      &ports.NeighborhoodNode{URN: "urn:cerebro:tenant-a:runtime_file:asset-1"},
		Neighbors: []*ports.NeighborhoodNode{},
		Relations: []*ports.NeighborhoodRelation{},
	}
	receipts := make(chan ShadowReceipt, 1)
	store, err := newShadowQueryStore(queryStoreStub{neighborhood: primary}, "http://127.0.0.1:1", 10*time.Millisecond, receiptSink{receipts: receipts})
	if err != nil {
		t.Fatalf("newShadowQueryStore() error = %v", err)
	}
	got, err := store.GetEntityNeighborhood(context.Background(), primary.Root.URN, 10)
	if err != nil || got != primary {
		t.Fatalf("GetEntityNeighborhood() = %#v, %v", got, err)
	}
	select {
	case receipt := <-receipts:
		if receipt.Status != "unavailable" {
			t.Fatalf("receipt status = %q", receipt.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("unavailable receipt was not recorded")
	}
}
