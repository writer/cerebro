package graph

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type snapshotCountingSearchStore struct {
	GraphStore
	snapshotCount atomic.Int32
}

func (s *snapshotCountingSearchStore) Snapshot(ctx context.Context) (*Snapshot, error) {
	s.snapshotCount.Add(1)
	return s.GraphStore.Snapshot(ctx)
}

type noopOpenSearchSigner struct{}

func (noopOpenSearchSigner) SignHTTP(_ context.Context, _ aws.Credentials, _ *http.Request, _ string, _ string, _ string, _ time.Time, _ ...func(*v4.SignerOptions)) error {
	return nil
}

func TestParseEntitySearchBackend(t *testing.T) {
	t.Parallel()

	if got := ParseEntitySearchBackend(""); got != EntitySearchBackendGraph {
		t.Fatalf("ParseEntitySearchBackend(\"\") = %q, want %q", got, EntitySearchBackendGraph)
	}
	if got := ParseEntitySearchBackend("opensearch"); got != EntitySearchBackendOpenSearch {
		t.Fatalf("ParseEntitySearchBackend(opensearch) = %q, want %q", got, EntitySearchBackendOpenSearch)
	}
	if ParseEntitySearchBackend("legacy").Valid() {
		t.Fatal("expected unsupported graph search backend to be invalid")
	}
}

func TestOpenSearchEntitySearchBackendSearchHydratesCurrentStateWithoutSnapshots(t *testing.T) {
	t.Parallel()

	backing := New()
	backing.AddNode(&Node{
		ID:       "service:payments",
		Kind:     NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     RiskHigh,
	})
	backing.AddNode(&Node{
		ID:       "database:payments",
		Kind:     NodeKindDatabase,
		Name:     "Payments DB",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     RiskMedium,
	})
	backing.AddEdge(&Edge{
		ID:     "service:payments->database:payments:depends_on",
		Source: "service:payments",
		Target: "database:payments",
		Kind:   EdgeKindDependsOn,
		Effect: EdgeEffectAllow,
	})

	store := &snapshotCountingSearchStore{GraphStore: backing}
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[{"_score":8.5,"_source":{"graphId":"service:payments","kind":"service","name":"Payments","provider":"aws","account":"123456789012","region":"us-east-1"}}]}}`)
	}))
	defer server.Close()

	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:     server.URL,
		Region:       "us-east-1",
		Index:        "entity-search",
		HTTPClient:   server.Client(),
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:       noopOpenSearchSigner{},
		ResolveStore: func(context.Context, string) (GraphStore, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	results, err := backend.Search(context.Background(), "tenant-a", EntitySearchOptions{
		Query: "payments",
		Kinds: []NodeKind{NodeKindService},
		Limit: 5,
		Fuzzy: true,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if results.Count != 1 {
		t.Fatalf("Search().Count = %d, want 1", results.Count)
	}
	if got := results.Results[0].Entity.ID; got != "service:payments" {
		t.Fatalf("Search() entity id = %q, want service:payments", got)
	}
	if got := results.Results[0].Entity.Links.OutgoingCount; got != 1 {
		t.Fatalf("Search() outgoing count = %d, want 1", got)
	}
	if got := store.snapshotCount.Load(); got != 0 {
		t.Fatalf("expected search hydration to avoid snapshots, got %d snapshot calls", got)
	}
	for _, fragment := range []string{`"entityKind":"node"`, `"tenantId":"tenant-a"`, `"kind":["service"]`, `"fuzziness":"AUTO"`} {
		if !strings.Contains(requestBody, fragment) {
			t.Fatalf("expected OpenSearch request to contain %q, got %s", fragment, requestBody)
		}
	}
}

func TestOpenSearchEntitySearchBackendSuggestsEntityNamesAndIDs(t *testing.T) {
	t.Parallel()

	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[{"_score":4.2,"_source":{"graphId":"service:payments","kind":"service","name":"Payments"}}]}}`)
	}))
	defer server.Close()

	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:     server.URL,
		Region:       "us-east-1",
		Index:        "entity-search",
		HTTPClient:   server.Client(),
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:       noopOpenSearchSigner{},
		ResolveStore: func(context.Context, string) (GraphStore, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	results, err := backend.Suggest(context.Background(), "tenant-a", EntitySuggestOptions{
		Prefix: "service:",
		Kinds:  []NodeKind{NodeKindService},
		Limit:  5,
	})
	if err != nil {
		t.Fatalf("Suggest() error = %v", err)
	}
	if results.Count != 1 {
		t.Fatalf("Suggest().Count = %d, want 1", results.Count)
	}
	if got := results.Suggestions[0].Value; got != "service:payments" {
		t.Fatalf("Suggest() value = %q, want service:payments", got)
	}
	for _, fragment := range []string{`"name.keyword"`, `"graphId"`, `"entityKind":"node"`, `"tenantId":"tenant-a"`} {
		if !strings.Contains(requestBody, fragment) {
			t.Fatalf("expected OpenSearch suggest request to contain %q, got %s", fragment, requestBody)
		}
	}
}
