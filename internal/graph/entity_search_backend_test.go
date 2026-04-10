package graph

import (
	"context"
	"fmt"
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

func TestOpenSearchEntitySearchBackendSearchResolvesGraphOncePerRequest(t *testing.T) {
	t.Parallel()

	tenantGraph := New()
	tenantGraph.AddNode(&Node{
		ID:       "service:payments",
		Kind:     NodeKindService,
		Name:     "Payments",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     RiskHigh,
		TenantID: "tenant-a",
	})
	tenantGraph.AddNode(&Node{
		ID:       "database:payments",
		Kind:     NodeKindDatabase,
		Name:     "Payments DB",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     RiskMedium,
		TenantID: "tenant-a",
	})
	tenantGraph.AddEdge(&Edge{
		ID:     "service:payments->database:payments:depends_on",
		Source: "service:payments",
		Target: "database:payments",
		Kind:   EdgeKindDependsOn,
		Effect: EdgeEffectAllow,
	})
	tenantGraph.AddNode(&Node{
		ID:       "service:billing",
		Kind:     NodeKindService,
		Name:     "Billing",
		Provider: "aws",
		TenantID: "tenant-a",
	})
	for i := 0; i < 600; i++ {
		nodeID := fmt.Sprintf("database:payments:%03d", i)
		tenantGraph.AddNode(&Node{
			ID:       nodeID,
			Kind:     NodeKindDatabase,
			Name:     fmt.Sprintf("Payments Replica %03d", i),
			Provider: "aws",
			TenantID: "tenant-a",
		})
		tenantGraph.AddEdge(&Edge{
			ID:     fmt.Sprintf("service:payments->%s:depends_on", nodeID),
			Source: "service:payments",
			Target: nodeID,
			Kind:   EdgeKindDependsOn,
			Effect: EdgeEffectAllow,
		})
	}

	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[{"_score":9.5,"_source":{"graphId":"claim:payments:owner","kind":"claim","name":"owner"}},{"_score":8.5,"_source":{"graphId":"service:payments","kind":"service","name":"Payments","provider":"aws","account":"123456789012","region":"us-east-1"}},{"_score":7.5,"_source":{"graphId":"service:billing","kind":"service","name":"Billing","provider":"aws","account":"123456789012","region":"us-east-1"}}]}}`)
	}))
	defer server.Close()

	var resolveCalls atomic.Int32
	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:    server.URL,
		Region:      "us-east-1",
		Index:       "entity-search",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:      noopOpenSearchSigner{},
		ResolveGraph: func(context.Context, string) (*Graph, error) {
			resolveCalls.Add(1)
			return tenantGraph.SubgraphForTenant("tenant-a"), nil
		},
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	results, err := backend.Search(context.Background(), "tenant-a", EntitySearchOptions{
		Query: "payments",
		Limit: 5,
		Fuzzy: true,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if results.Count != 2 {
		t.Fatalf("Search().Count = %d, want 2", results.Count)
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Fatalf("ResolveGraph() call count = %d, want 1", got)
	}
	if got := results.Results[0].Entity.ID; got != "service:payments" {
		t.Fatalf("Search() entity id = %q, want service:payments", got)
	}
	if got := results.Results[0].Entity.Links.OutgoingCount; got != 601 {
		t.Fatalf("Search() outgoing count = %d, want 601", got)
	}
	for _, fragment := range []string{`"entityKind":"node"`, `"tenantId":"tenant-a"`, `"must_not"`, `"claim"`, `"fuzziness":"AUTO"`} {
		if !strings.Contains(requestBody, fragment) {
			t.Fatalf("expected OpenSearch request to contain %q, got %s", fragment, requestBody)
		}
	}
}

func TestOpenSearchEntitySearchBackendUsesDeniedKindsFilterWhenKindsOmitted(t *testing.T) {
	t.Parallel()

	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[]}}`)
	}))
	defer server.Close()

	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:    server.URL,
		Region:      "us-east-1",
		Index:       "entity-search",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:      noopOpenSearchSigner{},
		ResolveGraph: func(context.Context, string) (*Graph, error) {
			return New(), nil
		},
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	if _, err := backend.Search(context.Background(), "tenant-a", EntitySearchOptions{Query: "payments", Limit: 5}); err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	for _, fragment := range []string{`"must_not"`, `"claim"`, `"evidence"`, `"observation"`} {
		if !strings.Contains(requestBody, fragment) {
			t.Fatalf("expected OpenSearch request to contain %q, got %s", fragment, requestBody)
		}
	}
	if strings.Contains(requestBody, `"service"`) {
		t.Fatalf("expected omitted-kind search to avoid registry-derived allowlists, got %s", requestBody)
	}
}

func TestOpenSearchEntitySearchBackendReturnsEmptyForDisallowedRequestedKinds(t *testing.T) {
	t.Parallel()

	requests := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[]}}`)
	}))
	defer server.Close()

	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:    server.URL,
		Region:      "us-east-1",
		Index:       "entity-search",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:      noopOpenSearchSigner{},
		ResolveGraph: func(context.Context, string) (*Graph, error) {
			t.Fatal("ResolveGraph() should not be called when all requested kinds are disallowed")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	results, err := backend.Search(context.Background(), "tenant-a", EntitySearchOptions{
		Query: "owner",
		Kinds: []NodeKind{NodeKindClaim},
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if results.Count != 0 {
		t.Fatalf("Search().Count = %d, want 0", results.Count)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("OpenSearch request count = %d, want 0", got)
	}
}

func TestOpenSearchEntitySearchBackendSuggestRevalidatesCurrentState(t *testing.T) {
	t.Parallel()

	current := New()
	current.AddNode(&Node{
		ID:   "service:payments",
		Kind: NodeKindService,
		Name: "Payments API",
	})

	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[{"_score":5.2,"_source":{"graphId":"service:deleted","kind":"service","name":"Deleted Service"}},{"_score":4.2,"_source":{"graphId":"service:payments","kind":"service","name":"Payments"}}]}}`)
	}))
	defer server.Close()

	var resolveCalls atomic.Int32
	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:    server.URL,
		Region:      "us-east-1",
		Index:       "entity-search",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:      noopOpenSearchSigner{},
		ResolveGraph: func(context.Context, string) (*Graph, error) {
			resolveCalls.Add(1)
			return current, nil
		},
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	results, err := backend.Suggest(context.Background(), "tenant-a", EntitySuggestOptions{
		Prefix: "pay",
		Limit:  5,
	})
	if err != nil {
		t.Fatalf("Suggest() error = %v", err)
	}
	if results.Count != 1 {
		t.Fatalf("Suggest().Count = %d, want 1", results.Count)
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Fatalf("ResolveGraph() call count = %d, want 1", got)
	}
	if got := results.Suggestions[0].Value; got != "Payments API" {
		t.Fatalf("Suggest() value = %q, want Payments API", got)
	}
	for _, fragment := range []string{`"name.keyword"`, `"graphId"`, `"entityKind":"node"`, `"tenantId":"tenant-a"`} {
		if !strings.Contains(requestBody, fragment) {
			t.Fatalf("expected OpenSearch suggest request to contain %q, got %s", fragment, requestBody)
		}
	}
}

func TestOpenSearchEntitySearchBackendCheckReturnsBootstrapPendingWhenIndexMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"type":"index_not_found_exception","reason":"no such index [entity-search]"},"status":404}`)
	}))
	defer server.Close()

	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:    server.URL,
		Region:      "us-east-1",
		Index:       "entity-search",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:      noopOpenSearchSigner{},
		ResolveGraph: func(context.Context, string) (*Graph, error) {
			return New(), nil
		},
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	err = backend.Check(context.Background())
	if !IsEntitySearchBootstrapPending(err) {
		t.Fatalf("Check() error = %v, want bootstrap-pending error", err)
	}
}

func TestOpenSearchEntitySearchBackendCheckProbesIndex(t *testing.T) {
	t.Parallel()

	requests := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"hits":[]}}`)
	}))
	defer server.Close()

	backend, err := NewOpenSearchEntitySearchBackend(OpenSearchEntitySearchBackendOptions{
		Endpoint:    server.URL,
		Region:      "us-east-1",
		Index:       "entity-search",
		HTTPClient:  server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Signer:      noopOpenSearchSigner{},
		ResolveGraph: func(context.Context, string) (*Graph, error) {
			return New(), nil
		},
	})
	if err != nil {
		t.Fatalf("NewOpenSearchEntitySearchBackend() error = %v", err)
	}

	if err := backend.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("Check() request count = %d, want 1", got)
	}
}
