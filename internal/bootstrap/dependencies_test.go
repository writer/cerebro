package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agentauthoring"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestOpenDependenciesAllowsUnconfiguredStores(t *testing.T) {
	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	if deps.AppendLog != nil {
		t.Fatal("AppendLog != nil, want nil")
	}
	if deps.StateStore != nil {
		t.Fatal("StateStore != nil, want nil")
	}
	if deps.GraphStore != nil {
		t.Fatal("GraphStore != nil, want nil")
	}
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll() error = %v", err)
	}
}

func TestOpenDependenciesRejectsGraphReadModeWithoutEndpoint(t *testing.T) {
	_, closeAll, err := OpenDependencies(context.Background(), config.Config{
		OrganizationalGraph: config.OrganizationalGraphConfig{ReadMode: "authority"},
	})
	if closeAll != nil {
		if closeErr := closeAll(); closeErr != nil {
			t.Fatalf("closeAll() error = %v", closeErr)
		}
	}
	if !errors.Is(err, errOrganizationalGraphReadEndpointRequired) {
		t.Fatalf("OpenDependencies() error = %v, want missing authority endpoint", err)
	}
}

func TestOpenDependenciesAllowsRustGraphWithoutGoGraphStore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" {
			http.NotFound(response, request)
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{
		OrganizationalGraph: config.OrganizationalGraphConfig{
			BaseURL:      server.URL,
			SharedSecret: "test-organizational-graph-secret-32-bytes",
			Timeout:      time.Second,
		},
	})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	defer func() {
		if err := closeAll(); err != nil {
			t.Fatalf("closeAll() error = %v", err)
		}
	}()
	if deps.GraphStore != nil {
		t.Fatal("GraphStore != nil, want no Go graph store")
	}
	if deps.GraphReads.RawCypher == nil {
		t.Fatal("GraphReads.RawCypher = nil, want Rust graph client")
	}
	if deps.GraphReads.CloudAttackPaths == nil {
		t.Fatal("GraphReads.CloudAttackPaths = nil, want typed Rust graph client")
	}
	if _, err := deps.GraphReads.RawCypher.ExecuteReadCypher(context.Background(), ports.CypherQueryRequest{Query: "RETURN 1"}); !errors.Is(err, ports.ErrGraphTypedOperationRequired) {
		t.Fatalf("ExecuteReadCypher() error = %v", err)
	}
}

func TestOpenDependenciesInitializesConfiguredGraphAgentLLM(t *testing.T) {
	deps, closeAll, err := OpenDependencies(context.Background(), config.Config{
		GraphAgentLLM: config.GraphAgentLLMConfig{Provider: "stub"},
	})
	if err != nil {
		t.Fatalf("OpenDependencies() error = %v", err)
	}
	defer func() {
		if err := closeAll(); err != nil {
			t.Fatalf("closeAll() error = %v", err)
		}
	}()
	if deps.GraphAgentLLM == nil {
		t.Fatal("GraphAgentLLM = nil, want configured startup client")
	}
	if deps.PolicyAuthoring == nil || deps.PolicyAuthoring.Model == nil {
		t.Fatal("PolicyAuthoring = nil, want configured structured authoring service")
	}
	payload, err := deps.PolicyAuthoring.Model.DraftJSON(context.Background(), agentauthoring.StructuredDraftRequest{
		TenantID: "tenant-a", Kind: "policy_finding_rule", Prompt: "draft", SchemaJSON: `{"type":"object"}`,
	})
	if err != nil {
		t.Fatalf("PolicyAuthoring.DraftJSON() error = %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("PolicyAuthoring payload = %q: %v", payload, err)
	}
}

func TestOpenDependenciesRejectsInvalidGraphAgentLLMAtStartup(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphAgentLLM: config.GraphAgentLLMConfig{Provider: "openrouter"},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want invalid LLM config error")
	}
}

func TestOpenDependenciesRejectsIncompleteJetStreamConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		AppendLog: config.AppendLogConfig{Driver: config.AppendLogDriverJetStream},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsIncompletePostgresConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		StateStore: config.StateStoreConfig{Driver: config.StateStoreDriverPostgres},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsIncompleteNeo4jConfig(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{Driver: config.GraphStoreDriverNeo4j},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenDependenciesRejectsUnsupportedGraphStoreDriver(t *testing.T) {
	_, _, err := OpenDependencies(context.Background(), config.Config{
		GraphStore: config.GraphStoreConfig{Driver: "alternate"},
	})
	if err == nil {
		t.Fatal("OpenDependencies() error = nil, want non-nil")
	}
}

func TestOpenSourceRuntimeBootstrapDependenciesIgnoresUnusedStores(t *testing.T) {
	deps, closeAll, err := OpenSourceRuntimeBootstrapDependencies(context.Background(), config.Config{
		AppendLog:  config.AppendLogConfig{Driver: config.AppendLogDriverJetStream},
		GraphStore: config.GraphStoreConfig{Driver: "alternate"},
	})
	if err != nil {
		t.Fatalf("OpenSourceRuntimeBootstrapDependencies() error = %v", err)
	}
	if deps.AppendLog != nil {
		t.Fatal("AppendLog != nil, want nil")
	}
	if deps.GraphStore != nil {
		t.Fatal("GraphStore != nil, want nil")
	}
	if err := closeAll(); err != nil {
		t.Fatalf("closeAll() error = %v", err)
	}
}
