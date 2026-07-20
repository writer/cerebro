package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubHandler struct {
	prefixes []string
}

func (s *stubHandler) Handles() []string { return s.prefixes }

func TestRegistry_RegisterAndLookupExact(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := &stubHandler{prefixes: []string{"aws.s3_bucket"}}
	r.Register(h)

	got, ok := r.Lookup("aws.s3_bucket")
	if !ok {
		t.Fatal("expected handler for exact kind")
	}
	if got != h {
		t.Fatal("returned handler does not match registered handler")
	}
}

func TestRegistry_LookupPrefixMatch(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := &stubHandler{prefixes: []string{"aws."}}
	r.Register(h)

	got, ok := r.Lookup("aws.ec2_instance")
	if !ok {
		t.Fatal("expected handler via prefix match")
	}
	if got != h {
		t.Fatal("returned handler does not match registered handler")
	}
}

func TestRegistry_LookupMissing(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := &stubHandler{prefixes: []string{"gcp.compute"}}
	r.Register(h)

	_, ok := r.Lookup("azure.vm")
	if ok {
		t.Fatal("expected no handler for unregistered kind")
	}
}

func TestRegistry_MultiplePrefixes(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	awsHandler := &stubHandler{prefixes: []string{"aws."}}
	gcpHandler := &stubHandler{prefixes: []string{"gcp."}}
	r.Register(awsHandler)
	r.Register(gcpHandler)

	got, ok := r.Lookup("aws.lambda_function")
	if !ok {
		t.Fatal("expected handler for aws kind")
	}
	if got != awsHandler {
		t.Fatal("expected aws handler")
	}

	got, ok = r.Lookup("gcp.cloud_run_service")
	if !ok {
		t.Fatal("expected handler for gcp kind")
	}
	if got != gcpHandler {
		t.Fatal("expected gcp handler")
	}
}

func TestRegistry_LongestPrefixWins(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	broad := &stubHandler{prefixes: []string{"aws."}}
	specific := &stubHandler{prefixes: []string{"aws.s3"}}
	r.Register(broad)
	r.Register(specific)

	got, ok := r.Lookup("aws.s3_bucket")
	if !ok {
		t.Fatal("expected handler for aws.s3_bucket")
	}
	if got != specific {
		t.Fatal("expected more specific handler to win")
	}

	got, ok = r.Lookup("aws.ec2_instance")
	if !ok {
		t.Fatal("expected handler for aws.ec2_instance")
	}
	if got != broad {
		t.Fatal("expected broad handler for non-s3 kind")
	}
}

func TestRegistry_RegisterNilHandler(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	r.Register(nil)

	_, ok := r.Lookup("anything")
	if ok {
		t.Fatal("expected no handler after registering nil")
	}
}

func TestRegistry_LookupOnNilRegistry(t *testing.T) {
	var r *Registry
	_, ok := r.Lookup("aws.s3_bucket")
	if ok {
		t.Fatal("expected no handler on nil registry")
	}
}

func TestRegistryProjectContextPreservesConnectorDefinitionPrecedence(t *testing.T) {
	contextProjectorCalled := false
	connectorProjectorCalled := false
	r := &Registry{
		projectors: map[string]ProjectFunc{},
		contextProjectors: map[string]ContextProjectFunc{
			"shared.kind": func(context.Context, *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
				contextProjectorCalled = true
				return nil, nil, nil
			},
		},
		connectorDefinitionProjectors: map[string]map[string]ProjectFunc{
			"shared.kind": {
				"connector-source": func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
					connectorProjectorCalled = true
					return nil, nil, nil
				},
			},
		},
	}

	_, _, err := r.ProjectContext(context.Background(), &cerebrov1.EventEnvelope{
		SourceId: "connector-source",
		Kind:     "shared.kind",
	})
	if err != nil {
		t.Fatalf("ProjectContext() error = %v", err)
	}
	if !connectorProjectorCalled {
		t.Fatal("ProjectContext() did not use connector definition projector")
	}
	if contextProjectorCalled {
		t.Fatal("ProjectContext() used context projector instead of connector definition projector")
	}
}

func TestRegistryProjectPreservesConnectorDefinitionPrecedenceForContextKind(t *testing.T) {
	contextProjectorCalled := false
	connectorProjectorCalled := false
	r := &Registry{
		contextProjectors: map[string]ContextProjectFunc{
			"shared.kind": func(context.Context, *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
				contextProjectorCalled = true
				return nil, nil, nil
			},
		},
		connectorDefinitionProjectors: map[string]map[string]ProjectFunc{
			"shared.kind": {
				"connector-source": func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
					connectorProjectorCalled = true
					return nil, nil, nil
				},
			},
		},
	}

	_, _, err := r.Project(&cerebrov1.EventEnvelope{
		SourceId: "connector-source",
		Kind:     "shared.kind",
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if !connectorProjectorCalled {
		t.Fatal("Project() did not use connector definition projector")
	}
	if contextProjectorCalled {
		t.Fatal("Project() used context projector instead of connector definition projector")
	}
}

func TestRegistryKindsDeduplicatesBaseAndContextProjectors(t *testing.T) {
	r := &Registry{
		projectors: map[string]ProjectFunc{
			"shared.kind": func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
				return nil, nil, nil
			},
		},
		contextProjectors: map[string]ContextProjectFunc{
			"shared.kind": func(context.Context, *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
				return nil, nil, nil
			},
		},
	}

	kinds := r.Kinds()
	if len(kinds) != 1 || kinds[0] != "shared.kind" {
		t.Fatalf("Kinds() = %v, want [shared.kind]", kinds)
	}
}
