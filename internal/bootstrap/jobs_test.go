package bootstrap

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	platformjobs "github.com/writer/cerebro/internal/jobs"
)

func TestAuthorizeJobCreateAllowsSourceRuntimeOrchestrate(t *testing.T) {
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-1": {Id: "runtime-1", SourceId: "github", TenantId: "writer"},
	}}
	tenantID, err := authorizeJobCreate(context.Background(), store, createJobHTTPRequest{
		Kind:     platformjobs.KindSourceRuntimeOrchestrate,
		TenantID: "writer",
		Payload:  map[string]any{"runtime_id": "runtime-1"},
	})
	if err != nil {
		t.Fatalf("authorizeJobCreate() error = %v", err)
	}
	if tenantID != "writer" {
		t.Fatalf("authorizeJobCreate() tenantID = %q, want writer", tenantID)
	}
}
