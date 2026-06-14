package bootstrap

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
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

func TestNewCachesJobServiceForAsyncLifecycle(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: &stubRuntimeStore{}}, nil)
	if app.services.jobs == nil {
		t.Fatal("jobsService = nil, want cached service")
	}
	first := app.jobService()
	second := app.jobService()
	if first != second {
		t.Fatal("jobService() returned different instances")
	}
}
