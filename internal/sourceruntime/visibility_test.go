package sourceruntime

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type unfilteredRuntimeLister struct {
	runtimes []*cerebrov1.SourceRuntime
}

func (s unfilteredRuntimeLister) ListSourceRuntimes(context.Context, ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	return s.runtimes, nil
}

func TestListVisibleRuntimesEnforcesTenantAndWorkspaceBoundaries(t *testing.T) {
	lister := unfilteredRuntimeLister{runtimes: []*cerebrov1.SourceRuntime{
		{Id: "visible", TenantId: "writer", Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: "workspace-a"}},
		{Id: "other-workspace", TenantId: "writer", Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: "workspace-b"}},
		{Id: "other-tenant", TenantId: "other", Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: "workspace-a"}},
		nil,
	}}

	runtimes, err := ListVisibleRuntimes(t.Context(), lister, ports.SourceRuntimeFilter{
		TenantID: "writer", ApplicationWorkspaceID: "workspace-a",
	}, func(_ context.Context, tenantID string) bool { return tenantID == "writer" })
	if err != nil {
		t.Fatalf("ListVisibleRuntimes() error = %v", err)
	}
	if len(runtimes) != 1 || runtimes[0].GetId() != "visible" {
		t.Fatalf("ListVisibleRuntimes() = %#v, want only visible runtime", runtimes)
	}
}
