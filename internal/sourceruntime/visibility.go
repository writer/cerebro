package sourceruntime

import (
	"context"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type runtimeLister interface {
	ListSourceRuntimes(context.Context, ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error)
}

// ListVisibleRuntimes applies tenant and workspace boundaries even when a
// runtime store returns rows outside the requested filter.
func ListVisibleRuntimes(ctx context.Context, lister runtimeLister, filter ports.SourceRuntimeFilter, tenantAllowed func(context.Context, string) bool) ([]*cerebrov1.SourceRuntime, error) {
	runtimes, err := lister.ListSourceRuntimes(ctx, filter)
	if err != nil {
		return nil, err
	}
	visible := make([]*cerebrov1.SourceRuntime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil || (filter.TenantID != "" && strings.TrimSpace(runtime.GetTenantId()) != filter.TenantID) ||
			(filter.ApplicationWorkspaceID != "" && strings.TrimSpace(runtime.GetConfig()[ports.SourceRuntimeApplicationWorkspaceIDConfigKey]) != filter.ApplicationWorkspaceID) ||
			(tenantAllowed != nil && !tenantAllowed(ctx, runtime.GetTenantId())) {
			continue
		}
		visible = append(visible, runtime)
	}
	return visible, nil
}
