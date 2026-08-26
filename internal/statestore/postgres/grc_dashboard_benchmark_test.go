package postgres

import (
	"fmt"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func BenchmarkGRCDashboardAggregateQueryRuntimeIDs(b *testing.B) {
	runtimeIDs := make([]string, 500)
	for index := range runtimeIDs {
		runtimeIDs[index] = fmt.Sprintf("runtime-%04d", index)
	}
	request := ports.GRCDashboardAggregateRequest{
		FindingRequest: ports.ListFindingsRequest{
			TenantID:   "tenant-a",
			RuntimeIDs: runtimeIDs,
			Status:     "open",
		},
		PreviewFindingIDs: []string{"finding-a", "finding-b"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := grcDashboardAggregateQuery(request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGRCDashboardAggregateQueryRuntimeScope(b *testing.B) {
	request := ports.GRCDashboardAggregateRequest{
		FindingRequest: ports.ListFindingsRequest{
			TenantID: "tenant-a",
			Status:   "open",
		},
		PreviewFindingIDs: []string{"finding-a", "finding-b"},
		RuntimeScope: &ports.SourceRuntimeFilter{
			TenantID:               "tenant-a",
			ApplicationWorkspaceID: "workspace-a",
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := grcDashboardAggregateQuery(request); err != nil {
			b.Fatal(err)
		}
	}
}
