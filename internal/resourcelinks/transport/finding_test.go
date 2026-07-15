package transport

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestFindingResponseMapsLinksAndOmitsInvalidStoredInputs(t *testing.T) {
	message := &cerebrov1.Finding{Id: "finding-1"}
	valid := FindingResponse(message, &ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		RuntimeID:    "runtime-1",
		ResourceURNs: []string{"urn:cerebro:tenant-a:asset:one"},
	})
	if valid.GetFinding() != message || len(valid.GetLinks()) != 5 {
		t.Fatalf("FindingResponse(valid) = %#v, want finding and five links", valid)
	}

	invalid := FindingResponse(message, &ports.FindingRecord{ID: "finding-1"})
	if invalid.GetFinding() != message || len(invalid.GetLinks()) != 0 {
		t.Fatalf("FindingResponse(invalid) = %#v, want existing finding without links", invalid)
	}

	crossTenant := FindingResponse(message, &ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		RuntimeID:    "runtime-1",
		ResourceURNs: []string{"urn:cerebro:tenant-b:asset:one"},
	})
	if crossTenant.GetFinding() != message || len(crossTenant.GetLinks()) != 0 {
		t.Fatalf("FindingResponse(cross tenant) = %#v, want existing finding without links", crossTenant)
	}
}
