package decisionpacket

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type findingReaderStub struct {
	finding *ports.FindingRecord
	err     error
}

func (s findingReaderStub) GetFinding(context.Context, string) (*ports.FindingRecord, error) {
	return s.finding, s.err
}

type graphReaderStub struct{ err error }

func (s graphReaderStub) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, s.err
}

type evidenceReaderStub struct{}

func (evidenceReaderStub) ListFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	return nil, nil
}

func TestPortsResolverHidesForeignFindingExistence(t *testing.T) {
	resolver := PortsResolver{Findings: findingReaderStub{finding: &ports.FindingRecord{ID: "finding-1", TenantID: "other"}}, FindingEvidence: evidenceReaderStub{}}
	_, err := resolver.Resolve(context.Background(), AuthorizedTenant{ID: "tenant-1"}, Request{FindingIDs: []string{"finding-1"}, Budgets: budgetDefaults})
	if !errors.Is(err, ErrProtectedReference) {
		t.Fatalf("Resolve() error = %v, want ErrProtectedReference", err)
	}
}

func TestPortsResolverRepresentsOptionalGraphFailureAsGap(t *testing.T) {
	resolver := PortsResolver{Graph: graphReaderStub{err: errors.New("graph unavailable")}}
	facts, err := resolver.Resolve(context.Background(), AuthorizedTenant{ID: "tenant-1"}, Request{ScopeURN: "urn:cerebro:tenant-1:asset:1", Budgets: budgetDefaults})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(facts.CoverageGaps) != 1 || facts.CoverageGaps[0].State != CoverageFailed || facts.CoverageGaps[0].Required {
		t.Fatalf("coverage gaps = %+v", facts.CoverageGaps)
	}
}

func TestPortsResolverReturnsBoundedFindingFacts(t *testing.T) {
	now := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	resolver := PortsResolver{
		Findings: findingReaderStub{finding: &ports.FindingRecord{
			ID: "finding-1", TenantID: "tenant-1", RuntimeID: "runtime-1", LastObservedAt: now,
			ResourceURNs: []string{"urn:cerebro:tenant-1:asset:1"},
			ControlRefs:  []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		}},
		FindingEvidence: evidenceReaderStub{},
	}
	facts, err := resolver.Resolve(context.Background(), AuthorizedTenant{ID: "tenant-1"}, Request{FindingIDs: []string{"finding-1"}, Budgets: budgetDefaults})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(facts.Evidence) != 1 || len(facts.Affected) != 1 || len(facts.Controls) != 1 || facts.Controls[0].ID != "CC6.1" {
		t.Fatalf("resolved facts = %+v", facts)
	}
}
