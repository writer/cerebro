package bootstrap

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestComplianceImpactServiceComposition(t *testing.T) {
	t.Parallel()
	app := &App{deps: Dependencies{
		StateStore: &monitorStateStub{}, GraphStore: &impactGraphStub{}, AppendLog: bootstrapAppendOnlyLog{},
	}}
	monitors, projector, scheduler := app.newComplianceImpactServices(nil)
	if monitors == nil || projector == nil || scheduler == nil {
		t.Fatalf("composed monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}

	app.deps.GraphStore = nil
	monitors, projector, scheduler = app.newComplianceImpactServices(nil)
	if monitors == nil || projector != nil || scheduler != nil {
		t.Fatalf("without graph monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}

	app.deps.StateStore = nonEvidenceStateStub{}
	app.deps.GraphStore = &impactGraphStub{}
	monitors, projector, scheduler = app.newComplianceImpactServices(nil)
	if monitors != nil || projector == nil || scheduler != nil {
		t.Fatalf("without monitor store monitors=%v projector=%v scheduler=%v", monitors != nil, projector != nil, scheduler != nil)
	}
}

type monitorStateStub struct {
	ports.ComplianceMonitorStore
}

func (*monitorStateStub) Ping(context.Context) error { return nil }

type impactGraphStub struct {
	ports.ProjectionGraphStore
	ports.GraphQueryStore
}

func (*impactGraphStub) Ping(context.Context) error { return nil }
