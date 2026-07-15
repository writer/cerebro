package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceremediation"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestComplianceRemediationCompositionRequiresAllDurableCapabilities(t *testing.T) {
	state := &bootstrapRemediationState{}
	log := &bootstrapRemediationLog{}
	app, err := NewWithError(config.Config{}, Dependencies{StateStore: state, AppendLog: log}, nil)
	if err != nil {
		t.Fatalf("NewWithError() error = %v", err)
	}
	if app.services.remediation == nil {
		t.Fatal("remediation service was not composed with store, projector, log, and replay capabilities")
	}
	app, err = NewWithError(config.Config{}, Dependencies{StateStore: state, AppendLog: bootstrapAppendOnlyLog{}}, nil)
	if err != nil {
		t.Fatalf("NewWithError(without replay) error = %v", err)
	}
	if app.services.remediation != nil {
		t.Fatal("remediation service composed without append-log replay capability")
	}
}

func TestComplianceWorkReadRejectsCrossTenantBeforeStoreLookup(t *testing.T) {
	state := &bootstrapRemediationState{}
	log := &bootstrapRemediationLog{}
	service := complianceremediation.New(state, state, log, log)
	app := &App{services: appServices{remediation: service}}
	request := httptest.NewRequest(http.MethodGet, "/grc/work-items/work-a?tenant_id=tenant-b", nil)
	request.SetPathValue("workItemID", "work-a")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "tenant-a"},
	}))
	recorder := httptest.NewRecorder()
	app.handleGetComplianceWorkItem(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if state.workReads != 0 {
		t.Fatalf("cross-tenant request reached state store %d times", state.workReads)
	}
}

func TestComplianceWorkListUsesCanonicalTenantAndBoundedFilters(t *testing.T) {
	state := &bootstrapRemediationState{}
	log := &bootstrapRemediationLog{}
	service := complianceremediation.New(state, state, log, log)
	app := &App{services: appServices{remediation: service}}
	request := httptest.NewRequest(http.MethodGet, "/grc/work-items?state=open&owner_id=owner-a&limit=25", nil)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "tenant-a"},
	}))
	recorder := httptest.NewRecorder()
	app.handleListComplianceWorkItems(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if state.workLists != 1 || state.lastTenant != "tenant-a" || state.lastFilter.State != complianceassessment.WorkOpen || state.lastFilter.OwnerID != "owner-a" || state.lastFilter.Limit != 25 {
		t.Fatalf("list call = count %d tenant %q filter %+v", state.workLists, state.lastTenant, state.lastFilter)
	}
}

func TestComplianceRemediationRoutesUseReadAndLifecycleWriteScopes(t *testing.T) {
	read, err := http.NewRequest(http.MethodGet, "/grc/work-items/work-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := httpRoutePolicyForRequest(read).Scope; got != scopeCosmoSecurityRead {
		t.Fatalf("work read scope = %q", got)
	}
	for _, path := range []string{
		"/grc/work-items", "/grc/work-items/work-a/commands",
		"/grc/remediation-plans", "/grc/remediation-plans/plan-a/commands",
	} {
		request, err := http.NewRequest(http.MethodPost, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := httpRoutePolicyForRequest(request).Scope; got != scopeFindingLifecycleWrite {
			t.Fatalf("%s scope = %q", path, got)
		}
	}
}

type bootstrapRemediationState struct {
	workReads  int
	workLists  int
	lastTenant string
	lastFilter complianceremediation.WorkItemListFilter
}

func (s *bootstrapRemediationState) ListWorkItems(_ context.Context, tenantID string, filter complianceremediation.WorkItemListFilter) (complianceremediation.WorkItemPage, error) {
	s.workLists++
	s.lastTenant = tenantID
	s.lastFilter = filter
	return complianceremediation.WorkItemPage{Items: []complianceassessment.WorkItem{}}, nil
}

func (s *bootstrapRemediationState) Ping(context.Context) error { return nil }

func (s *bootstrapRemediationState) GetWorkItem(context.Context, string, string) (complianceremediation.WorkItemRecord, error) {
	s.workReads++
	return complianceremediation.WorkItemRecord{}, complianceremediation.ErrNotFound
}

func (s *bootstrapRemediationState) GetRemediationPlan(context.Context, string, string) (complianceassessment.RemediationPlan, error) {
	return complianceassessment.RemediationPlan{}, complianceremediation.ErrNotFound
}

func (s *bootstrapRemediationState) ProjectWorkOccurrence(context.Context, complianceremediation.ProjectionMetadata, complianceassessment.WorkItem, complianceassessment.WorkOccurrence) error {
	return nil
}

func (s *bootstrapRemediationState) ProjectWorkAction(context.Context, complianceremediation.ProjectionMetadata, complianceassessment.WorkItem, complianceassessment.WorkActionRecord) error {
	return nil
}

func (s *bootstrapRemediationState) ProjectWorkReopen(context.Context, complianceremediation.ProjectionMetadata, complianceassessment.WorkItem, complianceassessment.WorkReopenRecord) error {
	return nil
}

func (s *bootstrapRemediationState) ProjectRemediationReopen(context.Context, complianceremediation.ProjectionMetadata, complianceassessment.RemediationPlan, complianceassessment.RemediationReopenRecord) error {
	return nil
}

func (s *bootstrapRemediationState) ProjectRemediationPlan(context.Context, complianceremediation.ProjectionMetadata, complianceassessment.RemediationPlan) error {
	return nil
}

type bootstrapRemediationLog struct{}

func (bootstrapRemediationLog) Ping(context.Context) error { return nil }
func (bootstrapRemediationLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}
func (bootstrapRemediationLog) ReplayPage(context.Context, ports.ReplayRequest) (ports.ReplayPage, error) {
	return ports.ReplayPage{Complete: true}, nil
}

type bootstrapAppendOnlyLog struct{}

func (bootstrapAppendOnlyLog) Ping(context.Context) error { return nil }
func (bootstrapAppendOnlyLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}
