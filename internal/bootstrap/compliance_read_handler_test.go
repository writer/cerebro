package bootstrap

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/complianceread"
	"github.com/writer/cerebro/internal/config"
)

func TestComplianceReadHandlerServesEveryResourceFamily(t *testing.T) {
	store := newComplianceReadStubStore()
	server := newComplianceReadTestServer(t, store, []string{
		scopeCosmoSecurityRead,
		scopeComplianceProgramsRead, scopeComplianceEvidenceRead,
		scopeComplianceAssessmentsRead, scopeComplianceWorkRead,
	})
	client := cerebrov1connect.NewComplianceReadServiceClient(server.Client(), server.URL)
	ctx := context.Background()
	bootstrapClient := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	version, err := bootstrapClient.GetVersion(ctx, complianceReadRequest(&cerebrov1.GetVersionRequest{}))
	if err != nil || version.Msg.GetComplianceReads().GetRouteState() != cerebrov1.ComplianceReadRouteState_COMPLIANCE_READ_ROUTE_STATE_REGISTERED {
		t.Fatalf("configured version = %+v error=%v", version, err)
	}

	programs, err := client.ListCompliancePrograms(ctx, complianceReadRequest(&cerebrov1.ListComplianceProgramsRequest{
		Page: &cerebrov1.CompliancePageRequest{PageSize: 25},
	}))
	if err != nil || len(programs.Msg.GetPrograms()) != 1 || programs.Msg.GetPrograms()[0].GetRevision().GetId() != "program-1" {
		t.Fatalf("ListCompliancePrograms() = %+v, error %v", programs, err)
	}
	if programs.Msg.GetPage().GetNextCursor() == "" {
		t.Fatal("ListCompliancePrograms() omitted next cursor")
	}
	if _, err := client.ListCompliancePrograms(ctx, complianceReadRequest(&cerebrov1.ListComplianceProgramsRequest{
		Page: &cerebrov1.CompliancePageRequest{Cursor: programs.Msg.GetPage().GetNextCursor(), PageSize: 10},
	})); err != nil {
		t.Fatalf("ListCompliancePrograms(cursor) error = %v", err)
	}

	program, err := client.GetComplianceProgram(ctx, complianceReadRequest(&cerebrov1.GetComplianceProgramRequest{Id: "program-1", RevisionId: "program-rev-1"}))
	if err != nil || program.Msg.GetProgram().GetRevision().GetId() != "program-1" || program.Header().Get("ETag") != `"program-etag"` {
		t.Fatalf("GetComplianceProgram() = %+v header=%q error=%v", program, program.Header().Get("ETag"), err)
	}
	implementations, err := client.ListControlImplementations(ctx, complianceReadRequest(&cerebrov1.ListControlImplementationsRequest{}))
	if err != nil || len(implementations.Msg.GetImplementations()) != 1 {
		t.Fatalf("ListControlImplementations() = %+v, error %v", implementations, err)
	}
	if _, err := client.GetControlImplementation(ctx, complianceReadRequest(&cerebrov1.GetControlImplementationRequest{Id: "implementation-1", RevisionId: "implementation-rev-1"})); err != nil {
		t.Fatalf("GetControlImplementation() error = %v", err)
	}
	artifacts, err := client.ListEvidenceArtifactMetadata(ctx, complianceReadRequest(&cerebrov1.ListEvidenceArtifactMetadataRequest{}))
	if err != nil || len(artifacts.Msg.GetArtifacts()) != 1 {
		t.Fatalf("ListEvidenceArtifactMetadata() = %+v, error %v", artifacts, err)
	}
	if _, err := client.GetEvidenceArtifactMetadata(ctx, complianceReadRequest(&cerebrov1.GetEvidenceArtifactMetadataRequest{Id: "artifact-1", RevisionId: "artifact-rev-1"})); err != nil {
		t.Fatalf("GetEvidenceArtifactMetadata() error = %v", err)
	}
	plans, err := client.ListAssessmentPlans(ctx, complianceReadRequest(&cerebrov1.ListAssessmentPlansRequest{}))
	if err != nil || len(plans.Msg.GetPlans()) != 1 {
		t.Fatalf("ListAssessmentPlans() = %+v, error %v", plans, err)
	}
	if _, err := client.GetAssessmentPlan(ctx, complianceReadRequest(&cerebrov1.GetAssessmentPlanRequest{Id: "plan-1", RevisionId: "plan-rev-1"})); err != nil {
		t.Fatalf("GetAssessmentPlan() error = %v", err)
	}
	runs, err := client.ListAssessmentRuns(ctx, complianceReadRequest(&cerebrov1.ListAssessmentRunsRequest{}))
	if err != nil || len(runs.Msg.GetRuns()) != 1 {
		t.Fatalf("ListAssessmentRuns() = %+v, error %v", runs, err)
	}
	if _, err := client.GetAssessmentRun(ctx, complianceReadRequest(&cerebrov1.GetAssessmentRunRequest{Id: "run-1", RevisionId: "run-rev-1"})); err != nil {
		t.Fatalf("GetAssessmentRun() error = %v", err)
	}
	results, err := client.ListAssessmentResults(ctx, complianceReadRequest(&cerebrov1.ListAssessmentResultsRequest{}))
	if err != nil || len(results.Msg.GetResults()) != 1 {
		t.Fatalf("ListAssessmentResults() = %+v, error %v", results, err)
	}
	if _, err := client.GetAssessmentResult(ctx, complianceReadRequest(&cerebrov1.GetAssessmentResultRequest{Id: "result-1", RevisionId: "result-rev-1"})); err != nil {
		t.Fatalf("GetAssessmentResult() error = %v", err)
	}
	reviews, err := client.ListAssessmentReviews(ctx, complianceReadRequest(&cerebrov1.ListAssessmentReviewsRequest{}))
	if err != nil || len(reviews.Msg.GetReviews()) != 1 {
		t.Fatalf("ListAssessmentReviews() = %+v, error %v", reviews, err)
	}
	if _, err := client.GetAssessmentReview(ctx, complianceReadRequest(&cerebrov1.GetAssessmentReviewRequest{Id: "review-1", RevisionId: "review-rev-1"})); err != nil {
		t.Fatalf("GetAssessmentReview() error = %v", err)
	}
	workItems, err := client.ListComplianceWorkItems(ctx, complianceReadRequest(&cerebrov1.ListComplianceWorkItemsRequest{}))
	if err != nil || len(workItems.Msg.GetWorkItems()) != 1 {
		t.Fatalf("ListComplianceWorkItems() = %+v, error %v", workItems, err)
	}
	if _, err := client.GetComplianceWorkItem(ctx, complianceReadRequest(&cerebrov1.GetComplianceWorkItemRequest{Id: "work-1", RevisionId: "work-rev-1"})); err != nil {
		t.Fatalf("GetComplianceWorkItem() error = %v", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lastTenant != "tenant-a" || store.programPage.Limit != 10 || store.programPage.After == nil || store.programPage.After.ID != "program-1" {
		t.Fatalf("repository scope/page = tenant %q page %+v", store.lastTenant, store.programPage)
	}
}

func TestComplianceReadHandlerRejectsCursorAndLimitBeforeRepository(t *testing.T) {
	store := newComplianceReadStubStore()
	server := newComplianceReadTestServer(t, store, []string{scopeComplianceProgramsRead})
	client := cerebrov1connect.NewComplianceReadServiceClient(server.Client(), server.URL)
	for _, page := range []*cerebrov1.CompliancePageRequest{
		{PageSize: complianceread.MaxPageSize + 1},
		{Cursor: "not-an-opaque-cursor"},
		{Cursor: strings.Repeat("x", 2049)},
	} {
		_, err := client.ListCompliancePrograms(context.Background(), complianceReadRequest(&cerebrov1.ListComplianceProgramsRequest{Page: page}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("ListCompliancePrograms(%+v) error = %v", page, err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.listCalls != 0 {
		t.Fatalf("invalid pages reached repository %d times", store.listCalls)
	}
}

func TestComplianceReadHandlerHidesForeignTenantRecords(t *testing.T) {
	store := newComplianceReadStubStore()
	store.returnTenant = "tenant-b"
	server := newComplianceReadTestServer(t, store, []string{scopeComplianceProgramsRead})
	client := cerebrov1connect.NewComplianceReadServiceClient(server.Client(), server.URL)
	list, err := client.ListCompliancePrograms(context.Background(), complianceReadRequest(&cerebrov1.ListComplianceProgramsRequest{}))
	if err != nil || len(list.Msg.GetPrograms()) != 0 {
		t.Fatalf("foreign list = %+v error=%v", list, err)
	}

	_, foreignErr := client.GetComplianceProgram(context.Background(), complianceReadRequest(&cerebrov1.GetComplianceProgramRequest{Id: "program-1", RevisionId: "program-rev-1"}))
	store.getErr = complianceread.ErrNotFound
	_, missingErr := client.GetComplianceProgram(context.Background(), complianceReadRequest(&cerebrov1.GetComplianceProgramRequest{Id: "missing", RevisionId: "missing-rev"}))
	var foreignConnectErr, missingConnectErr *connect.Error
	if connect.CodeOf(foreignErr) != connect.CodeNotFound || connect.CodeOf(missingErr) != connect.CodeNotFound ||
		!errors.As(foreignErr, &foreignConnectErr) || !errors.As(missingErr, &missingConnectErr) || foreignConnectErr.Message() != missingConnectErr.Message() {
		t.Fatalf("foreign error=%v missing error=%v", foreignErr, missingErr)
	}
}

func TestComplianceReadHandlerEnforcesProcedureScopes(t *testing.T) {
	store := newComplianceReadStubStore()
	server := newComplianceReadTestServer(t, store, []string{scopeComplianceEvidenceRead})
	client := cerebrov1connect.NewComplianceReadServiceClient(server.Client(), server.URL)
	if _, err := client.ListCompliancePrograms(context.Background(), complianceReadRequest(&cerebrov1.ListComplianceProgramsRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("program list error = %v, want permission denied", err)
	}
	if _, err := client.ListEvidenceArtifactMetadata(context.Background(), complianceReadRequest(&cerebrov1.ListEvidenceArtifactMetadataRequest{})); err != nil {
		t.Fatalf("evidence list error = %v", err)
	}
}

func TestComplianceReadHandlerIsAbsentWithoutRepository(t *testing.T) {
	app := New(config.Config{}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := cerebrov1connect.NewComplianceReadServiceClient(server.Client(), server.URL)
	if _, err := client.ListCompliancePrograms(context.Background(), connect.NewRequest(&cerebrov1.ListComplianceProgramsRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("unconfigured handler error = %v, want unimplemented", err)
	}
	bootstrapClient := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	version, err := bootstrapClient.GetVersion(context.Background(), connect.NewRequest(&cerebrov1.GetVersionRequest{}))
	if err != nil || version.Msg.GetComplianceReads().GetRouteState() != cerebrov1.ComplianceReadRouteState_COMPLIANCE_READ_ROUTE_STATE_CONTRACT_ONLY {
		t.Fatalf("unconfigured version = %+v error=%v", version, err)
	}
}

func newComplianceReadTestServer(t *testing.T, store *complianceReadStubStore, scopes []string) *httptest.Server {
	t.Helper()
	app := New(config.Config{Auth: config.AuthConfig{Enabled: true, APICredentials: []config.APICredential{{
		ID: "read-credential", Key: "read-token", Principal: "reader", TenantID: "tenant-a", Scopes: scopes,
	}}}}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	t.Cleanup(server.Close)
	return server
}

func complianceReadRequest[T any](message *T) *connect.Request[T] {
	request := connect.NewRequest(message)
	request.Header().Set("Authorization", "Bearer read-token")
	return request
}

type complianceReadStubStore struct {
	mu             sync.Mutex
	lastTenant     string
	programPage    complianceread.Page
	listCalls      int
	returnTenant   string
	getErr         error
	program        *cerebrov1.ComplianceProgram
	implementation *cerebrov1.ControlImplementation
	artifact       *cerebrov1.EvidenceArtifactMetadata
	plan           *cerebrov1.AssessmentPlan
	run            *cerebrov1.AssessmentRun
	result         *cerebrov1.AssessmentResult
	review         *cerebrov1.AssessmentReview
	workItem       *cerebrov1.ComplianceWorkItem
}

func newComplianceReadStubStore() *complianceReadStubStore {
	return &complianceReadStubStore{
		returnTenant:   "tenant-a",
		program:        &cerebrov1.ComplianceProgram{Revision: complianceReadRevision("program-1", "program-rev-1", "program-etag")},
		implementation: &cerebrov1.ControlImplementation{Revision: complianceReadRevision("implementation-1", "implementation-rev-1", "implementation-etag")},
		artifact:       &cerebrov1.EvidenceArtifactMetadata{Revision: complianceReadRevision("artifact-1", "artifact-rev-1", "artifact-etag")},
		plan:           &cerebrov1.AssessmentPlan{Revision: complianceReadRevision("plan-1", "plan-rev-1", "plan-etag")},
		run:            &cerebrov1.AssessmentRun{Revision: complianceReadRevision("run-1", "run-rev-1", "run-etag")},
		result:         &cerebrov1.AssessmentResult{Revision: complianceReadRevision("result-1", "result-rev-1", "result-etag")},
		review:         &cerebrov1.AssessmentReview{Revision: complianceReadRevision("review-1", "review-rev-1", "review-etag")},
		workItem:       &cerebrov1.ComplianceWorkItem{Revision: complianceReadRevision("work-1", "work-rev-1", "work-etag")},
	}
}

func complianceReadRevision(id string, revisionID string, etag string) *cerebrov1.ComplianceRevisionMetadata {
	return &cerebrov1.ComplianceRevisionMetadata{Id: id, RevisionId: revisionID, Version: 1, ContentDigest: etag, Etag: etag}
}

func (s *complianceReadStubStore) Ping(context.Context) error { return nil }

func (s *complianceReadStubStore) recordList(tenantID string, _ complianceread.Page) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTenant = tenantID
	s.listCalls++
}

func pageOf[T any](tenantID string, value T) complianceread.PageResult[T] {
	return complianceread.PageResult[T]{
		Records: []complianceread.TenantRecord[T]{{TenantID: tenantID, Value: value}},
		Next:    &complianceread.Keyset{LastModified: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC), ID: "program-1", RevisionID: "program-rev-1"},
	}
}

func (s *complianceReadStubStore) ListCompliancePrograms(_ context.Context, tenantID string, _ *cerebrov1.ListComplianceProgramsRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.ComplianceProgram], error) {
	s.recordList(tenantID, page)
	s.mu.Lock()
	s.programPage = page
	s.mu.Unlock()
	return pageOf(s.returnTenant, s.program), nil
}
func (s *complianceReadStubStore) GetComplianceProgram(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.ComplianceProgram], error) {
	return complianceread.TenantRecord[*cerebrov1.ComplianceProgram]{TenantID: s.returnTenant, Value: s.program}, s.getErr
}
func (s *complianceReadStubStore) ListControlImplementations(_ context.Context, tenantID string, _ *cerebrov1.ListControlImplementationsRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.ControlImplementation], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.implementation), nil
}
func (s *complianceReadStubStore) GetControlImplementation(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.ControlImplementation], error) {
	return complianceread.TenantRecord[*cerebrov1.ControlImplementation]{TenantID: s.returnTenant, Value: s.implementation}, s.getErr
}
func (s *complianceReadStubStore) ListEvidenceArtifactMetadata(_ context.Context, tenantID string, _ *cerebrov1.ListEvidenceArtifactMetadataRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.EvidenceArtifactMetadata], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.artifact), nil
}
func (s *complianceReadStubStore) GetEvidenceArtifactMetadata(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.EvidenceArtifactMetadata], error) {
	return complianceread.TenantRecord[*cerebrov1.EvidenceArtifactMetadata]{TenantID: s.returnTenant, Value: s.artifact}, s.getErr
}
func (s *complianceReadStubStore) ListAssessmentPlans(_ context.Context, tenantID string, _ *cerebrov1.ListAssessmentPlansRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.AssessmentPlan], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.plan), nil
}
func (s *complianceReadStubStore) GetAssessmentPlan(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.AssessmentPlan], error) {
	return complianceread.TenantRecord[*cerebrov1.AssessmentPlan]{TenantID: s.returnTenant, Value: s.plan}, s.getErr
}
func (s *complianceReadStubStore) ListAssessmentRuns(_ context.Context, tenantID string, _ *cerebrov1.ListAssessmentRunsRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.AssessmentRun], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.run), nil
}
func (s *complianceReadStubStore) GetAssessmentRun(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.AssessmentRun], error) {
	return complianceread.TenantRecord[*cerebrov1.AssessmentRun]{TenantID: s.returnTenant, Value: s.run}, s.getErr
}
func (s *complianceReadStubStore) ListAssessmentResults(_ context.Context, tenantID string, _ *cerebrov1.ListAssessmentResultsRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.AssessmentResult], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.result), nil
}
func (s *complianceReadStubStore) GetAssessmentResult(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.AssessmentResult], error) {
	return complianceread.TenantRecord[*cerebrov1.AssessmentResult]{TenantID: s.returnTenant, Value: s.result}, s.getErr
}
func (s *complianceReadStubStore) ListAssessmentReviews(_ context.Context, tenantID string, _ *cerebrov1.ListAssessmentReviewsRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.AssessmentReview], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.review), nil
}
func (s *complianceReadStubStore) GetAssessmentReview(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.AssessmentReview], error) {
	return complianceread.TenantRecord[*cerebrov1.AssessmentReview]{TenantID: s.returnTenant, Value: s.review}, s.getErr
}
func (s *complianceReadStubStore) ListComplianceWorkItems(_ context.Context, tenantID string, _ *cerebrov1.ListComplianceWorkItemsRequest, page complianceread.Page) (complianceread.PageResult[*cerebrov1.ComplianceWorkItem], error) {
	s.recordList(tenantID, page)
	return pageOf(s.returnTenant, s.workItem), nil
}
func (s *complianceReadStubStore) GetComplianceWorkItem(context.Context, string, string, string) (complianceread.TenantRecord[*cerebrov1.ComplianceWorkItem], error) {
	return complianceread.TenantRecord[*cerebrov1.ComplianceWorkItem]{TenantID: s.returnTenant, Value: s.workItem}, s.getErr
}

var _ complianceread.Repository = (*complianceReadStubStore)(nil)
