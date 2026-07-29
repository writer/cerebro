package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securitylifecyclefindings"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type lifecycleFindingQueryStub struct {
	resolveResponses []*cerebrov1.ResolveSecurityLifecycleFindingResponse
	resolveErrors    []error
	resolveCalls     int
	listResult       *cerebrov1.SecurityLifecycleQueryResult
	listQueries      []*cerebrov1.SecurityLifecycleQuery
}

func (s *lifecycleFindingQueryStub) ResolveSecurityLifecycleFinding(_ context.Context, _, _ string) (*cerebrov1.ResolveSecurityLifecycleFindingResponse, error) {
	index := s.resolveCalls
	s.resolveCalls++
	if index < len(s.resolveErrors) && s.resolveErrors[index] != nil {
		return nil, s.resolveErrors[index]
	}
	if index >= len(s.resolveResponses) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("lifecycle finding is not open"))
	}
	return s.resolveResponses[index], nil
}

func (s *lifecycleFindingQueryStub) ListSecurityLifecycle(_ context.Context, query *cerebrov1.SecurityLifecycleQuery) (*cerebrov1.SecurityLifecycleQueryResult, error) {
	s.listQueries = append(s.listQueries, query)
	return s.listResult, nil
}

type lifecycleReceiptStub struct {
	manifests []ports.SourceCollectionManifest
	calls     [][3]string
}

func (s *lifecycleReceiptStub) GetSourceCollection(_ context.Context, tenantID, runtimeID, collectionID string) (ports.SourceCollectionManifest, error) {
	s.calls = append(s.calls, [3]string{tenantID, runtimeID, collectionID})
	if len(s.manifests) == 0 {
		return ports.SourceCollectionManifest{}, errors.New("unexpected source collection lookup")
	}
	manifest := s.manifests[0]
	s.manifests = s.manifests[1:]
	return manifest, nil
}

func TestSecurityLifecycleFindingReconcileUsesDurableFindingAndAuditAuthorities(t *testing.T) {
	const (
		tenantID   = "tenant-a"
		runtimeID  = "runtime-lifecycle"
		findingURN = "urn:cerebro:tenant-a:finding:urn%3Acerebro%3Atenant-a%3Acredential%3Aauthority-a%3Adeploy-signing"
		subjectURN = "urn:cerebro:tenant-a:credential:authority-a:deploy-signing"
	)
	openedAt := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	providerAt := openedAt.Add(5 * time.Minute)
	verifiedAt := openedAt.Add(15 * time.Minute)
	query := &lifecycleFindingQueryStub{
		resolveResponses: []*cerebrov1.ResolveSecurityLifecycleFindingResponse{
			lifecycleResolverResponse(findingURN, subjectURN, runtimeID, "collection-open", "material-1", "expiring", openedAt, "urn:cerebro:tenant-a:evidence:open"),
			lifecycleResolverResponse(findingURN, subjectURN, runtimeID, "collection-provider-success", "material-2", "expiring", providerAt, "urn:cerebro:tenant-a:evidence:provider-success"),
		},
		resolveErrors: []error{
			nil,
			nil,
			connect.NewError(connect.CodeNotFound, errors.New("lifecycle finding is not open")),
			connect.NewError(connect.CodeNotFound, errors.New("lifecycle finding is not open")),
		},
		listResult: lifecycleCompliantResult(subjectURN, runtimeID, "collection-verified", verifiedAt),
	}
	receipt := &lifecycleReceiptStub{manifests: []ports.SourceCollectionManifest{
		{
			CollectionID:          "collection-verified",
			TenantID:              tenantID,
			RuntimeID:             runtimeID,
			Status:                "incomplete",
			CompletedAtUnixMS:     verifiedAt.Add(time.Minute).UnixMilli(),
			IncompletenessReasons: []string{"page_limit_reached"},
		},
		{
			CollectionID:      "collection-verified",
			TenantID:          tenantID,
			RuntimeID:         runtimeID,
			Status:            "complete",
			CompletedAtUnixMS: verifiedAt.Add(time.Minute).UnixMilli(),
		},
	}}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:       runtimeID,
				TenantId: tenantID,
				SourceId: "security-lifecycle-source",
			},
		},
		findings:        map[string]*ports.FindingRecord{},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{},
	}
	log := &recordingAppendLog{}
	app := &App{deps: Dependencies{
		AppendLog:                log,
		StateStore:               store,
		SecurityLifecycleQueries: query,
		SourceCollectionReceipts: receipt,
	}}

	first := reconcileLifecycleFinding(t, app)
	if first.code != http.StatusOK || first.body.Status != "open" || first.body.FindingID != findingURN {
		t.Fatalf("first reconcile = %#v", first)
	}
	stored := store.findings[findingURN]
	if stored == nil || stored.RuntimeID != runtimeID {
		t.Fatalf("durable finding = %#v, want actual runtime %q", stored, runtimeID)
	}
	if stored.Fingerprint == "" {
		t.Fatal("durable finding fingerprint is empty")
	}
	openFingerprint := stored.Fingerprint

	previewRequest := tenantRequest(httptest.NewRequest(http.MethodGet, lifecycleAuditPreviewURL(findingURN), nil), tenantID)
	preview, err := app.buildGRCAuditPreview(previewRequest, findingURN)
	if err != nil {
		t.Fatalf("buildGRCAuditPreview(open) error = %v", err)
	}
	if preview.Finding.ID != findingURN || preview.FindingRecord.RuntimeID != runtimeID {
		t.Fatalf("audit preview finding/runtime = %q/%q", preview.Finding.ID, preview.FindingRecord.RuntimeID)
	}

	second := reconcileLifecycleFinding(t, app)
	if second.code != http.StatusOK || second.body.Status != "open" {
		t.Fatalf("provider-success reconcile = %#v", second)
	}
	if got := store.findings[findingURN]; got.Status != "open" || got.Fingerprint != openFingerprint {
		t.Fatalf("finding after provider success = %#v, want stable open finding", got)
	}

	incomplete := reconcileLifecycleFinding(t, app)
	if incomplete.code != http.StatusAccepted ||
		incomplete.body.Verification != "collection_incomplete" ||
		store.findings[findingURN].Status != "open" {
		t.Fatalf("incomplete reconcile = %#v finding=%#v", incomplete, store.findings[findingURN])
	}

	verified := reconcileLifecycleFinding(t, app)
	if verified.code != http.StatusOK ||
		verified.body.Status != "resolved" ||
		verified.body.Verification != "verified_closed" {
		t.Fatalf("verified reconcile = %#v", verified)
	}
	if got := store.findings[findingURN]; got.Status != "resolved" {
		t.Fatalf("finding after verified observation = %#v", got)
	}
	if len(receipt.calls) != 2 {
		t.Fatalf("receipt lookups = %d, want incomplete and complete checks", len(receipt.calls))
	}
	for _, call := range receipt.calls {
		if call != [3]string{tenantID, runtimeID, "collection-verified"} {
			t.Fatalf("receipt lookup = %#v, want exact tenant/runtime/collection", call)
		}
	}
	if len(query.listQueries) != 2 {
		t.Fatalf("exact subject queries = %d, want two closure attempts", len(query.listQueries))
	}
	for _, exact := range query.listQueries {
		locator := exact.GetSubjectLocator()
		if locator.GetAuthorityId() != "authority-a" ||
			locator.GetStableLocator() != "deploy-signing" ||
			exact.GetLimit() != 2 {
			t.Fatalf("exact subject query = %#v", exact)
		}
	}

	preview, err = app.buildGRCAuditPreview(previewRequest, findingURN)
	if err != nil {
		t.Fatalf("buildGRCAuditPreview(resolved) error = %v", err)
	}
	if preview.Finding.ID != findingURN || preview.Finding.Status != "RESOLVED" {
		t.Fatalf("resolved audit preview finding = %#v", preview.Finding)
	}
	if len(preview.Evidence) != 3 {
		t.Fatalf("resolved audit preview evidence = %d, want open, provider-success, and verified observations", len(preview.Evidence))
	}

	alreadyResolved := reconcileLifecycleFinding(t, app)
	if alreadyResolved.code != http.StatusOK ||
		alreadyResolved.body.Status != "resolved" ||
		alreadyResolved.body.Verification != "already_resolved" {
		t.Fatalf("already-resolved reconcile = %#v", alreadyResolved)
	}
	if len(receipt.calls) != 2 {
		t.Fatalf("receipt lookups after already-resolved reconcile = %d, want no additional lookup", len(receipt.calls))
	}
	if len(query.listQueries) != 2 {
		t.Fatalf("exact subject queries after already-resolved reconcile = %d, want no additional query", len(query.listQueries))
	}
}

func TestSecurityLifecycleFindingReconcileRejectsMissingFindingsService(t *testing.T) {
	query := &lifecycleFindingQueryStub{}
	_, err := securitylifecyclefindings.New(nil, query, nil).Reconcile(
		context.Background(),
		"tenant-a",
		"urn:cerebro:tenant-a:finding:lifecycle",
	)
	if !errors.Is(err, securitylifecyclefindings.ErrDependency) {
		t.Fatalf("Reconcile() error = %v, want ErrDependency", err)
	}
	if query.resolveCalls != 0 {
		t.Fatalf("lifecycle resolver calls = %d, want dependency validation before query", query.resolveCalls)
	}
}

func TestLifecycleOpenObservationRequiresMatchingResolverProvenanceAliases(t *testing.T) {
	const (
		findingURN = "urn:cerebro:tenant-a:finding:urn%3Acerebro%3Atenant-a%3Acredential%3Aauthority-a%3Adeploy-signing"
		subjectURN = "urn:cerebro:tenant-a:credential:authority-a:deploy-signing"
	)
	response := lifecycleResolverResponse(
		findingURN,
		subjectURN,
		"runtime-lifecycle",
		"",
		"material-1",
		"expiring",
		time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
		"urn:cerebro:tenant-a:evidence:open",
	)
	observation, err := securitylifecyclefindings.ObservationFromResolved("tenant-a", findingURN, response)
	if err != nil {
		t.Fatalf("ObservationFromResolved(pending collection) error = %v", err)
	}
	if observation.SourceCollectionID != "" {
		t.Fatalf("pending source collection = %q, want empty", observation.SourceCollectionID)
	}

	response.SourceRuntimeId = "other-runtime"
	if _, err := securitylifecyclefindings.ObservationFromResolved("tenant-a", findingURN, response); err == nil {
		t.Fatal("ObservationFromResolved(runtime alias mismatch) succeeded")
	}
	response.SourceRuntimeId = response.GetRecord().GetSourceRuntimeId()
	response.SourceCollectionId = "other-collection"
	if _, err := securitylifecyclefindings.ObservationFromResolved("tenant-a", findingURN, response); err == nil {
		t.Fatal("ObservationFromResolved(collection alias mismatch) succeeded")
	}
}

func TestSecurityLifecycleReconcileRouteRequiresFindingWriteScope(t *testing.T) {
	path := "/grc/findings/lifecycle-finding/security-lifecycle/reconcile"
	policy := httpRoutePolicyFor(http.MethodPost, path)
	if policy.Scope != scopeFindingLifecycleWrite {
		t.Fatalf("POST %s scope = %q, want %q", path, policy.Scope, scopeFindingLifecycleWrite)
	}
	viewer := authPrincipal{Roles: []string{roleCerebroViewer}}
	if err := authorizePrincipalHTTPPolicy(viewer, policy); err == nil {
		t.Fatal("viewer authorized for lifecycle finding reconcile")
	}
	manager := authPrincipal{Roles: []string{roleCerebroFindingManager}}
	if err := authorizePrincipalHTTPPolicy(manager, policy); err != nil {
		t.Fatalf("finding manager rejected for lifecycle finding reconcile: %v", err)
	}
}

type lifecycleReconcileResult struct {
	code int
	body securityLifecycleReconcileResponse
}

func reconcileLifecycleFinding(t *testing.T, app *App) lifecycleReconcileResult {
	t.Helper()
	const (
		tenantID  = "tenant-a"
		findingID = "urn:cerebro:tenant-a:finding:urn%3Acerebro%3Atenant-a%3Acredential%3Aauthority-a%3Adeploy-signing"
	)
	body, err := json.Marshal(securityLifecycleReconcileRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("marshal reconcile request: %v", err)
	}
	request := tenantRequest(
		httptest.NewRequest(http.MethodPost, "/grc/findings/lifecycle/security-lifecycle/reconcile", bytes.NewReader(body)),
		tenantID,
	)
	request.SetPathValue("findingID", findingID)
	response := httptest.NewRecorder()
	app.handleReconcileSecurityLifecycleFinding(response, request)
	var decoded securityLifecycleReconcileResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode reconcile response status=%d body=%q: %v", response.Code, response.Body.String(), err)
	}
	return lifecycleReconcileResult{code: response.Code, body: decoded}
}

func tenantRequest(request *http.Request, tenantID string) *http.Request {
	return request.WithContext(context.WithValue(
		request.Context(),
		authContextKey{},
		authContext{principal: authPrincipal{TenantID: tenantID}},
	))
}

func lifecycleResolverResponse(findingURN, subjectURN, runtimeID, collectionID, revision, policyState string, observedAt time.Time, evidenceURN string) *cerebrov1.ResolveSecurityLifecycleFindingResponse {
	subject := &cerebrov1.ResourceRef{Kind: "credential", Id: subjectURN, Revision: revision}
	evidence := &cerebrov1.ResourceRef{Kind: "evidence", Id: evidenceURN}
	record := &cerebrov1.SecurityLifecycleRecord{
		Observation: &cerebrov1.SecurityLifecycleObservation{
			SubjectRef:        subject,
			SubjectKind:       cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL,
			Provider:          "provider-a",
			AuthorityId:       "authority-a",
			StableLocator:     "deploy-signing",
			DisplayName:       "Deploy signing credential",
			State:             cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_ACTIVE,
			ObservedAt:        timestamppb.New(observedAt),
			ExpiresAt:         timestamppb.New(openedExpiry(observedAt)),
			OwnerUrn:          "urn:cerebro:tenant-a:team:security",
			EvidenceClaimRefs: []*cerebrov1.ResourceRef{evidence},
		},
		PolicyEvaluations: []*cerebrov1.SecurityLifecyclePolicyEvaluation{{
			PolicyId:          "security.lifecycle.expiry",
			PolicyVersion:     "1",
			SubjectRef:        subject,
			State:             policyState,
			EvaluatedAt:       timestamppb.New(observedAt),
			EvidenceClaimRefs: []*cerebrov1.ResourceRef{evidence},
		}},
		Findings: []*cerebrov1.SecurityLifecycleFindingBinding{{
			FindingRef:        &cerebrov1.ResourceRef{Kind: "finding", Id: findingURN, State: "open"},
			SubjectRef:        subject,
			FindingKind:       "credential_expiry",
			Status:            "open",
			EvidenceClaimRefs: []*cerebrov1.ResourceRef{evidence},
		}},
		SourceRuntimeId:    runtimeID,
		SourceCollectionId: collectionID,
	}
	return &cerebrov1.ResolveSecurityLifecycleFindingResponse{
		Record:             record,
		GraphRevision:      42,
		SourceRuntimeId:    runtimeID,
		SourceCollectionId: collectionID,
	}
}

func lifecycleCompliantResult(subjectURN, runtimeID, collectionID string, observedAt time.Time) *cerebrov1.SecurityLifecycleQueryResult {
	subject := &cerebrov1.ResourceRef{Kind: "credential", Id: subjectURN, Revision: "material-3"}
	return &cerebrov1.SecurityLifecycleQueryResult{
		Records: []*cerebrov1.SecurityLifecycleRecord{{
			Observation: &cerebrov1.SecurityLifecycleObservation{
				SubjectRef:        subject,
				SubjectKind:       cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL,
				Provider:          "provider-a",
				AuthorityId:       "authority-a",
				StableLocator:     "deploy-signing",
				DisplayName:       "Deploy signing credential",
				State:             cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_ACTIVE,
				ObservedAt:        timestamppb.New(observedAt),
				ExpiresAt:         timestamppb.New(openedExpiry(observedAt)),
				EvidenceClaimRefs: []*cerebrov1.ResourceRef{{Kind: "evidence", Id: "urn:cerebro:tenant-a:evidence:verified-observation"}},
			},
			PolicyEvaluations: []*cerebrov1.SecurityLifecyclePolicyEvaluation{{
				PolicyId:          "security.lifecycle.expiry",
				PolicyVersion:     "1",
				SubjectRef:        subject,
				State:             "compliant",
				EvaluatedAt:       timestamppb.New(observedAt),
				EvidenceClaimRefs: []*cerebrov1.ResourceRef{{Kind: "evidence", Id: "urn:cerebro:tenant-a:evidence:verified-observation"}},
			}},
			SourceRuntimeId:    runtimeID,
			SourceCollectionId: collectionID,
		}},
		Metadata: &cerebrov1.SecurityLifecycleQueryMetadata{
			Coverage: &cerebrov1.SecurityLifecycleCoverage{
				Complete: true,
				Reason:   cerebrov1.SecurityLifecycleCoverageReason_SECURITY_LIFECYCLE_COVERAGE_REASON_COMPLETE,
			},
			Freshness: &cerebrov1.SecurityLifecycleFreshness{
				AsOf:             timestamppb.New(observedAt.Add(time.Minute)),
				OldestObservedAt: timestamppb.New(observedAt),
				NewestObservedAt: timestamppb.New(observedAt),
			},
		},
	}
}

func openedExpiry(observedAt time.Time) time.Time {
	return observedAt.Add(90 * 24 * time.Hour)
}
