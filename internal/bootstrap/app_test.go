package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/claims"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/workflowevents"
	"github.com/writer/cerebro/internal/workflowprojection"
	githubsource "github.com/writer/cerebro/sources/github"
	oktasource "github.com/writer/cerebro/sources/okta"
	sdksource "github.com/writer/cerebro/sources/sdk"
)

func sourceGet(t *testing.T, server *httptest.Server, path string, config map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		return nil, err
	}
	if len(config) > 0 {
		payload, err := json.Marshal(config)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Cerebro-Source-Config", string(payload))
	}
	return server.Client().Do(req)
}

func TestSourceConfigFromRequestRejectsSensitiveQueryKeys(t *testing.T) {
	for _, key := range []string{"token", "api_key", "apiKey", "secret_access_key", "private_key", "privateKey", "signing_key", "key"} {
		t.Run(key, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sources/okta/check?"+key+"=secret", nil)
			if _, err := sourceConfigFromRequest(req); !errors.Is(err, sourceops.ErrInvalidRequest) {
				t.Fatalf("sourceConfigFromRequest() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestSourceConfigFromRequestAllowsAWSAccessKeyIDQueryField(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/aws/check?account_id=123456789012&access_key_id=AKIAEXAMPLE", nil)
	config, err := sourceConfigFromRequest(req)
	if err != nil {
		t.Fatalf("sourceConfigFromRequest() error = %v", err)
	}
	if got := config["account_id"]; got != "123456789012" {
		t.Fatalf("config[account_id] = %q, want 123456789012", got)
	}
	if got := config["access_key_id"]; got != "AKIAEXAMPLE" {
		t.Fatalf("config[access_key_id] = %q, want AKIAEXAMPLE", got)
	}
}

func TestSourceConfigFromRequestAllowsNonSecretKeyQueryFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sources/aws/check?region=us-east-1&lookup_key=inventory&group_key=security@example.com&access_key_id=AKIAEXAMPLE", nil)
	config, err := sourceConfigFromRequest(req)
	if err != nil {
		t.Fatalf("sourceConfigFromRequest() error = %v", err)
	}
	for _, key := range []string{"region", "lookup_key", "group_key", "access_key_id"} {
		if got := config[key]; got == "" {
			t.Fatalf("config[%q] = %q, want value", key, got)
		}
	}
}

func TestConnectErrorHelpersUseSpecificCodes(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		code connect.Code
	}{
		{name: "report not found", err: reportConnectError(reports.ErrReportNotFound), code: connect.CodeNotFound},
		{name: "report unavailable", err: reportConnectError(reports.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "report invalid", err: reportConnectError(reports.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "report unknown", err: reportConnectError(errors.New("storage failed")), code: connect.CodeInternal},
		{name: "report canceled", err: reportConnectError(context.Canceled), code: connect.CodeCanceled},
		{name: "report deadline", err: reportConnectError(context.DeadlineExceeded), code: connect.CodeDeadlineExceeded},
		{name: "source not found", err: sourceConnectError(sourceops.ErrSourceNotFound), code: connect.CodeNotFound},
		{name: "source invalid", err: sourceConnectError(sourceops.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "source unknown", err: sourceConnectError(errors.New("transport failed")), code: connect.CodeInternal},
		{name: "runtime not found", err: sourceRuntimeConnectError(ports.ErrSourceRuntimeNotFound), code: connect.CodeNotFound},
		{name: "runtime unavailable", err: sourceRuntimeConnectError(sourceruntime.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "runtime invalid", err: sourceRuntimeConnectError(sourceruntime.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "runtime unknown", err: sourceRuntimeConnectError(errors.New("persist failed")), code: connect.CodeInternal},
		{name: "claim runtime not found", err: claimConnectError(ports.ErrSourceRuntimeNotFound), code: connect.CodeNotFound},
		{name: "claim invalid", err: claimConnectError(claims.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "claim unknown", err: claimConnectError(errors.New("persist failed")), code: connect.CodeInternal},
		{name: "finding not found", err: findingConnectError(ports.ErrFindingNotFound), code: connect.CodeNotFound},
		{name: "finding rule not found", err: findingConnectError(findings.ErrRuleNotFound), code: connect.CodeNotFound},
		{name: "finding rule selection required", err: findingConnectError(findings.ErrRuleSelectionRequired), code: connect.CodeInvalidArgument},
		{name: "finding rule unsupported", err: findingConnectError(findings.ErrRuleUnsupported), code: connect.CodeInvalidArgument},
		{name: "finding invalid", err: findingConnectError(findings.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "finding rule unavailable", err: findingConnectError(findings.ErrRuleUnavailable), code: connect.CodeFailedPrecondition},
		{name: "finding unavailable", err: findingConnectError(findings.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "finding unknown", err: findingConnectError(errors.New("finding store failed")), code: connect.CodeInternal},
		{name: "knowledge entity not found", err: knowledgeConnectError(ports.ErrGraphEntityNotFound), code: connect.CodeNotFound},
		{name: "knowledge invalid", err: knowledgeConnectError(knowledge.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "knowledge unavailable", err: knowledgeConnectError(knowledge.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "knowledge unknown", err: knowledgeConnectError(errors.New("knowledge store failed")), code: connect.CodeInternal},
		{name: "workflow replay unavailable", err: workflowReplayConnectError(workflowprojection.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "workflow replay unknown", err: workflowReplayConnectError(errors.New("replay failed")), code: connect.CodeInternal},
		{name: "graph query entity not found", err: graphQueryConnectError(ports.ErrGraphEntityNotFound), code: connect.CodeNotFound},
		{name: "graph query unavailable", err: graphQueryConnectError(graphquery.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "graph query invalid", err: graphQueryConnectError(graphquery.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "graph ingest run not found", err: graphIngestConnectError(graphingest.ErrRunNotFound), code: connect.CodeNotFound},
		{name: "graph ingest source not found", err: graphIngestConnectError(sourceops.ErrSourceNotFound), code: connect.CodeNotFound},
		{name: "graph ingest unavailable", err: graphIngestConnectError(graphingest.ErrRuntimeUnavailable), code: connect.CodeUnavailable},
		{name: "graph ingest invalid", err: graphIngestConnectError(graphingest.ErrInvalidRequest), code: connect.CodeInvalidArgument},
		{name: "graph ingest unknown", err: graphIngestConnectError(errors.New("graph ingest failed")), code: connect.CodeInternal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := connect.CodeOf(tt.err); got != tt.code {
				t.Fatalf("connect.CodeOf() = %s, want %s", got, tt.code)
			}
		})
	}
}

func TestConnectInternalErrorsHideDetails(t *testing.T) {
	internalErr := errors.New("postgres password leaked")
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "report", err: reportConnectError(internalErr)},
		{name: "source", err: sourceConnectError(internalErr)},
		{name: "runtime", err: sourceRuntimeConnectError(internalErr)},
		{name: "claim", err: claimConnectError(internalErr)},
		{name: "finding", err: findingConnectError(internalErr)},
		{name: "knowledge", err: knowledgeConnectError(internalErr)},
		{name: "workflow replay", err: workflowReplayConnectError(internalErr)},
		{name: "graph query", err: graphQueryConnectError(internalErr)},
		{name: "graph ingest", err: graphIngestConnectError(internalErr)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := connect.CodeOf(tt.err); got != connect.CodeInternal {
				t.Fatalf("connect.CodeOf() = %s, want %s", got, connect.CodeInternal)
			}
			var connectErr *connect.Error
			if !errors.As(tt.err, &connectErr) {
				t.Fatalf("error = %T, want *connect.Error", tt.err)
			}
			if strings.Contains(connectErr.Message(), "postgres password leaked") {
				t.Fatalf("connect error exposed internal detail: %q", connectErr.Message())
			}
			if !strings.Contains(connectErr.Message(), "internal error") {
				t.Fatalf("connect error = %q, want generic internal error", connectErr.Message())
			}
		})
	}
}

func TestWriteSourceRuntimeErrorDoesNotExposeInternalMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeSourceRuntimeError(recorder, errors.New("postgres password leaked"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if strings.Contains(recorder.Body.String(), "postgres password leaked") {
		t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
		t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
	}

	invalid := httptest.NewRecorder()
	writeSourceRuntimeError(invalid, sourceruntime.ErrInvalidRequest)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid runtime status = %d, want %d", invalid.Code, http.StatusBadRequest)
	}
}

func TestWriteKnowledgeErrorMapsInvalidRequestToBadRequest(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeKnowledgeError(recorder, knowledge.ErrInvalidRequest)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestWriteHTTPErrorHelpersDoNotExposeInternalMessages(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(http.ResponseWriter, error)
	}{
		{name: "source", write: writeSourceError},
		{name: "claim", write: writeClaimError},
		{name: "finding", write: writeFindingError},
		{name: "knowledge", write: writeKnowledgeError},
		{name: "workflow replay", write: writeWorkflowReplayError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.write(recorder, errors.New("postgres password leaked"))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
			}
			if strings.Contains(recorder.Body.String(), "postgres password leaked") {
				t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
				t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
			}
		})
	}
}

func TestInvalidHTTPRequestErrorsReturnBadRequest(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(http.ResponseWriter, error)
	}{
		{name: "source", write: writeSourceError},
		{name: "report", write: writeReportError},
		{name: "source runtime", write: writeSourceRuntimeError},
		{name: "claim", write: writeClaimError},
		{name: "finding", write: writeFindingError},
		{name: "knowledge", write: writeKnowledgeError},
		{name: "workflow replay", write: writeWorkflowReplayError},
		{name: "graph query", write: writeGraphQueryError},
		{name: "graph ingest", write: writeGraphIngestError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.write(recorder, invalidHTTPRequestError(errors.New("bad query param")))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestWriteReportErrorDoesNotExposeInternalMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeReportError(recorder, errors.New("postgres password leaked"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if strings.Contains(recorder.Body.String(), "postgres password leaked") {
		t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
		t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
	}

	invalid := httptest.NewRecorder()
	writeReportError(invalid, reports.ErrInvalidRequest)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid report status = %d, want %d", invalid.Code, http.StatusBadRequest)
	}
}

func TestWriteGraphErrorsDoNotExposeInternalMessages(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(http.ResponseWriter, error)
	}{
		{name: "query", write: writeGraphQueryError},
		{name: "ingest", write: writeGraphIngestError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tt.write(recorder, errors.New("postgres password leaked"))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
			}
			if strings.Contains(recorder.Body.String(), "postgres password leaked") {
				t.Fatalf("response body exposed internal error: %q", recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), http.StatusText(http.StatusInternalServerError)) {
				t.Fatalf("response body = %q, want generic status text", recorder.Body.String())
			}
		})
	}
}

func TestStoreBoundaryHelpersTreatTypedNilAsUnavailable(t *testing.T) {
	var graph *stubGraphStore
	if got := graphQueryStore(graph); got != nil {
		t.Fatalf("graphQueryStore(typed nil) = %#v, want nil", got)
	}
	if got := sourceProjectionGraphStore(graph); got != nil {
		t.Fatalf("sourceProjectionGraphStore(typed nil) = %#v, want nil", got)
	}
	var state *stubRuntimeStore
	if got := sourceRuntimeStore(state); got != nil {
		t.Fatalf("sourceRuntimeStore(typed nil) = %#v, want nil", got)
	}
	if got := reportStore(state); got != nil {
		t.Fatalf("reportStore(typed nil) = %#v, want nil", got)
	}
	var log *recordingAppendLog
	if got := eventReplayer(log); got != nil {
		t.Fatalf("eventReplayer(typed nil) = %#v, want nil", got)
	}
}

type stubAppendLog struct {
	err error
}

func (s stubAppendLog) Ping(context.Context) error                             { return s.err }
func (s stubAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return s.err }

type stubStore struct {
	err error
}

func (s stubStore) Ping(context.Context) error { return s.err }

type deadlineAwareStore struct {
	sawDeadline bool
}

func (s *deadlineAwareStore) Ping(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("health check deadline is required")
	}
	s.sawDeadline = true
	return nil
}

type typedNilPinger struct{}

func (s *typedNilPinger) Ping(context.Context) error {
	return errors.New("typed nil pinger was called")
}

type recordingAppendLog struct {
	err            error
	events         []*cerebrov1.EventEnvelope
	replayEvents   []*cerebrov1.EventEnvelope
	replayRequests []ports.ReplayRequest
}

func (s *recordingAppendLog) Ping(context.Context) error { return s.err }

func (s *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	return nil
}

func (s *recordingAppendLog) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.replayRequests = append(s.replayRequests, request)
	source := s.events
	if len(s.replayEvents) != 0 {
		source = s.replayEvents
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(source))
	for _, event := range source {
		if event == nil {
			continue
		}
		if request.RuntimeID != "" && event.GetAttributes()[ports.EventAttributeSourceRuntimeID] != request.RuntimeID {
			continue
		}
		if request.KindPrefix != "" && !strings.HasPrefix(event.GetKind(), request.KindPrefix) {
			continue
		}
		if request.TenantID != "" && event.GetTenantId() != request.TenantID {
			continue
		}
		if !matchesReplayAttributes(event, request.AttributeEquals) {
			continue
		}
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
		if request.Limit != 0 && uint32(len(events)) >= request.Limit {
			break
		}
	}
	return events, nil
}

func matchesReplayAttributes(event *cerebrov1.EventEnvelope, expected map[string]string) bool {
	for key, value := range expected {
		if event.GetAttributes()[key] != value {
			return false
		}
	}
	return true
}

type stubRuntimeStore struct {
	err                             error
	runtimes                        map[string]*cerebrov1.SourceRuntime
	entities                        map[string]*ports.ProjectedEntity
	links                           map[string]*ports.ProjectedLink
	claims                          map[string]*ports.ClaimRecord
	claimListRequest                ports.ListClaimsRequest
	findings                        map[string]*ports.FindingRecord
	findingListRequest              ports.ListFindingsRequest
	findingEvidence                 map[string]*cerebrov1.FindingEvidence
	findingEvidenceListRequest      ports.ListFindingEvidenceRequest
	findingEvaluationRuns           map[string]*cerebrov1.FindingEvaluationRun
	findingEvaluationRunListRequest ports.ListFindingEvaluationRunsRequest
	reportRuns                      map[string]*cerebrov1.ReportRun
}

func (s *stubRuntimeStore) Ping(context.Context) error { return s.err }

func (s *stubRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	if s.err != nil {
		return s.err
	}
	if s.runtimes == nil {
		s.runtimes = make(map[string]*cerebrov1.SourceRuntime)
	}
	s.runtimes[runtime.GetId()] = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

func (s *stubRuntimeStore) ListSourceRuntimes(_ context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	if s.err != nil {
		return nil, s.err
	}
	var ids []string
	for id := range s.runtimes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var runtimes []*cerebrov1.SourceRuntime
	for _, id := range ids {
		runtime := s.runtimes[id]
		if filter.TenantID != "" && runtime.GetTenantId() != filter.TenantID {
			continue
		}
		if filter.SourceID != "" && runtime.GetSourceId() != filter.SourceID {
			continue
		}
		runtimes = append(runtimes, proto.Clone(runtime).(*cerebrov1.SourceRuntime))
	}
	return runtimes, nil
}

func (s *stubRuntimeStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.err != nil {
		return s.err
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	s.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (s *stubRuntimeStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.err != nil {
		return s.err
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	s.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

func (s *stubRuntimeStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if finding == nil {
		return nil, nil
	}
	if s.findings == nil {
		s.findings = make(map[string]*ports.FindingRecord)
	}
	cloned := cloneFinding(finding)
	if existing, ok := s.findings[cloned.ID]; ok {
		cloned = preserveFindingWorkflow(existing, cloned)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) GetFinding(_ context.Context, id string) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[id]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	return cloneFinding(finding), nil
}

func (s *stubRuntimeStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	if claim == nil {
		return nil, nil
	}
	if s.claims == nil {
		s.claims = make(map[string]*ports.ClaimRecord)
	}
	s.claims[claim.ID] = cloneClaim(claim)
	return cloneClaim(claim), nil
}

func (s *stubRuntimeStore) ListClaims(_ context.Context, request ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.claimListRequest = request
	claims := []*ports.ClaimRecord{}
	for _, claim := range s.claims {
		if !claimMatches(request, claim) {
			continue
		}
		claims = append(claims, cloneClaim(claim))
	}
	sort.Slice(claims, func(i, j int) bool {
		left := claims[i]
		right := claims[j]
		switch {
		case left.ObservedAt.Equal(right.ObservedAt):
			return left.ID < right.ID
		case left.ObservedAt.IsZero():
			return false
		case right.ObservedAt.IsZero():
			return true
		default:
			return left.ObservedAt.After(right.ObservedAt)
		}
	})
	if request.Limit != 0 && len(claims) > int(request.Limit) {
		claims = claims[:int(request.Limit)]
	}
	return claims, nil
}

func (s *stubRuntimeStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingListRequest = request
	findings := []*ports.FindingRecord{}
	for _, finding := range s.findings {
		if !findingMatches(request, finding) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		switch {
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		case left.LastObservedAt.IsZero():
			return false
		case right.LastObservedAt.IsZero():
			return true
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if request.Limit != 0 && len(findings) > int(request.Limit) {
		findings = findings[:int(request.Limit)]
	}
	return findings, nil
}

func (s *stubRuntimeStore) UpdateFindingStatus(_ context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Status = strings.TrimSpace(request.Status)
	cloned.StatusReason = strings.TrimSpace(request.Reason)
	cloned.StatusUpdatedAt = request.UpdatedAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) UpdateFindingAssignee(_ context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Assignee = strings.TrimSpace(request.Assignee)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) UpdateFindingDueDate(_ context.Context, request ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.DueAt = request.DueAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) AddFindingNote(_ context.Context, request ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	cloned.Notes = append(cloned.Notes, request.Note)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) LinkFindingTicket(_ context.Context, request ports.FindingTicketLink) (*ports.FindingRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	finding, ok := s.findings[request.FindingID]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneFinding(finding)
	exists := false
	for _, ticket := range cloned.Tickets {
		if strings.TrimSpace(ticket.URL) == strings.TrimSpace(request.Ticket.URL) {
			exists = true
			break
		}
	}
	if !exists {
		cloned.Tickets = append(cloned.Tickets, request.Ticket)
	}
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubRuntimeStore) PutFindingEvidence(_ context.Context, evidence *cerebrov1.FindingEvidence) error {
	if s.err != nil {
		return s.err
	}
	if evidence == nil {
		return nil
	}
	if s.findingEvidence == nil {
		s.findingEvidence = make(map[string]*cerebrov1.FindingEvidence)
	}
	s.findingEvidence[evidence.GetId()] = cloneFindingEvidence(evidence)
	return nil
}

func (s *stubRuntimeStore) GetFindingEvidence(_ context.Context, id string) (*cerebrov1.FindingEvidence, error) {
	if s.err != nil {
		return nil, s.err
	}
	evidence, ok := s.findingEvidence[id]
	if !ok {
		return nil, ports.ErrFindingEvidenceNotFound
	}
	return cloneFindingEvidence(evidence), nil
}

func (s *stubRuntimeStore) ListFindingEvidence(_ context.Context, request ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingEvidenceListRequest = request
	evidence := []*cerebrov1.FindingEvidence{}
	for _, record := range s.findingEvidence {
		if !findingEvidenceMatches(request, record) {
			continue
		}
		evidence = append(evidence, cloneFindingEvidence(record))
	}
	sort.Slice(evidence, func(i, j int) bool {
		left := evidence[i]
		right := evidence[j]
		switch {
		case left.GetCreatedAt().AsTime().Equal(right.GetCreatedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetCreatedAt().AsTime().After(right.GetCreatedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(evidence) > int(request.Limit) {
		evidence = evidence[:int(request.Limit)]
	}
	return evidence, nil
}

func (s *stubRuntimeStore) PutFindingEvaluationRun(_ context.Context, run *cerebrov1.FindingEvaluationRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.findingEvaluationRuns == nil {
		s.findingEvaluationRuns = make(map[string]*cerebrov1.FindingEvaluationRun)
	}
	s.findingEvaluationRuns[run.GetId()] = cloneFindingEvaluationRun(run)
	return nil
}

func (s *stubRuntimeStore) GetFindingEvaluationRun(_ context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.findingEvaluationRuns[id]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	return cloneFindingEvaluationRun(run), nil
}

func (s *stubRuntimeStore) ListFindingEvaluationRuns(_ context.Context, request ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.findingEvaluationRunListRequest = request
	runs := []*cerebrov1.FindingEvaluationRun{}
	for _, run := range s.findingEvaluationRuns {
		if !findingEvaluationRunMatches(request, run) {
			continue
		}
		runs = append(runs, cloneFindingEvaluationRun(run))
	}
	sort.Slice(runs, func(i, j int) bool {
		left := runs[i]
		right := runs[j]
		switch {
		case left.GetStartedAt().AsTime().Equal(right.GetStartedAt().AsTime()):
			return left.GetId() < right.GetId()
		default:
			return left.GetStartedAt().AsTime().After(right.GetStartedAt().AsTime())
		}
	})
	if request.Limit != 0 && len(runs) > int(request.Limit) {
		runs = runs[:int(request.Limit)]
	}
	return runs, nil
}

func (s *stubRuntimeStore) PutReportRun(_ context.Context, run *cerebrov1.ReportRun) error {
	if s.err != nil {
		return s.err
	}
	if run == nil {
		return nil
	}
	if s.reportRuns == nil {
		s.reportRuns = make(map[string]*cerebrov1.ReportRun)
	}
	s.reportRuns[run.GetId()] = cloneReportRun(run)
	return nil
}

func (s *stubRuntimeStore) GetReportRun(_ context.Context, id string) (*cerebrov1.ReportRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	run, ok := s.reportRuns[id]
	if !ok {
		return nil, ports.ErrReportRunNotFound
	}
	return cloneReportRun(run), nil
}

type stubGraphStore struct {
	err                 error
	entities            map[string]*ports.ProjectedEntity
	links               map[string]*ports.ProjectedLink
	checkpoints         map[string]graphstore.IngestCheckpoint
	ingestRuns          map[string]graphstore.IngestRun
	neighborhood        *ports.EntityNeighborhood
	neighborhoodRootURN string
	neighborhoodLimit   int
	ingestRunListFilter graphstore.IngestRunFilter
}

func (s *stubGraphStore) Ping(context.Context) error {
	return s.err
}

func (s *stubGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.err != nil {
		return s.err
	}
	if entity == nil {
		return nil
	}
	if s.entities == nil {
		s.entities = make(map[string]*ports.ProjectedEntity)
	}
	s.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (s *stubGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.err != nil {
		return s.err
	}
	if link == nil {
		return nil
	}
	if s.links == nil {
		s.links = make(map[string]*ports.ProjectedLink)
	}
	s.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.neighborhoodRootURN = rootURN
	s.neighborhoodLimit = limit
	if entity, ok := s.entities[rootURN]; ok && entity != nil {
		return &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        entity.URN,
				EntityType: entity.EntityType,
				Label:      entity.Label,
			},
		}, nil
	}
	if s.neighborhood == nil {
		return nil, ports.ErrGraphEntityNotFound
	}
	return cloneNeighborhood(s.neighborhood), nil
}

func (s *stubGraphStore) GetIngestCheckpoint(_ context.Context, id string) (graphstore.IngestCheckpoint, bool, error) {
	if s.err != nil {
		return graphstore.IngestCheckpoint{}, false, s.err
	}
	checkpoint, ok := s.checkpoints[id]
	return checkpoint, ok, nil
}

func (s *stubGraphStore) PutIngestCheckpoint(_ context.Context, checkpoint graphstore.IngestCheckpoint) error {
	if s.err != nil {
		return s.err
	}
	if s.checkpoints == nil {
		s.checkpoints = make(map[string]graphstore.IngestCheckpoint)
	}
	s.checkpoints[checkpoint.ID] = checkpoint
	return nil
}

func (s *stubGraphStore) PutIngestRun(_ context.Context, run graphstore.IngestRun) error {
	if s.err != nil {
		return s.err
	}
	if s.ingestRuns == nil {
		s.ingestRuns = make(map[string]graphstore.IngestRun)
	}
	s.ingestRuns[run.ID] = run
	return nil
}

func (s *stubGraphStore) GetIngestRun(_ context.Context, id string) (graphstore.IngestRun, bool, error) {
	if s.err != nil {
		return graphstore.IngestRun{}, false, s.err
	}
	run, ok := s.ingestRuns[id]
	return run, ok, nil
}

func (s *stubGraphStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.ingestRunListFilter = filter
	runs := make([]graphstore.IngestRun, 0, len(s.ingestRuns))
	for _, run := range s.ingestRuns {
		if filter.RuntimeID != "" && run.RuntimeID != filter.RuntimeID {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool {
		left := runs[i]
		right := runs[j]
		if left.StartedAt == right.StartedAt {
			return left.ID > right.ID
		}
		return left.StartedAt > right.StartedAt
	})
	if filter.Limit > 0 && len(runs) > filter.Limit {
		runs = runs[:filter.Limit]
	}
	return runs, nil
}

func TestBootstrapEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /health response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /health response: %v", err)
	}
	if payload["status"] != "ready" {
		t.Fatalf("health status = %#v, want %q", payload["status"], "ready")
	}
	sourcesResp, err := server.Client().Get(server.URL + "/sources")
	if err != nil {
		t.Fatalf("GET /sources error = %v", err)
	}
	defer func() {
		if closeErr := sourcesResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources response body: %v", closeErr)
		}
	}()
	var sourcesPayload map[string]any
	if err := json.NewDecoder(sourcesResp.Body).Decode(&sourcesPayload); err != nil {
		t.Fatalf("decode /sources response: %v", err)
	}
	entries, ok := sourcesPayload["sources"].([]any)
	if !ok || len(entries) != 3 {
		t.Fatalf("/sources entries = %#v, want 3 entries", sourcesPayload["sources"])
	}
	checkResp, err := sourceGet(t, server, "/sources/github/check", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/check error = %v", err)
	}
	defer func() {
		if closeErr := checkResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/check response body: %v", closeErr)
		}
	}()
	var checkPayload map[string]any
	if err := json.NewDecoder(checkResp.Body).Decode(&checkPayload); err != nil {
		t.Fatalf("decode /sources/github/check response: %v", err)
	}
	if checkPayload["status"] != "ok" {
		t.Fatalf("check status = %#v, want %q", checkPayload["status"], "ok")
	}
	discoverResp, err := sourceGet(t, server, "/sources/github/discover", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/discover error = %v", err)
	}
	defer func() {
		if closeErr := discoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/discover response body: %v", closeErr)
		}
	}()
	var discoverPayload map[string]any
	if err := json.NewDecoder(discoverResp.Body).Decode(&discoverPayload); err != nil {
		t.Fatalf("decode /sources/github/discover response: %v", err)
	}
	if urns, ok := discoverPayload["urns"].([]any); !ok || len(urns) != 2 {
		t.Fatalf("discover urns = %#v, want 2 entries", discoverPayload["urns"])
	}
	readResp, err := sourceGet(t, server, "/sources/github/read", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/read error = %v", err)
	}
	defer func() {
		if closeErr := readResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/github/read response body: %v", closeErr)
		}
	}()
	var readPayload map[string]any
	if err := json.NewDecoder(readResp.Body).Decode(&readPayload); err != nil {
		t.Fatalf("decode /sources/github/read response: %v", err)
	}
	if events, ok := readPayload["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("read events = %#v, want 1 entry", readPayload["events"])
	}
	repeatedCursorResp, err := sourceGet(t, server, "/sources/github/read?cursor=0&cursor=1", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/github/read repeated cursor error = %v", err)
	}
	defer func() {
		if closeErr := repeatedCursorResp.Body.Close(); closeErr != nil {
			t.Fatalf("close repeated cursor response body: %v", closeErr)
		}
	}()
	var repeatedCursorPayload map[string]any
	if err := json.NewDecoder(repeatedCursorResp.Body).Decode(&repeatedCursorPayload); err != nil {
		t.Fatalf("decode repeated cursor response: %v", err)
	}
	repeatedCursorEvents, ok := repeatedCursorPayload["events"].([]any)
	if !ok || len(repeatedCursorEvents) != 1 {
		t.Fatalf("repeated cursor events = %#v, want 1 entry", repeatedCursorPayload["events"])
	}
	repeatedCursorEvent, ok := repeatedCursorEvents[0].(map[string]any)
	if !ok || repeatedCursorEvent["id"] != "github-pr-1" {
		t.Fatalf("repeated cursor event = %#v, want github-pr-1", repeatedCursorEvents[0])
	}
	previewEvents, ok := readPayload["preview_events"].([]any)
	if !ok || len(previewEvents) != 1 {
		t.Fatalf("read preview_events = %#v, want 1 entry", readPayload["preview_events"])
	}
	previewEvent, ok := previewEvents[0].(map[string]any)
	if !ok || previewEvent["event_id"] != "github-audit-1" {
		t.Fatalf("read preview_event = %#v, want event_id github-audit-1", previewEvents[0])
	}
	oktaCheckResp, err := sourceGet(t, server, "/sources/okta/check?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/okta/check error = %v", err)
	}
	defer func() {
		if closeErr := oktaCheckResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/check response body: %v", closeErr)
		}
	}()
	var oktaCheckPayload map[string]any
	if err := json.NewDecoder(oktaCheckResp.Body).Decode(&oktaCheckPayload); err != nil {
		t.Fatalf("decode /sources/okta/check response: %v", err)
	}
	if oktaCheckPayload["status"] != "ok" {
		t.Fatalf("okta check status = %#v, want %q", oktaCheckPayload["status"], "ok")
	}
	oktaDiscoverResp, err := sourceGet(t, server, "/sources/okta/discover?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/okta/discover error = %v", err)
	}
	defer func() {
		if closeErr := oktaDiscoverResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/discover response body: %v", closeErr)
		}
	}()
	var oktaDiscoverPayload map[string]any
	if err := json.NewDecoder(oktaDiscoverResp.Body).Decode(&oktaDiscoverPayload); err != nil {
		t.Fatalf("decode /sources/okta/discover response: %v", err)
	}
	if urns, ok := oktaDiscoverPayload["urns"].([]any); !ok || len(urns) != 2 {
		t.Fatalf("okta discover urns = %#v, want 2 entries", oktaDiscoverPayload["urns"])
	}
	oktaReadResp, err := sourceGet(t, server, "/sources/okta/read?domain=writer.okta.com&family=user", map[string]string{"token": "test"})
	if err != nil {
		t.Fatalf("GET /sources/okta/read error = %v", err)
	}
	defer func() {
		if closeErr := oktaReadResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /sources/okta/read response body: %v", closeErr)
		}
	}()
	var oktaReadPayload map[string]any
	if err := json.NewDecoder(oktaReadResp.Body).Decode(&oktaReadPayload); err != nil {
		t.Fatalf("decode /sources/okta/read response: %v", err)
	}
	if events, ok := oktaReadPayload["events"].([]any); !ok || len(events) != 1 {
		t.Fatalf("okta read events = %#v, want 1 entry", oktaReadPayload["events"])
	}
	oktaPreviewEvents, ok := oktaReadPayload["preview_events"].([]any)
	if !ok || len(oktaPreviewEvents) != 1 {
		t.Fatalf("okta read preview_events = %#v, want 1 entry", oktaReadPayload["preview_events"])
	}
	leakyQueryResp, err := server.Client().Get(server.URL + "/sources/github/check?token=secret")
	if err != nil {
		t.Fatalf("GET /sources/github/check leaky query error = %v", err)
	}
	defer func() {
		if closeErr := leakyQueryResp.Body.Close(); closeErr != nil {
			t.Fatalf("close leaky query response body: %v", closeErr)
		}
	}()
	if leakyQueryResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("leaky query status = %d, want %d", leakyQueryResp.StatusCode, http.StatusBadRequest)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	versionResp, err := client.GetVersion(context.Background(), connect.NewRequest(&cerebrov1.GetVersionRequest{}))
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if versionResp.Msg.ServiceName != buildinfo.ServiceName {
		t.Fatalf("ServiceName = %q, want %q", versionResp.Msg.ServiceName, buildinfo.ServiceName)
	}

	healthResp, err := client.CheckHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckHealthRequest{}))
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if healthResp.Msg.Status != "ready" {
		t.Fatalf("CheckHealth status = %q, want %q", healthResp.Msg.Status, "ready")
	}
	listResp, err := client.ListSources(context.Background(), connect.NewRequest(&cerebrov1.ListSourcesRequest{}))
	if err != nil {
		t.Fatalf("ListSources() error = %v", err)
	}
	if len(listResp.Msg.Sources) != 3 {
		t.Fatalf("len(ListSources.Sources) = %d, want 3", len(listResp.Msg.Sources))
	}
	checkSourceResp, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("CheckSource() error = %v", err)
	}
	if checkSourceResp.Msg.Status != "ok" {
		t.Fatalf("CheckSource status = %q, want %q", checkSourceResp.Msg.Status, "ok")
	}
	discoverSourceResp, err := client.DiscoverSource(context.Background(), connect.NewRequest(&cerebrov1.DiscoverSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("DiscoverSource() error = %v", err)
	}
	if len(discoverSourceResp.Msg.Urns) != 2 {
		t.Fatalf("len(DiscoverSource.Urns) = %d, want 2", len(discoverSourceResp.Msg.Urns))
	}
	readSourceResp, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	}))
	if err != nil {
		t.Fatalf("ReadSource() error = %v", err)
	}
	if len(readSourceResp.Msg.Events) != 1 {
		t.Fatalf("len(ReadSource.Events) = %d, want 1", len(readSourceResp.Msg.Events))
	}
	if len(readSourceResp.Msg.PreviewEvents) != 1 {
		t.Fatalf("len(ReadSource.PreviewEvents) = %d, want 1", len(readSourceResp.Msg.PreviewEvents))
	}
	if !readSourceResp.Msg.PreviewEvents[0].PayloadDecoded {
		t.Fatal("ReadSource.PreviewEvents[0].PayloadDecoded = false, want true")
	}
	oktaCheckSourceResp, err := client.CheckSource(context.Background(), connect.NewRequest(&cerebrov1.CheckSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("CheckSource(okta) error = %v", err)
	}
	if oktaCheckSourceResp.Msg.Status != "ok" {
		t.Fatalf("CheckSource(okta) status = %q, want %q", oktaCheckSourceResp.Msg.Status, "ok")
	}
	oktaDiscoverSourceResp, err := client.DiscoverSource(context.Background(), connect.NewRequest(&cerebrov1.DiscoverSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("DiscoverSource(okta) error = %v", err)
	}
	if len(oktaDiscoverSourceResp.Msg.Urns) != 2 {
		t.Fatalf("len(DiscoverSource(okta).Urns) = %d, want 2", len(oktaDiscoverSourceResp.Msg.Urns))
	}
	oktaReadSourceResp, err := client.ReadSource(context.Background(), connect.NewRequest(&cerebrov1.ReadSourceRequest{
		SourceId: "okta",
		Config: map[string]string{
			"domain": "writer.okta.com",
			"family": "user",
			"token":  "test",
		},
	}))
	if err != nil {
		t.Fatalf("ReadSource(okta) error = %v", err)
	}
	if len(oktaReadSourceResp.Msg.Events) != 1 {
		t.Fatalf("len(ReadSource(okta).Events) = %d, want 1", len(oktaReadSourceResp.Msg.Events))
	}
	if len(oktaReadSourceResp.Msg.PreviewEvents) != 1 {
		t.Fatalf("len(ReadSource(okta).PreviewEvents) = %d, want 1", len(oktaReadSourceResp.Msg.PreviewEvents))
	}
	if !oktaReadSourceResp.Msg.PreviewEvents[0].PayloadDecoded {
		t.Fatal("ReadSource(okta).PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestAuthMiddlewareProtectsNonPublicRoutes(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "test-key",
				Principal: "ci",
				TenantID:  "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	healthResp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error = %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}

	unauthResp, err := server.Client().Get(server.URL + "/sources")
	if err != nil {
		t.Fatalf("GET /sources without auth error = %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /sources without auth status = %d, want %d", unauthResp.StatusCode, http.StatusUnauthorized)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/sources", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	authResp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /sources with auth error = %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sources with auth status = %d, want %d", authResp.StatusCode, http.StatusOK)
	}
}

func TestAuthMiddlewareEnforcesTenantOnHTTPProtoBodies(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	registry, err := sourcecdk.NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(cfg, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := strings.NewReader(`{"runtime":{"id":"runtime-1","sourceId":"github","tenantId":"other"}}`)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/runtime-1", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT /source-runtimes tenant mismatch error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT /source-runtimes tenant mismatch status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestAuthMiddlewareEnforcesTenantOnIDOnlyRoutes(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"other-runtime": {
				Id:       "other-runtime",
				SourceId: "okta",
				TenantId: "other",
			},
		},
		findings: map[string]*ports.FindingRecord{
			"other-finding": {
				ID:       "other-finding",
				TenantID: "other",
			},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, tt := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "get runtime", method: http.MethodGet, path: "/source-runtimes/other-runtime"},
		{name: "sync runtime", method: http.MethodPost, path: "/source-runtimes/other-runtime/sync"},
		{name: "get finding", method: http.MethodGet, path: "/findings/other-finding"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer writer-key")
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s error = %v", tt.method, tt.path, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s status = %d, want %d", tt.method, tt.path, resp.StatusCode, http.StatusForbidden)
			}
		})
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	getRuntimeReq := connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{Id: "other-runtime"})
	getRuntimeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetSourceRuntime(context.Background(), getRuntimeReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetSourceRuntime(other) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	getFindingReq := connect.NewRequest(&cerebrov1.GetFindingRequest{Id: "other-finding"})
	getFindingReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetFinding(context.Background(), getFindingReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetFinding(other) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareRejectsBlankTenantSourceRuntimesForScopedKeys(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"blank-runtime": {
				Id:       "blank-runtime",
				SourceId: "github",
			},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/new-runtime", strings.NewReader(`{"runtime":{"sourceId":"github"}}`))
	if err != nil {
		t.Fatalf("NewRequest put: %v", err)
	}
	putReq.Header.Set("Authorization", "Bearer writer-key")
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := server.Client().Do(putReq)
	if err != nil {
		t.Fatalf("PUT /source-runtimes blank tenant error = %v", err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT /source-runtimes blank tenant status = %d, want %d", putResp.StatusCode, http.StatusForbidden)
	}

	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/source-runtimes/blank-runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest get: %v", err)
	}
	getReq.Header.Set("Authorization", "Bearer writer-key")
	getResp, err := server.Client().Do(getReq)
	if err != nil {
		t.Fatalf("GET /source-runtimes blank tenant error = %v", err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /source-runtimes blank tenant status = %d, want %d", getResp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	putRuntimeReq := connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{Id: "connect-new-runtime", SourceId: "github"},
	})
	putRuntimeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.PutSourceRuntime(context.Background(), putRuntimeReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("PutSourceRuntime(blank tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	getRuntimeReq := connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{Id: "blank-runtime"})
	getRuntimeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetSourceRuntime(context.Background(), getRuntimeReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetSourceRuntime(blank tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnMapBackedProtoFields(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body, err := protojson.Marshal(&cerebrov1.RunReportRequest{
		Parameters: map[string]string{"tenant_id": "other"},
	})
	if err != nil {
		t.Fatalf("marshal report request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/reports/finding-summary/runs", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /reports/finding-summary/runs error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /reports/finding-summary/runs status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	runReq := connect.NewRequest(&cerebrov1.RunReportRequest{
		Parameters: map[string]string{"tenant_id": "other"},
	})
	runReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.RunReport(context.Background(), runReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("RunReport(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnReportRunLookups(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	store := &stubRuntimeStore{
		reportRuns: map[string]*cerebrov1.ReportRun{
			"other-report-run": {
				Id:         "other-report-run",
				ReportId:   "finding-summary",
				Parameters: map[string]string{"tenant_id": "other"},
				Status:     "completed",
			},
		},
	}
	app := New(cfg, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report-runs/other-report-run", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /report-runs/other-report-run error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /report-runs/other-report-run status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	getReq := connect.NewRequest(&cerebrov1.GetReportRunRequest{Id: "other-report-run"})
	getReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetReportRun(context.Background(), getReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetReportRun(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnGraphRootURN(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?root_urn=urn:cerebro:other:github_user:alice", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /platform/graph/neighborhood error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /platform/graph/neighborhood status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	neighborhoodReq := connect.NewRequest(&cerebrov1.GetEntityNeighborhoodRequest{
		RootUrn: "urn:cerebro:other:github_user:alice",
	})
	neighborhoodReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.GetEntityNeighborhood(context.Background(), neighborhoodReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetEntityNeighborhood(other tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestGraphPackageImpactEndpointReturnsCanonicalPackageRoot(t *testing.T) {
	rootURN := "urn:cerebro:writer:package:canonical:pkg:npm/foo"
	graph := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			rootURN: {
				URN:        rootURN,
				TenantID:   "writer",
				SourceID:   "github",
				EntityType: "package",
				Label:      "foo",
			},
		},
	}
	app := New(config.Config{}, Dependencies{GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/platform/graph/impact/package?tenant_id=writer&package=pkg:npm/foo@1.2.3")
	if err != nil {
		t.Fatalf("GET /platform/graph/impact/package error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /platform/graph/impact/package status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		RootURN string `json:"root_urn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.RootURN != rootURN {
		t.Fatalf("root_urn = %q, want %q", body.RootURN, rootURN)
	}
}

func TestGraphImpactEndpointRejectsExplicitZeroBounds(t *testing.T) {
	app := New(config.Config{}, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, query := range []string{
		"tenant_id=writer&package=pkg:npm/foo&limit=0",
		"tenant_id=writer&package=pkg:npm/foo&depth=0",
	} {
		resp, err := server.Client().Get(server.URL + "/platform/graph/impact/package?" + query)
		if err != nil {
			t.Fatalf("GET /platform/graph/impact/package?%s error = %v", query, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET /platform/graph/impact/package?%s status = %d, want %d", query, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

func TestAuthMiddlewareRejectsUnscopedGraphIngestRunListings(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/ingest-runs?status=failed", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer writer-key")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /platform/graph/ingest-runs error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /platform/graph/ingest-runs status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listReq := connect.NewRequest(&cerebrov1.ListGraphIngestRunsRequest{
		Status: graphstore.IngestRunStatusFailed,
	})
	listReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.ListGraphIngestRuns(context.Background(), listReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ListGraphIngestRuns(unscoped) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareRequiresTenantScopeForGlobalWorkflowOperations(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{AppendLog: &recordingAppendLog{}, GraphStore: &stubGraphStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	replayReq, err := http.NewRequest(http.MethodPost, server.URL+"/platform/workflow/replay", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequest replay: %v", err)
	}
	replayReq.Header.Set("Authorization", "Bearer writer-key")
	replayReq.Header.Set("Content-Type", "application/json")
	replayResp, err := server.Client().Do(replayReq)
	if err != nil {
		t.Fatalf("POST /platform/workflow/replay error = %v", err)
	}
	_ = replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /platform/workflow/replay status = %d, want %d", replayResp.StatusCode, http.StatusForbidden)
	}

	healthReq, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/ingest-health", nil)
	if err != nil {
		t.Fatalf("NewRequest health: %v", err)
	}
	healthReq.Header.Set("Authorization", "Bearer writer-key")
	healthResp, err := server.Client().Do(healthReq)
	if err != nil {
		t.Fatalf("GET /platform/graph/ingest-health error = %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /platform/graph/ingest-health status = %d, want %d", healthResp.StatusCode, http.StatusForbidden)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	connectReplayReq := connect.NewRequest(&cerebrov1.ReplayWorkflowEventsRequest{})
	connectReplayReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.ReplayWorkflowEvents(context.Background(), connectReplayReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ReplayWorkflowEvents(unscoped) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	connectHealthReq := connect.NewRequest(&cerebrov1.CheckGraphIngestHealthRequest{})
	connectHealthReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.CheckGraphIngestHealth(context.Background(), connectHealthReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("CheckGraphIngestHealth(scoped) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestAuthMiddlewareEnforcesTenantOnKnowledgeWrites(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:      "writer-key",
				TenantID: "writer",
			}},
		},
	}
	app := New(cfg, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	decisionReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/platform/knowledge/decisions",
		strings.NewReader(`{"decisionType":"finding-triage","targetIds":["urn:cerebro:other:asset:app"]}`),
	)
	if err != nil {
		t.Fatalf("NewRequest decision: %v", err)
	}
	decisionReq.Header.Set("Authorization", "Bearer writer-key")
	decisionReq.Header.Set("Content-Type", "application/json")
	decisionResp, err := server.Client().Do(decisionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/decisions error = %v", err)
	}
	_ = decisionResp.Body.Close()
	if decisionResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /platform/knowledge/decisions status = %d, want %d", decisionResp.StatusCode, http.StatusForbidden)
	}

	actionReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/platform/knowledge/actions",
		strings.NewReader(`{"title":"Fix finding","targetIds":["urn:cerebro:writer:asset:app"],"metadata":{"tenant_id":"other"}}`),
	)
	if err != nil {
		t.Fatalf("NewRequest action: %v", err)
	}
	actionReq.Header.Set("Authorization", "Bearer writer-key")
	actionReq.Header.Set("Content-Type", "application/json")
	actionResp, err := server.Client().Do(actionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/actions error = %v", err)
	}
	_ = actionResp.Body.Close()
	if actionResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /platform/knowledge/actions status = %d, want %d", actionResp.StatusCode, http.StatusForbidden)
	}

	metadata, err := structpb.NewStruct(map[string]any{"tenant_id": "other"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	connectActionReq := connect.NewRequest(&cerebrov1.WriteActionRequest{
		Title:     "Fix finding",
		TargetIds: []string{"urn:cerebro:writer:asset:app"},
		Metadata:  metadata,
	})
	connectActionReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.WriteAction(context.Background(), connectActionReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("WriteAction(other metadata tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
	connectOutcomeReq := connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
		DecisionId:  "urn:cerebro:other:decision:decision-1",
		OutcomeType: "finding-resolution",
		Verdict:     "resolved",
	})
	connectOutcomeReq.Header().Set("Authorization", "Bearer writer-key")
	if _, err := client.WriteOutcome(context.Background(), connectOutcomeReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("WriteOutcome(other decision tenant) code = %s, want %s (err: %v)", connect.CodeOf(err), connect.CodePermissionDenied, err)
	}
}

func TestBootstrapHealthDegradesOnDependencyError(t *testing.T) {
	const rawDependencyError = "state store unavailable at postgres://user:pass@internal-db:5432/cerebro"
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  stubAppendLog{},
		StateStore: stubStore{err: errors.New(rawDependencyError)},
		GraphStore: stubStore{},
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	healthResp, err := client.CheckHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckHealthRequest{}))
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if healthResp.Msg.Status != "degraded" {
		t.Fatalf("CheckHealth status = %q, want %q", healthResp.Msg.Status, "degraded")
	}
	if got := healthResp.Msg.Components[1].Status; got != "error" {
		t.Fatalf("state_store status = %q, want %q", got, "error")
	}
	if got := healthResp.Msg.Components[1].Detail; got != "unhealthy" {
		t.Fatalf("state_store detail = %q, want sanitized detail", got)
	}
	if got := healthResp.Msg.Components[1].Detail; got == rawDependencyError {
		t.Fatalf("state_store detail leaked raw dependency error")
	}
}

func TestBootstrapHealthPingsUseTimeoutContext(t *testing.T) {
	stateStore := &deadlineAwareStore{}
	response := healthResponse(context.Background(), Dependencies{StateStore: stateStore})
	if response.GetStatus() != "ready" {
		t.Fatalf("health status = %q, want ready", response.GetStatus())
	}
	if !stateStore.sawDeadline {
		t.Fatal("state store ping did not receive a deadline")
	}
}

func TestBootstrapHealthTreatsTypedNilPingerAsUnconfigured(t *testing.T) {
	var stateStore *typedNilPinger
	response := healthResponse(context.Background(), Dependencies{StateStore: stateStore})
	if response.GetStatus() != "ready" {
		t.Fatalf("health status = %q, want ready", response.GetStatus())
	}
	if got := response.GetComponents()[1].GetStatus(); got != "unconfigured" {
		t.Fatalf("state_store status = %q, want unconfigured", got)
	}
}

func TestReadProtoJSONRejectsOversizedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/reports/finding-summary/runs", strings.NewReader(strings.Repeat("x", maxProtoJSONBodyBytes+1)))
	err := readProtoJSON(req, &cerebrov1.RunReportRequest{})
	if err == nil {
		t.Fatal("readProtoJSON() error = nil, want non-nil")
	}
	if !errors.Is(err, errProtoJSONBodyTooLarge) {
		t.Fatalf("readProtoJSON() error = %v, want size error", err)
	}
	if !errors.Is(err, errInvalidHTTPRequest) {
		t.Fatalf("readProtoJSON() error = %v, want invalid request error", err)
	}
}

func TestReadProtoJSONClassifiesMalformedBodyAsInvalidRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/reports/finding-summary/runs", strings.NewReader("{"))
	err := readProtoJSON(req, &cerebrov1.RunReportRequest{})
	if !errors.Is(err, errInvalidHTTPRequest) {
		t.Fatalf("readProtoJSON() error = %v, want invalid request error", err)
	}

	recorder := httptest.NewRecorder()
	writeFindingError(recorder, err)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestSourceRuntimeEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{}
	runtimeStore := &stubRuntimeStore{}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	putBody, err := protojson.Marshal(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "user",
				"token":  "test",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal put runtime body: %v", err)
	}
	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/source-runtimes/writer-okta-users", bytes.NewReader(putBody))
	if err != nil {
		t.Fatalf("new put request: %v", err)
	}
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := server.Client().Do(putReq)
	if err != nil {
		t.Fatalf("PUT /source-runtimes/{id} error = %v", err)
	}
	defer func() {
		if closeErr := putResp.Body.Close(); closeErr != nil {
			t.Fatalf("close put runtime response body: %v", closeErr)
		}
	}()
	var putPayload map[string]any
	if err := json.NewDecoder(putResp.Body).Decode(&putPayload); err != nil {
		t.Fatalf("decode put runtime response: %v", err)
	}
	runtimePayload, ok := putPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("put runtime payload = %#v, want object", putPayload["runtime"])
	}
	configPayload, ok := runtimePayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("put runtime config = %#v, want object", runtimePayload["config"])
	}
	if got := configPayload["token"]; got != "[redacted]" {
		t.Fatalf("put runtime token = %#v, want [redacted]", got)
	}
	if got := runtimePayload["tenant_id"]; got != "writer" {
		t.Fatalf("put runtime tenant_id = %#v, want writer", got)
	}

	getResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-users")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get runtime response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode get runtime response: %v", err)
	}
	getRuntimePayload, ok := getPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("get runtime payload = %#v, want object", getPayload["runtime"])
	}
	if got := getRuntimePayload["source_id"]; got != "okta" {
		t.Fatalf("get runtime source_id = %#v, want okta", got)
	}
	if got := getRuntimePayload["tenant_id"]; got != "writer" {
		t.Fatalf("get runtime tenant_id = %#v, want writer", got)
	}

	listResp, err := server.Client().Get(server.URL + "/source-runtimes?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /source-runtimes error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list runtime response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list runtime response: %v", err)
	}
	listRuntimes, ok := listPayload["runtimes"].([]any)
	if !ok || len(listRuntimes) != 1 {
		t.Fatalf("list runtimes = %#v, want one runtime", listPayload["runtimes"])
	}
	listRuntimePayload, ok := listRuntimes[0].(map[string]any)
	if !ok {
		t.Fatalf("listed runtime = %#v, want object", listRuntimes[0])
	}
	listConfigPayload, ok := listRuntimePayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("listed runtime config = %#v, want object", listRuntimePayload["config"])
	}
	if got := listConfigPayload["token"]; got != "[redacted]" {
		t.Fatalf("listed runtime token = %#v, want [redacted]", got)
	}

	syncReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-users/sync?page_limit=1", nil)
	if err != nil {
		t.Fatalf("new sync request: %v", err)
	}
	syncResp, err := server.Client().Do(syncReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/sync error = %v", err)
	}
	defer func() {
		if closeErr := syncResp.Body.Close(); closeErr != nil {
			t.Fatalf("close sync runtime response body: %v", closeErr)
		}
	}()
	var syncPayload map[string]any
	if err := json.NewDecoder(syncResp.Body).Decode(&syncPayload); err != nil {
		t.Fatalf("decode sync runtime response: %v", err)
	}
	if got := syncPayload["events_appended"]; got != float64(1) {
		t.Fatalf("sync events_appended = %#v, want 1", got)
	}
	if got := syncPayload["entities_projected"]; got != float64(4) {
		t.Fatalf("sync entities_projected = %#v, want 4", got)
	}
	if got := syncPayload["links_projected"]; got != float64(4) {
		t.Fatalf("sync links_projected = %#v, want 4", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	putRuntimeResp, err := client.PutSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{
		Runtime: &cerebrov1.SourceRuntime{
			Id:       "writer-github",
			SourceId: "github",
			TenantId: "writer",
			Config:   map[string]string{"token": "test"},
		},
	}))
	if err != nil {
		t.Fatalf("PutSourceRuntime() error = %v", err)
	}
	if got := putRuntimeResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("PutSourceRuntime token = %q, want [redacted]", got)
	}
	if got := putRuntimeResp.Msg.GetRuntime().GetTenantId(); got != "writer" {
		t.Fatalf("PutSourceRuntime tenant_id = %q, want writer", got)
	}

	getRuntimeResp, err := client.GetSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.GetSourceRuntimeRequest{
		Id: "writer-okta-users",
	}))
	if err != nil {
		t.Fatalf("GetSourceRuntime() error = %v", err)
	}
	if got := getRuntimeResp.Msg.GetRuntime().GetSourceId(); got != "okta" {
		t.Fatalf("GetSourceRuntime source_id = %q, want okta", got)
	}
	if got := getRuntimeResp.Msg.GetRuntime().GetTenantId(); got != "writer" {
		t.Fatalf("GetSourceRuntime tenant_id = %q, want writer", got)
	}

	syncRuntimeResp, err := client.SyncSourceRuntime(context.Background(), connect.NewRequest(&cerebrov1.SyncSourceRuntimeRequest{
		Id:        "writer-okta-users",
		PageLimit: 1,
	}))
	if err != nil {
		t.Fatalf("SyncSourceRuntime() error = %v", err)
	}
	if syncRuntimeResp.Msg.GetEventsAppended() != 1 {
		t.Fatalf("SyncSourceRuntime events_appended = %d, want 1", syncRuntimeResp.Msg.GetEventsAppended())
	}
	if syncRuntimeResp.Msg.GetEntitiesProjected() != 4 {
		t.Fatalf("SyncSourceRuntime entities_projected = %d, want 4", syncRuntimeResp.Msg.GetEntitiesProjected())
	}
	if syncRuntimeResp.Msg.GetLinksProjected() != 4 {
		t.Fatalf("SyncSourceRuntime links_projected = %d, want 4", syncRuntimeResp.Msg.GetLinksProjected())
	}
	if len(appendLog.events) != 2 {
		t.Fatalf("len(appendLog.events) = %d, want 2", len(appendLog.events))
	}
	if len(runtimeStore.entities) == 0 || len(graphStore.entities) == 0 {
		t.Fatalf("projected entities = state:%d graph:%d, want non-zero", len(runtimeStore.entities), len(graphStore.entities))
	}
}

func TestGraphIngestEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-users": {
			Id:       "writer-okta-users",
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "user",
				"token":  "test",
			},
		},
		"writer-okta-bad": {
			Id:       "writer-okta-bad",
			SourceId: "okta",
			TenantId: "writer",
			Config: map[string]string{
				"domain": "writer.okta.com",
				"family": "missing",
				"token":  "test",
			},
		},
	}}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	runReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-users/graph-ingest-runs?page_limit=1&checkpoint_id=graph-okta", nil)
	if err != nil {
		t.Fatalf("new graph ingest request: %v", err)
	}
	runResp, err := server.Client().Do(runReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/graph-ingest-runs error = %v", err)
	}
	defer func() {
		if closeErr := runResp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest response body: %v", closeErr)
		}
	}()
	if runResp.StatusCode != http.StatusOK {
		t.Fatalf("graph ingest status = %d, want %d", runResp.StatusCode, http.StatusOK)
	}
	var runPayload map[string]any
	if err := json.NewDecoder(runResp.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode graph ingest response: %v", err)
	}
	resultPayload, ok := runPayload["result"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest result = %#v, want object", runPayload["result"])
	}
	runRecord, ok := resultPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest run = %#v, want object", resultPayload["run"])
	}
	runID, ok := runRecord["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("graph ingest run id = %#v, want non-empty string", runRecord["id"])
	}
	if got := runRecord["status"]; got != "completed" {
		t.Fatalf("graph ingest status = %#v, want completed", got)
	}
	if got := runRecord["checkpoint_id"]; got != "graph-okta" {
		t.Fatalf("graph ingest checkpoint_id = %#v, want graph-okta", got)
	}
	overrideReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/source-runtimes/writer-okta-users/graph-ingest-runs?page_limit=1&reset_checkpoint=true",
		strings.NewReader(`{"checkpoint_id":"body-checkpoint"}`),
	)
	if err != nil {
		t.Fatalf("new graph ingest override request: %v", err)
	}
	overrideResp, err := server.Client().Do(overrideReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/graph-ingest-runs override error = %v", err)
	}
	defer func() {
		if closeErr := overrideResp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest override response body: %v", closeErr)
		}
	}()
	var overridePayload map[string]any
	if err := json.NewDecoder(overrideResp.Body).Decode(&overridePayload); err != nil {
		t.Fatalf("decode graph ingest override response: %v", err)
	}
	overrideResult, ok := overridePayload["result"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest override result = %#v, want object", overridePayload["result"])
	}
	overrideRun, ok := overrideResult["run"].(map[string]any)
	if !ok {
		t.Fatalf("graph ingest override run = %#v, want object", overrideResult["run"])
	}
	if got := overrideRun["checkpoint_id"]; got != "body-checkpoint" {
		t.Fatalf("graph ingest override checkpoint_id = %#v, want body-checkpoint", got)
	}

	getResp, err := server.Client().Get(server.URL + "/graph/ingest-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /graph/ingest-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close graph ingest get response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode graph ingest get response: %v", err)
	}
	getRun, ok := getPayload["run"].(map[string]any)
	if !ok || getRun["id"] != runID {
		t.Fatalf("graph ingest get run = %#v, want id %q", getPayload["run"], runID)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	_, err = client.RunGraphIngestRuntime(context.Background(), connect.NewRequest(&cerebrov1.RunGraphIngestRuntimeRequest{
		RuntimeId: "writer-okta-bad",
		PageLimit: 1,
	}))
	if err == nil {
		t.Fatal("RunGraphIngestRuntime(bad) error = nil, want non-nil")
	}
	listResp, err := client.ListGraphIngestRuns(context.Background(), connect.NewRequest(&cerebrov1.ListGraphIngestRunsRequest{
		Status: graphstore.IngestRunStatusFailed,
		Limit:  5,
	}))
	if err != nil {
		t.Fatalf("ListGraphIngestRuns(failed) error = %v", err)
	}
	if got := len(listResp.Msg.GetRuns()); got != 1 {
		t.Fatalf("len(ListGraphIngestRuns(failed).Runs) = %d, want 1", got)
	}
	if got := listResp.Msg.GetFailedCount(); got != 1 {
		t.Fatalf("ListGraphIngestRuns failed_count = %d, want 1", got)
	}
	healthResp, err := client.CheckGraphIngestHealth(context.Background(), connect.NewRequest(&cerebrov1.CheckGraphIngestHealthRequest{Limit: 5}))
	if err != nil {
		t.Fatalf("CheckGraphIngestHealth() error = %v", err)
	}
	if got := healthResp.Msg.GetStatus(); got != "degraded" {
		t.Fatalf("CheckGraphIngestHealth status = %q, want degraded", got)
	}
	if got := healthResp.Msg.GetFailedCount(); got != 1 {
		t.Fatalf("CheckGraphIngestHealth failed_count = %d, want 1", got)
	}
}

func TestFindingRuleEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/finding-rules")
	if err != nil {
		t.Fatalf("GET /finding-rules error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /finding-rules response body: %v", closeErr)
		}
	}()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /finding-rules response: %v", err)
	}
	rulesPayload, ok := payload["rules"].([]any)
	if !ok || len(rulesPayload) < 10 {
		t.Fatalf("/finding-rules payload = %#v, want at least 10 rules", payload["rules"])
	}
	ruleIDs := map[string]struct{}{}
	for _, rawRule := range rulesPayload {
		rulePayload, ok := rawRule.(map[string]any)
		if !ok {
			t.Fatalf("/finding-rules rule entry = %#v, want object", rawRule)
		}
		ruleID, ok := rulePayload["id"].(string)
		if !ok {
			t.Fatalf("/finding-rules rule id = %#v, want string", rulePayload["id"])
		}
		ruleIDs[ruleID] = struct{}{}
	}
	for _, ruleID := range []string{"github-dependabot-open-alert", "github-secret-scanning-disabled", "identity-okta-policy-rule-lifecycle-tampering"} {
		if _, ok := ruleIDs[ruleID]; !ok {
			t.Fatalf("/finding-rules missing %q in %#v", ruleID, ruleIDs)
		}
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listResp, err := client.ListFindingRules(context.Background(), connect.NewRequest(&cerebrov1.ListFindingRulesRequest{}))
	if err != nil {
		t.Fatalf("ListFindingRules() error = %v", err)
	}
	if got := len(listResp.Msg.GetRules()); got < 10 {
		t.Fatalf("len(ListFindingRules().Rules) = %d, want at least 10", got)
	}
	connectRuleIDs := map[string]struct{}{}
	for _, rule := range listResp.Msg.GetRules() {
		connectRuleIDs[rule.GetId()] = struct{}{}
	}
	for _, ruleID := range []string{"github-dependabot-open-alert", "github-secret-scanning-disabled", "identity-okta-policy-rule-lifecycle-tampering"} {
		if _, ok := connectRuleIDs[ruleID]; !ok {
			t.Fatalf("ListFindingRules() missing %q in %#v", ruleID, connectRuleIDs)
		}
	}
}

func TestFindingEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	appendLog := &recordingAppendLog{
		replayEvents: []*cerebrov1.EventEnvelope{
			findingTestEvent("okta-audit-1", "user.session.start", "SUCCESS"),
			findingTestEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{"token": "super-secret"},
			},
		},
		claims: map[string]*ports.ClaimRecord{
			"claim-1": {
				ID:            "claim-1",
				RuntimeID:     "writer-okta-audit",
				TenantID:      "writer",
				SubjectURN:    "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				Predicate:     "status",
				ObjectValue:   "updated",
				ClaimType:     "attribute",
				Status:        "asserted",
				SourceEventID: "okta-audit-2",
				ObservedAt:    time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
		},
	}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	evaluateReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-audit/findings/evaluate?event_limit=2&rule_id=identity-okta-policy-rule-lifecycle-tampering", nil)
	if err != nil {
		t.Fatalf("new evaluate findings request: %v", err)
	}
	evaluateResp, err := server.Client().Do(evaluateReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/findings/evaluate error = %v", err)
	}
	defer func() {
		if closeErr := evaluateResp.Body.Close(); closeErr != nil {
			t.Fatalf("close evaluate findings response body: %v", closeErr)
		}
	}()
	var evaluatePayload map[string]any
	if err := json.NewDecoder(evaluateResp.Body).Decode(&evaluatePayload); err != nil {
		t.Fatalf("decode evaluate findings response: %v", err)
	}
	if got := evaluatePayload["events_evaluated"]; got != float64(2) {
		t.Fatalf("evaluate findings events_evaluated = %#v, want 2", got)
	}
	if got := evaluatePayload["findings_upserted"]; got != float64(1) {
		t.Fatalf("evaluate findings findings_upserted = %#v, want 1", got)
	}
	evaluateRuntime, ok := evaluatePayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate runtime payload = %#v, want object", evaluatePayload["runtime"])
	}
	evaluateConfig, ok := evaluateRuntime["config"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate runtime config = %#v, want object", evaluateRuntime["config"])
	}
	if got := evaluateConfig["token"]; got != "[redacted]" {
		t.Fatalf("evaluate runtime config token = %#v, want [redacted]", got)
	}
	findingsPayload, ok := evaluatePayload["findings"].([]any)
	if !ok || len(findingsPayload) != 1 {
		t.Fatalf("evaluate findings payload = %#v, want 1 entry", evaluatePayload["findings"])
	}
	findingPayload, ok := findingsPayload[0].(map[string]any)
	if !ok {
		t.Fatalf("evaluate finding payload = %#v, want object", findingsPayload[0])
	}
	if got := findingPayload["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("evaluate finding rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := findingPayload["summary"]; got != "admin@writer.com performed policy.rule.update on pol-1" {
		t.Fatalf("evaluate finding summary = %#v, want admin summary", got)
	}
	if got := findingPayload["policy_id"]; got != "pol-1" {
		t.Fatalf("evaluate finding policy_id = %#v, want pol-1", got)
	}
	if got := findingPayload["policy_name"]; got != "pol-1" {
		t.Fatalf("evaluate finding policy_name = %#v, want pol-1", got)
	}
	if got := findingPayload["check_id"]; got != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("evaluate finding check_id = %#v, want identity-okta-policy-rule-lifecycle-tampering-30d", got)
	}
	if got := findingPayload["check_name"]; got != "Okta Policy Rule Lifecycle Tampering (30 days)" {
		t.Fatalf("evaluate finding check_name = %#v, want check name", got)
	}
	controlRefs, ok := findingPayload["control_refs"].([]any)
	if !ok || len(controlRefs) != 2 {
		t.Fatalf("evaluate finding control_refs = %#v, want 2 entries", findingPayload["control_refs"])
	}
	runPayload, ok := evaluatePayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("evaluate run payload = %#v, want object", evaluatePayload["run"])
	}
	runID, ok := runPayload["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("evaluate run id = %#v, want non-empty string", runPayload["id"])
	}
	if got := runPayload["status"]; got != "completed" {
		t.Fatalf("evaluate run status = %#v, want completed", got)
	}
	if got := runPayload["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("evaluate run rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	evidencePayload, ok := evaluatePayload["evidence"].([]any)
	if !ok || len(evidencePayload) != 1 {
		t.Fatalf("evaluate evidence payload = %#v, want 1 entry", evaluatePayload["evidence"])
	}
	evidenceEntry, ok := evidencePayload[0].(map[string]any)
	if !ok {
		t.Fatalf("evaluate evidence entry = %#v, want object", evidencePayload[0])
	}
	evidenceID, ok := evidenceEntry["id"].(string)
	if !ok || evidenceID == "" {
		t.Fatalf("evaluate evidence id = %#v, want non-empty string", evidenceEntry["id"])
	}
	if got := evidenceEntry["finding_id"]; got != findingPayload["id"] {
		t.Fatalf("evaluate evidence finding_id = %#v, want finding id %#v", got, findingPayload["id"])
	}
	claimIDs, ok := evidenceEntry["claim_ids"].([]any)
	if !ok || len(claimIDs) != 1 || claimIDs[0] != "claim-1" {
		t.Fatalf("evaluate evidence claim_ids = %#v, want [claim-1]", evidenceEntry["claim_ids"])
	}
	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-audit/findings?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=open&event_id=okta-audit-2&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/findings error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list findings response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list findings response: %v", err)
	}
	listedFindings, ok := listPayload["findings"].([]any)
	if !ok || len(listedFindings) != 1 {
		t.Fatalf("list findings payload = %#v, want 1 entry", listPayload["findings"])
	}
	listedFinding, ok := listedFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("list findings entry = %#v, want object", listedFindings[0])
	}
	if got := listedFinding["rule_id"]; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("list finding rule_id = %#v, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	runListResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-audit/finding-evaluation-runs?rule_id=identity-okta-policy-rule-lifecycle-tampering&status=completed&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/finding-evaluation-runs error = %v", err)
	}
	defer func() {
		if closeErr := runListResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list evaluation runs response body: %v", closeErr)
		}
	}()
	var runListPayload map[string]any
	if err := json.NewDecoder(runListResp.Body).Decode(&runListPayload); err != nil {
		t.Fatalf("decode list evaluation runs response: %v", err)
	}
	runEntries, ok := runListPayload["runs"].([]any)
	if !ok || len(runEntries) != 1 {
		t.Fatalf("list evaluation runs payload = %#v, want 1 entry", runListPayload["runs"])
	}
	runEntry, ok := runEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("list evaluation run entry = %#v, want object", runEntries[0])
	}
	if got := runEntry["id"]; got != runID {
		t.Fatalf("list evaluation run id = %#v, want %q", got, runID)
	}
	evidenceListResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-okta-audit/finding-evidence?finding_id=" + findingPayload["id"].(string) + "&run_id=" + runID + "&claim_id=claim-1&event_id=okta-audit-2&graph_root_urn=urn:cerebro:writer:okta_resource:policyrule:pol-1&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/finding-evidence error = %v", err)
	}
	defer func() {
		if closeErr := evidenceListResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list finding evidence response body: %v", closeErr)
		}
	}()
	var evidenceListPayload map[string]any
	if err := json.NewDecoder(evidenceListResp.Body).Decode(&evidenceListPayload); err != nil {
		t.Fatalf("decode list finding evidence response: %v", err)
	}
	evidenceEntries, ok := evidenceListPayload["evidence"].([]any)
	if !ok || len(evidenceEntries) != 1 {
		t.Fatalf("list finding evidence payload = %#v, want 1 entry", evidenceListPayload["evidence"])
	}
	listedEvidence, ok := evidenceEntries[0].(map[string]any)
	if !ok {
		t.Fatalf("list finding evidence entry = %#v, want object", evidenceEntries[0])
	}
	if got := listedEvidence["id"]; got != evidenceID {
		t.Fatalf("list finding evidence id = %#v, want %q", got, evidenceID)
	}
	getEvidenceResp, err := server.Client().Get(server.URL + "/finding-evidence/" + evidenceID)
	if err != nil {
		t.Fatalf("GET /finding-evidence/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getEvidenceResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get finding evidence response body: %v", closeErr)
		}
	}()
	var getEvidencePayload map[string]any
	if err := json.NewDecoder(getEvidenceResp.Body).Decode(&getEvidencePayload); err != nil {
		t.Fatalf("decode get finding evidence response: %v", err)
	}
	getEvidenceBody, ok := getEvidencePayload["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("get finding evidence payload = %#v, want object", getEvidencePayload["evidence"])
	}
	if got := getEvidenceBody["id"]; got != evidenceID {
		t.Fatalf("get finding evidence id = %#v, want %q", got, evidenceID)
	}
	getRunResp, err := server.Client().Get(server.URL + "/finding-evaluation-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /finding-evaluation-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getRunResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get evaluation run response body: %v", closeErr)
		}
	}()
	var getRunPayload map[string]any
	if err := json.NewDecoder(getRunResp.Body).Decode(&getRunPayload); err != nil {
		t.Fatalf("decode get evaluation run response: %v", err)
	}
	getRunBody, ok := getRunPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("get evaluation run payload = %#v, want object", getRunPayload["run"])
	}
	if got := getRunBody["id"]; got != runID {
		t.Fatalf("get evaluation run id = %#v, want %q", got, runID)
	}
	missingRuleResp, err := server.Client().Post(server.URL+"/source-runtimes/writer-okta-audit/findings/evaluate?rule_id=does-not-exist", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/findings/evaluate unknown rule error = %v", err)
	}
	defer func() {
		if closeErr := missingRuleResp.Body.Close(); closeErr != nil {
			t.Fatalf("close unknown rule response body: %v", closeErr)
		}
	}()
	if got := missingRuleResp.StatusCode; got != http.StatusNotFound {
		t.Fatalf("unknown rule status = %d, want %d", got, http.StatusNotFound)
	}
	batchEvaluateReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-audit/finding-rules/evaluate?event_limit=2", nil)
	if err != nil {
		t.Fatalf("new batch evaluate request: %v", err)
	}
	batchEvaluateResp, err := server.Client().Do(batchEvaluateReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/finding-rules/evaluate error = %v", err)
	}
	defer func() {
		if closeErr := batchEvaluateResp.Body.Close(); closeErr != nil {
			t.Fatalf("close batch evaluate response body: %v", closeErr)
		}
	}()
	var batchEvaluatePayload map[string]any
	if err := json.NewDecoder(batchEvaluateResp.Body).Decode(&batchEvaluatePayload); err != nil {
		t.Fatalf("decode batch evaluate response: %v", err)
	}
	if got := batchEvaluatePayload["events_evaluated"]; got != float64(2) {
		t.Fatalf("batch evaluate events_evaluated = %#v, want 2", got)
	}
	batchRuntime, ok := batchEvaluatePayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("batch runtime payload = %#v, want object", batchEvaluatePayload["runtime"])
	}
	batchConfig, ok := batchRuntime["config"].(map[string]any)
	if !ok {
		t.Fatalf("batch runtime config = %#v, want object", batchRuntime["config"])
	}
	if got := batchConfig["token"]; got != "[redacted]" {
		t.Fatalf("batch runtime config token = %#v, want [redacted]", got)
	}
	batchEvaluations, ok := batchEvaluatePayload["evaluations"].([]any)
	if !ok || len(batchEvaluations) == 0 {
		t.Fatalf("batch evaluate payload = %#v, want evaluations", batchEvaluatePayload["evaluations"])
	}
	var batchEvaluation map[string]any
	for _, candidate := range batchEvaluations {
		entry, ok := candidate.(map[string]any)
		if !ok {
			t.Fatalf("batch evaluation entry = %#v, want object", candidate)
		}
		batchRule, ok := entry["rule"].(map[string]any)
		if ok && batchRule["id"] == "identity-okta-policy-rule-lifecycle-tampering" {
			batchEvaluation = entry
			break
		}
	}
	if batchEvaluation == nil {
		t.Fatalf("batch evaluations = %#v, want lifecycle tampering rule", batchEvaluations)
	}
	batchEvidence, ok := batchEvaluation["evidence"].([]any)
	if !ok || len(batchEvidence) != 1 {
		t.Fatalf("batch evaluation evidence = %#v, want 1 entry", batchEvaluation["evidence"])
	}

	batchBody, err := protojson.Marshal(&cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{
		RuleIds: []string{"identity-okta-policy-rule-lifecycle-tampering"},
	})
	if err != nil {
		t.Fatalf("marshal batch evaluate body: %v", err)
	}
	batchBodyReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-okta-audit/finding-rules/evaluate?event_limit=2", bytes.NewReader(batchBody))
	if err != nil {
		t.Fatalf("new body batch evaluate request: %v", err)
	}
	batchBodyReq.Header.Set("Content-Type", "application/json")
	batchBodyResp, err := server.Client().Do(batchBodyReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/finding-rules/evaluate body error = %v", err)
	}
	defer func() {
		if closeErr := batchBodyResp.Body.Close(); closeErr != nil {
			t.Fatalf("close body batch evaluate response body: %v", closeErr)
		}
	}()
	var batchBodyPayload map[string]any
	if err := json.NewDecoder(batchBodyResp.Body).Decode(&batchBodyPayload); err != nil {
		t.Fatalf("decode body batch evaluate response: %v", err)
	}
	batchBodyEvaluations, ok := batchBodyPayload["evaluations"].([]any)
	if !ok || len(batchBodyEvaluations) != 1 {
		t.Fatalf("body batch evaluations = %#v, want exactly one selected rule", batchBodyPayload["evaluations"])
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	evaluateFindingsResp, err := client.EvaluateSourceRuntimeFindings(context.Background(), connect.NewRequest(&cerebrov1.EvaluateSourceRuntimeFindingsRequest{
		Id:         "writer-okta-audit",
		RuleId:     "identity-okta-policy-rule-lifecycle-tampering",
		EventLimit: 5,
	}))
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeFindings() error = %v", err)
	}
	if got := evaluateFindingsResp.Msg.GetEventsEvaluated(); got != 2 {
		t.Fatalf("EvaluateSourceRuntimeFindings events_evaluated = %d, want 2", got)
	}
	if got := evaluateFindingsResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("EvaluateSourceRuntimeFindings runtime token = %q, want [redacted]", got)
	}
	if got := evaluateFindingsResp.Msg.GetFindingsUpserted(); got != 1 {
		t.Fatalf("EvaluateSourceRuntimeFindings findings_upserted = %d, want 1", got)
	}
	if len(evaluateFindingsResp.Msg.GetFindings()) != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindings.Findings) = %d, want 1", len(evaluateFindingsResp.Msg.GetFindings()))
	}
	if got := evaluateFindingsResp.Msg.GetRule().GetId(); got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("EvaluateSourceRuntimeFindings rule id = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := evaluateFindingsResp.Msg.GetRun().GetId(); got == "" {
		t.Fatal("EvaluateSourceRuntimeFindings run id = empty, want non-empty")
	}
	if got := len(evaluateFindingsResp.Msg.GetEvidence()); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindings.Evidence) = %d, want 1", got)
	}
	if got := evaluateFindingsResp.Msg.GetEvidence()[0].GetClaimIds(); len(got) != 1 || got[0] != "claim-1" {
		t.Fatalf("EvaluateSourceRuntimeFindings evidence claim ids = %#v, want [claim-1]", got)
	}
	listFindingsResp, err := client.ListFindings(context.Background(), connect.NewRequest(&cerebrov1.ListFindingsRequest{
		RuntimeId:   "writer-okta-audit",
		RuleId:      "identity-okta-policy-rule-lifecycle-tampering",
		Severity:    "HIGH",
		Status:      cerebrov1.FindingStatus_FINDING_STATUS_OPEN,
		PolicyId:    "pol-1",
		ResourceUrn: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		EventId:     "okta-audit-2",
		Limit:       1,
	}))
	if err != nil {
		t.Fatalf("ListFindings() error = %v", err)
	}
	if got := len(listFindingsResp.Msg.GetFindings()); got != 1 {
		t.Fatalf("len(ListFindings().Findings) = %d, want 1", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetId(); got == "" {
		t.Fatal("ListFindings().Findings[0].ID = empty, want non-empty")
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetPolicyId(); got != "pol-1" {
		t.Fatalf("ListFindings().Findings[0].PolicyId = %q, want pol-1", got)
	}
	if got := listFindingsResp.Msg.GetFindings()[0].GetCheckId(); got != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("ListFindings().Findings[0].CheckId = %q, want identity-okta-policy-rule-lifecycle-tampering-30d", got)
	}
	if got := len(listFindingsResp.Msg.GetFindings()[0].GetControlRefs()); got != 2 {
		t.Fatalf("len(ListFindings().Findings[0].ControlRefs) = %d, want 2", got)
	}
	if got := runtimeStore.findingListRequest.TenantID; got != "writer" {
		t.Fatalf("runtimeStore.findingListRequest.TenantID = %q, want writer", got)
	}
	if got := runtimeStore.findingListRequest.RuleID; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("runtimeStore.findingListRequest.RuleID = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runtimeStore.findingListRequest.ResourceURN; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("runtimeStore.findingListRequest.ResourceURN = %q, want policy rule urn", got)
	}
	if got := runtimeStore.findingListRequest.EventID; got != "okta-audit-2" {
		t.Fatalf("runtimeStore.findingListRequest.EventID = %q, want okta-audit-2", got)
	}
	if got := runtimeStore.findingListRequest.PolicyID; got != "pol-1" {
		t.Fatalf("runtimeStore.findingListRequest.PolicyID = %q, want pol-1", got)
	}
	listRunsResp, err := client.ListFindingEvaluationRuns(context.Background(), connect.NewRequest(&cerebrov1.ListFindingEvaluationRunsRequest{
		RuntimeId: "writer-okta-audit",
		RuleId:    "identity-okta-policy-rule-lifecycle-tampering",
		Status:    "completed",
		Limit:     1,
	}))
	if err != nil {
		t.Fatalf("ListFindingEvaluationRuns() error = %v", err)
	}
	if got := len(listRunsResp.Msg.GetRuns()); got != 1 {
		t.Fatalf("len(ListFindingEvaluationRuns().Runs) = %d, want 1", got)
	}
	evaluateFindingRulesResp, err := client.EvaluateSourceRuntimeFindingRules(context.Background(), connect.NewRequest(&cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{
		Id:         "writer-okta-audit",
		EventLimit: 2,
	}))
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeFindingRules() error = %v", err)
	}
	if got := evaluateFindingRulesResp.Msg.GetEventsEvaluated(); got != 2 {
		t.Fatalf("EvaluateSourceRuntimeFindingRules events_evaluated = %d, want 2", got)
	}
	if got := evaluateFindingRulesResp.Msg.GetRuntime().GetConfig()["token"]; got != "[redacted]" {
		t.Fatalf("EvaluateSourceRuntimeFindingRules runtime token = %q, want [redacted]", got)
	}
	var lifecycleEvaluation *cerebrov1.FindingRuleEvaluation
	for _, evaluation := range evaluateFindingRulesResp.Msg.GetEvaluations() {
		if evaluation.GetRule().GetId() == "identity-okta-policy-rule-lifecycle-tampering" {
			lifecycleEvaluation = evaluation
			break
		}
	}
	if lifecycleEvaluation == nil {
		t.Fatalf("EvaluateSourceRuntimeFindingRules evaluations = %v, want lifecycle tampering rule", evaluateFindingRulesResp.Msg.GetEvaluations())
	}
	if got := len(lifecycleEvaluation.GetEvidence()); got != 1 {
		t.Fatalf("len(EvaluateSourceRuntimeFindingRules().Evaluations[0].Evidence) = %d, want 1", got)
	}
	listEvidenceResp, err := client.ListFindingEvidence(context.Background(), connect.NewRequest(&cerebrov1.ListFindingEvidenceRequest{
		RuntimeId:    "writer-okta-audit",
		FindingId:    evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		RunId:        evaluateFindingsResp.Msg.GetRun().GetId(),
		RuleId:       "identity-okta-policy-rule-lifecycle-tampering",
		ClaimId:      "claim-1",
		EventId:      "okta-audit-2",
		GraphRootUrn: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		Limit:        1,
	}))
	if err != nil {
		t.Fatalf("ListFindingEvidence() error = %v", err)
	}
	if got := len(listEvidenceResp.Msg.GetEvidence()); got != 1 {
		t.Fatalf("len(ListFindingEvidence().Evidence) = %d, want 1", got)
	}
	getFindingEvidenceResp, err := client.GetFindingEvidence(context.Background(), connect.NewRequest(&cerebrov1.GetFindingEvidenceRequest{
		Id: listEvidenceResp.Msg.GetEvidence()[0].GetId(),
	}))
	if err != nil {
		t.Fatalf("GetFindingEvidence() error = %v", err)
	}
	if got := getFindingEvidenceResp.Msg.GetEvidence().GetId(); got != listEvidenceResp.Msg.GetEvidence()[0].GetId() {
		t.Fatalf("GetFindingEvidence().Evidence.Id = %q, want %q", got, listEvidenceResp.Msg.GetEvidence()[0].GetId())
	}
	getEvaluationRunResp, err := client.GetFindingEvaluationRun(context.Background(), connect.NewRequest(&cerebrov1.GetFindingEvaluationRunRequest{
		Id: evaluateFindingsResp.Msg.GetRun().GetId(),
	}))
	if err != nil {
		t.Fatalf("GetFindingEvaluationRun() error = %v", err)
	}
	if got := getEvaluationRunResp.Msg.GetRun().GetId(); got != evaluateFindingsResp.Msg.GetRun().GetId() {
		t.Fatalf("GetFindingEvaluationRun().Run.Id = %q, want %q", got, evaluateFindingsResp.Msg.GetRun().GetId())
	}
	assignBody, err := protojson.Marshal(&cerebrov1.AssignFindingRequest{Assignee: "secops"})
	if err != nil {
		t.Fatalf("marshal assign finding body: %v", err)
	}
	assignReq, err := http.NewRequest(http.MethodPut, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/assign", bytes.NewReader(assignBody))
	if err != nil {
		t.Fatalf("new assign finding request: %v", err)
	}
	assignReq.Header.Set("Content-Type", "application/json")
	assignResp, err := server.Client().Do(assignReq)
	if err != nil {
		t.Fatalf("PUT /findings/{id}/assign error = %v", err)
	}
	defer func() {
		if closeErr := assignResp.Body.Close(); closeErr != nil {
			t.Fatalf("close assign finding response body: %v", closeErr)
		}
	}()
	var assignPayload map[string]any
	if err := json.NewDecoder(assignResp.Body).Decode(&assignPayload); err != nil {
		t.Fatalf("decode assign finding response: %v", err)
	}
	assignFinding, ok := assignPayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("assign finding payload = %#v, want object", assignPayload["finding"])
	}
	if got := assignFinding["assignee"]; got != "secops" {
		t.Fatalf("assign finding assignee = %#v, want secops", got)
	}
	httpDueAt := "2026-05-01T12:00:00Z"
	dueBody, err := protojson.Marshal(&cerebrov1.SetFindingDueDateRequest{DueAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatalf("marshal due date body: %v", err)
	}
	dueReq, err := http.NewRequest(http.MethodPut, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/due", bytes.NewReader(dueBody))
	if err != nil {
		t.Fatalf("new due date request: %v", err)
	}
	dueReq.Header.Set("Content-Type", "application/json")
	dueResp, err := server.Client().Do(dueReq)
	if err != nil {
		t.Fatalf("PUT /findings/{id}/due error = %v", err)
	}
	defer func() {
		if closeErr := dueResp.Body.Close(); closeErr != nil {
			t.Fatalf("close due date response body: %v", closeErr)
		}
	}()
	var duePayload map[string]any
	if err := json.NewDecoder(dueResp.Body).Decode(&duePayload); err != nil {
		t.Fatalf("decode due date response: %v", err)
	}
	dueFinding, ok := duePayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("due finding payload = %#v, want object", duePayload["finding"])
	}
	if got := dueFinding["due_at"]; got != httpDueAt {
		t.Fatalf("due finding due_at = %#v, want %q", got, httpDueAt)
	}
	noteBody, err := protojson.Marshal(&cerebrov1.AddFindingNoteRequest{Note: "Escalate to identity engineering."})
	if err != nil {
		t.Fatalf("marshal add finding note body: %v", err)
	}
	noteReq, err := http.NewRequest(http.MethodPost, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/notes", bytes.NewReader(noteBody))
	if err != nil {
		t.Fatalf("new add note request: %v", err)
	}
	noteReq.Header.Set("Content-Type", "application/json")
	noteResp, err := server.Client().Do(noteReq)
	if err != nil {
		t.Fatalf("POST /findings/{id}/notes error = %v", err)
	}
	defer func() {
		if closeErr := noteResp.Body.Close(); closeErr != nil {
			t.Fatalf("close note response body: %v", closeErr)
		}
	}()
	var notePayload map[string]any
	if err := json.NewDecoder(noteResp.Body).Decode(&notePayload); err != nil {
		t.Fatalf("decode note response: %v", err)
	}
	noteFinding, ok := notePayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("note finding payload = %#v, want object", notePayload["finding"])
	}
	noteEntries, ok := noteFinding["notes"].([]any)
	if !ok || len(noteEntries) != 1 {
		t.Fatalf("note finding notes = %#v, want 1 entry", noteFinding["notes"])
	}
	addNoteResp, err := client.AddFindingNote(context.Background(), connect.NewRequest(&cerebrov1.AddFindingNoteRequest{
		Id:   evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Note: "Create follow-up review task.",
	}))
	if err != nil {
		t.Fatalf("AddFindingNote() error = %v", err)
	}
	if got := len(addNoteResp.Msg.GetFinding().GetNotes()); got != 2 {
		t.Fatalf("len(AddFindingNote().Finding.Notes) = %d, want 2", got)
	}
	ticketBody, err := protojson.Marshal(&cerebrov1.LinkFindingTicketRequest{
		Url:        "https://jira.writer.com/browse/ENG-123",
		Name:       "ENG-123",
		ExternalId: "ENG-123",
	})
	if err != nil {
		t.Fatalf("marshal finding ticket body: %v", err)
	}
	ticketReq, err := http.NewRequest(http.MethodPost, server.URL+"/findings/"+evaluateFindingsResp.Msg.GetFindings()[0].GetId()+"/tickets", bytes.NewReader(ticketBody))
	if err != nil {
		t.Fatalf("new finding ticket request: %v", err)
	}
	ticketReq.Header.Set("Content-Type", "application/json")
	ticketResp, err := server.Client().Do(ticketReq)
	if err != nil {
		t.Fatalf("POST /findings/{id}/tickets error = %v", err)
	}
	defer func() {
		if closeErr := ticketResp.Body.Close(); closeErr != nil {
			t.Fatalf("close ticket response body: %v", closeErr)
		}
	}()
	var ticketPayload map[string]any
	if err := json.NewDecoder(ticketResp.Body).Decode(&ticketPayload); err != nil {
		t.Fatalf("decode ticket response: %v", err)
	}
	ticketFinding, ok := ticketPayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("ticket finding payload = %#v, want object", ticketPayload["finding"])
	}
	ticketEntries, ok := ticketFinding["tickets"].([]any)
	if !ok || len(ticketEntries) != 1 {
		t.Fatalf("ticket finding tickets = %#v, want 1 entry", ticketFinding["tickets"])
	}
	linkTicketResp, err := client.LinkFindingTicket(context.Background(), connect.NewRequest(&cerebrov1.LinkFindingTicketRequest{
		Id:         evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Url:        "https://linear.app/writer/issue/SEC-42",
		Name:       "SEC-42",
		ExternalId: "SEC-42",
	}))
	if err != nil {
		t.Fatalf("LinkFindingTicket() error = %v", err)
	}
	if got := len(linkTicketResp.Msg.GetFinding().GetTickets()); got != 2 {
		t.Fatalf("len(LinkFindingTicket().Finding.Tickets) = %d, want 2", got)
	}
	connectDueAt := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	setDueDateResp, err := client.SetFindingDueDate(context.Background(), connect.NewRequest(&cerebrov1.SetFindingDueDateRequest{
		Id:    evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		DueAt: timestamppb.New(connectDueAt),
	}))
	if err != nil {
		t.Fatalf("SetFindingDueDate() error = %v", err)
	}
	if got := setDueDateResp.Msg.GetFinding().GetDueAt().AsTime(); !got.Equal(connectDueAt) {
		t.Fatalf("SetFindingDueDate().Finding.DueAt = %v, want %v", got, connectDueAt)
	}
	resolveFindingResp, err := client.ResolveFinding(context.Background(), connect.NewRequest(&cerebrov1.ResolveFindingRequest{
		Id:     evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Reason: "verified remediation",
	}))
	if err != nil {
		t.Fatalf("ResolveFinding() error = %v", err)
	}
	if got := resolveFindingResp.Msg.GetFinding().GetStatus(); got != cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED {
		t.Fatalf("ResolveFinding().Finding.Status = %v, want FINDING_STATUS_RESOLVED", got)
	}
	if got := resolveFindingResp.Msg.GetFinding().GetStatusReason(); got != "verified remediation" {
		t.Fatalf("ResolveFinding().Finding.StatusReason = %q, want verified remediation", got)
	}
	getFindingResp, err := server.Client().Get(server.URL + "/findings/" + evaluateFindingsResp.Msg.GetFindings()[0].GetId())
	if err != nil {
		t.Fatalf("GET /findings/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getFindingResp.Body.Close(); closeErr != nil {
			t.Fatalf("close get finding response body: %v", closeErr)
		}
	}()
	var getFindingPayload map[string]any
	if err := json.NewDecoder(getFindingResp.Body).Decode(&getFindingPayload); err != nil {
		t.Fatalf("decode get finding response: %v", err)
	}
	getFindingBody, ok := getFindingPayload["finding"].(map[string]any)
	if !ok {
		t.Fatalf("get finding payload = %#v, want object", getFindingPayload["finding"])
	}
	if got := getFindingBody["status"]; got != "FINDING_STATUS_RESOLVED" {
		t.Fatalf("get finding status = %#v, want FINDING_STATUS_RESOLVED", got)
	}
	if got := getFindingBody["assignee"]; got != "secops" {
		t.Fatalf("get finding assignee = %#v, want secops", got)
	}
	if got := getFindingBody["due_at"]; got != "2026-05-02T12:00:00Z" {
		t.Fatalf("get finding due_at = %#v, want 2026-05-02T12:00:00Z", got)
	}
	getFindingNotes, ok := getFindingBody["notes"].([]any)
	if !ok || len(getFindingNotes) != 2 {
		t.Fatalf("get finding notes = %#v, want 2 entries", getFindingBody["notes"])
	}
	getFindingTickets, ok := getFindingBody["tickets"].([]any)
	if !ok || len(getFindingTickets) != 2 {
		t.Fatalf("get finding tickets = %#v, want 2 entries", getFindingBody["tickets"])
	}
	suppressFindingResp, err := client.SuppressFinding(context.Background(), connect.NewRequest(&cerebrov1.SuppressFindingRequest{
		Id:     evaluateFindingsResp.Msg.GetFindings()[0].GetId(),
		Reason: "accepted risk",
	}))
	if err != nil {
		t.Fatalf("SuppressFinding() error = %v", err)
	}
	if got := suppressFindingResp.Msg.GetFinding().GetStatus(); got != cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED {
		t.Fatalf("SuppressFinding().Finding.Status = %v, want FINDING_STATUS_SUPPRESSED", got)
	}
	if got := runtimeStore.findingEvaluationRunListRequest.RuleID; got != "identity-okta-policy-rule-lifecycle-tampering" {
		t.Fatalf("runtimeStore.findingEvaluationRunListRequest.RuleID = %q, want identity-okta-policy-rule-lifecycle-tampering", got)
	}
	if got := runtimeStore.findingEvaluationRunListRequest.Status; got != "completed" {
		t.Fatalf("runtimeStore.findingEvaluationRunListRequest.Status = %q, want completed", got)
	}
	if got := runtimeStore.findingEvidenceListRequest.ClaimID; got != "claim-1" {
		t.Fatalf("runtimeStore.findingEvidenceListRequest.ClaimID = %q, want claim-1", got)
	}
	if got := runtimeStore.findingEvidenceListRequest.EventID; got != "okta-audit-2" {
		t.Fatalf("runtimeStore.findingEvidenceListRequest.EventID = %q, want okta-audit-2", got)
	}
	if len(runtimeStore.findingEvaluationRuns) < 4 {
		t.Fatalf("len(runtimeStore.findingEvaluationRuns) = %d, want at least 4", len(runtimeStore.findingEvaluationRuns))
	}
	if len(runtimeStore.findings) < 1 {
		t.Fatalf("len(runtimeStore.findings) = %d, want at least 1", len(runtimeStore.findings))
	}
	if len(runtimeStore.findingEvidence) < 4 {
		t.Fatalf("len(runtimeStore.findingEvidence) = %d, want at least 4", len(runtimeStore.findingEvidence))
	}
	if got := len(graphStore.entities); got < 9 {
		t.Fatalf("len(graphStore.entities) = %d, want at least 9", got)
	}
	if got := len(graphStore.links); got < 20 {
		t.Fatalf("len(graphStore.links) = %d, want at least 20", got)
	}
	decisionCount := 0
	outcomeCount := 0
	for _, entity := range graphStore.entities {
		if entity == nil {
			continue
		}
		switch entity.EntityType {
		case "decision":
			decisionCount++
		case "outcome":
			outcomeCount++
		}
	}
	if decisionCount != 2 {
		t.Fatalf("decision entity count = %d, want 2", decisionCount)
	}
	if outcomeCount != 2 {
		t.Fatalf("outcome entity count = %d, want 2", outcomeCount)
	}
}

func TestPlatformKnowledgeDecisionAndOutcomeEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	graphStore := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			targetURN: {
				URN:        targetURN,
				TenantID:   "writer",
				SourceID:   "okta",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
		},
	}
	appendLog := &recordingAppendLog{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		GraphStore: graphStore,
		AppendLog:  appendLog,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)

	decisionBody, err := protojson.Marshal(&cerebrov1.WriteDecisionRequest{
		DecisionType: "finding-triage",
		Status:       "approved",
		MadeBy:       "secops",
		Rationale:    "accepted risk pending remediation",
		TargetIds:    []string{targetURN},
		EvidenceIds:  []string{"finding-evidence-1"},
	})
	if err != nil {
		t.Fatalf("marshal write decision body: %v", err)
	}
	decisionReq, err := http.NewRequest(http.MethodPost, server.URL+"/platform/knowledge/decisions", bytes.NewReader(decisionBody))
	if err != nil {
		t.Fatalf("new write decision request: %v", err)
	}
	decisionReq.Header.Set("Content-Type", "application/json")
	decisionResp, err := server.Client().Do(decisionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/decisions error = %v", err)
	}
	defer func() {
		if closeErr := decisionResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write decision response body: %v", closeErr)
		}
	}()
	if decisionResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /platform/knowledge/decisions status = %d, want %d", decisionResp.StatusCode, http.StatusCreated)
	}
	var decisionPayload map[string]any
	if err := json.NewDecoder(decisionResp.Body).Decode(&decisionPayload); err != nil {
		t.Fatalf("decode write decision response: %v", err)
	}
	decisionID, ok := decisionPayload["decision_id"].(string)
	if !ok || decisionID == "" {
		t.Fatalf("decision_id = %#v, want non-empty string", decisionPayload["decision_id"])
	}
	if got := decisionPayload["target_count"]; got != float64(1) {
		t.Fatalf("decision target_count = %#v, want 1", got)
	}
	if _, ok := graphStore.entities["urn:cerebro:writer:evidence:finding-evidence-1"]; !ok {
		t.Fatal("decision evidence entity missing")
	}
	if _, ok := graphStore.links[decisionID+"|targets|"+targetURN]; !ok {
		t.Fatal("decision target link missing")
	}
	actionBody, err := protojson.Marshal(&cerebrov1.WriteActionRequest{
		RecommendationId: "recommendation-1",
		InsightType:      "remediation",
		Title:            "Open remediation ticket",
		Summary:          "Track the fix in the owning team's backlog",
		DecisionId:       decisionID,
		TargetIds:        []string{targetURN},
		SourceSystem:     "platform.recommendations",
		SourceEventId:    "recommendation-evt-1",
		AutoGenerated:    true,
	})
	if err != nil {
		t.Fatalf("marshal write action body: %v", err)
	}
	actionReq, err := http.NewRequest(http.MethodPost, server.URL+"/platform/knowledge/actions", bytes.NewReader(actionBody))
	if err != nil {
		t.Fatalf("new write action request: %v", err)
	}
	actionReq.Header.Set("Content-Type", "application/json")
	actionResp, err := server.Client().Do(actionReq)
	if err != nil {
		t.Fatalf("POST /platform/knowledge/actions error = %v", err)
	}
	defer func() {
		if closeErr := actionResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write action response body: %v", closeErr)
		}
	}()
	if actionResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /platform/knowledge/actions status = %d, want %d", actionResp.StatusCode, http.StatusCreated)
	}
	var actionPayload map[string]any
	if err := json.NewDecoder(actionResp.Body).Decode(&actionPayload); err != nil {
		t.Fatalf("decode write action response: %v", err)
	}
	actionID, ok := actionPayload["action_id"].(string)
	if !ok || actionID == "" {
		t.Fatalf("action_id = %#v, want non-empty string", actionPayload["action_id"])
	}
	if got := actionPayload["decision_id"]; got != decisionID {
		t.Fatalf("action decision_id = %#v, want %q", got, decisionID)
	}
	if got := actionPayload["target_count"]; got != float64(1) {
		t.Fatalf("action target_count = %#v, want 1", got)
	}
	if _, ok := graphStore.entities[actionID]; !ok {
		t.Fatalf("action entity %q missing", actionID)
	}
	if _, ok := graphStore.links[actionID+"|targets|"+targetURN]; !ok {
		t.Fatal("action target link missing")
	}
	if _, ok := graphStore.links[decisionID+"|executed_by|"+actionID]; !ok {
		t.Fatal("decision action link missing")
	}

	outcomeResp, err := client.WriteOutcome(context.Background(), connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
		DecisionId:  decisionID,
		OutcomeType: "finding-resolution",
		Verdict:     "resolved",
		TargetIds:   []string{targetURN},
	}))
	if err != nil {
		t.Fatalf("WriteOutcome() error = %v", err)
	}
	if got := outcomeResp.Msg.GetDecisionId(); got != decisionID {
		t.Fatalf("WriteOutcome().DecisionId = %q, want %q", got, decisionID)
	}
	if got := outcomeResp.Msg.GetTargetCount(); got != 1 {
		t.Fatalf("WriteOutcome().TargetCount = %d, want 1", got)
	}
	outcomeID := outcomeResp.Msg.GetOutcomeId()
	if outcomeID == "" {
		t.Fatal("WriteOutcome().OutcomeId = empty, want non-empty")
	}
	if _, ok := graphStore.entities[outcomeID]; !ok {
		t.Fatalf("outcome entity %q missing", outcomeID)
	}
	if _, ok := graphStore.links[outcomeID+"|evaluates|"+decisionID]; !ok {
		t.Fatal("outcome evaluates link missing")
	}
	if _, ok := graphStore.links[outcomeID+"|targets|"+targetURN]; !ok {
		t.Fatal("outcome target link missing")
	}
	if len(appendLog.events) != 3 {
		t.Fatalf("len(appendLog.events) = %d, want 3", len(appendLog.events))
	}
}

func TestWorkflowReplayEndpoint(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	decisionID := "urn:cerebro:writer:decision:decision-1"
	decisionEvent, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:     "writer",
		DecisionID:   decisionID,
		DecisionType: "finding-triage",
		Status:       "approved",
		TargetIDs:    []string{targetURN},
		SourceSystem: "findings",
		ObservedAt:   "2026-04-27T12:00:00Z",
		ValidFrom:    "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	appendLog := &recordingAppendLog{replayEvents: []*cerebrov1.EventEnvelope{decisionEvent}}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body, err := protojson.Marshal(&cerebrov1.ReplayWorkflowEventsRequest{
		TenantId: "writer",
		AttributeEquals: map[string]string{
			"workflow_kind": "knowledge_decision",
		},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("marshal ReplayWorkflowEventsRequest: %v", err)
	}
	resp, err := server.Client().Post(server.URL+"/platform/workflow/replay", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /platform/workflow/replay error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /platform/workflow/replay response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /platform/workflow/replay status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var replayPayload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&replayPayload); err != nil {
		t.Fatalf("decode ReplayWorkflowEventsResponse: %v", err)
	}
	if replayPayload["events_read"] != float64(1) || replayPayload["events_projected"] != float64(1) {
		t.Fatalf("replay counts = read:%v projected:%v, want 1/1", replayPayload["events_read"], replayPayload["events_projected"])
	}
	if _, ok := graphStore.entities[decisionID]; !ok {
		t.Fatalf("decision entity %q missing after replay", decisionID)
	}
	if _, ok := graphStore.links[decisionID+"|targets|"+targetURN]; !ok {
		t.Fatal("decision target link missing after replay")
	}
	if len(appendLog.replayRequests) != 1 {
		t.Fatalf("len(replayRequests) = %d, want 1", len(appendLog.replayRequests))
	}
	if got := appendLog.replayRequests[0].KindPrefix; got != "workflow.v1." {
		t.Fatalf("HTTP replay kind prefix = %q, want workflow.v1.", got)
	}
	if got := appendLog.replayRequests[0].AttributeEquals["workflow_kind"]; got != "knowledge_decision" {
		t.Fatalf("HTTP replay workflow_kind filter = %q, want knowledge_decision", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	connectResp, err := client.ReplayWorkflowEvents(context.Background(), connect.NewRequest(&cerebrov1.ReplayWorkflowEventsRequest{
		KindPrefix: "workflow.v1.knowledge.",
		TenantId:   "writer",
		Limit:      1,
	}))
	if err != nil {
		t.Fatalf("ReplayWorkflowEvents() error = %v", err)
	}
	if got := connectResp.Msg.GetEntitiesProjected(); got != 1 {
		t.Fatalf("ReplayWorkflowEvents().EntitiesProjected = %d, want 1", got)
	}
	if len(appendLog.replayRequests) != 2 {
		t.Fatalf("len(replayRequests) = %d, want 2", len(appendLog.replayRequests))
	}
	if got := appendLog.replayRequests[1].KindPrefix; got != "workflow.v1.knowledge." {
		t.Fatalf("Connect replay kind prefix = %q, want workflow.v1.knowledge.", got)
	}
}

func TestClaimEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-jira": {
				Id:       "writer-jira",
				SourceId: "sdk",
				TenantId: "writer",
				Config: map[string]string{
					"integration": "jira",
				},
			},
		},
	}
	graphStore := &stubGraphStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	userURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	writeBody, err := protojson.Marshal(&cerebrov1.WriteClaimsRequest{
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate: "assigned_to",
				ObjectRef: &cerebrov1.EntityRef{
					Urn:        userURN,
					EntityType: "user",
					Label:      "Alice",
				},
				ClaimType:     "relation",
				SourceEventId: "jira-event-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal write claims body: %v", err)
	}
	writeReq, err := http.NewRequest(http.MethodPost, server.URL+"/source-runtimes/writer-jira/claims", bytes.NewReader(writeBody))
	if err != nil {
		t.Fatalf("new write claims request: %v", err)
	}
	writeReq.Header.Set("Content-Type", "application/json")
	writeResp, err := server.Client().Do(writeReq)
	if err != nil {
		t.Fatalf("POST /source-runtimes/{id}/claims error = %v", err)
	}
	defer func() {
		if closeErr := writeResp.Body.Close(); closeErr != nil {
			t.Fatalf("close write claims response body: %v", closeErr)
		}
	}()
	var writePayload map[string]any
	if err := json.NewDecoder(writeResp.Body).Decode(&writePayload); err != nil {
		t.Fatalf("decode write claims response: %v", err)
	}
	if got := writePayload["claims_written"]; got != float64(2) {
		t.Fatalf("write claims claims_written = %#v, want 2", got)
	}
	if got := writePayload["entities_upserted"]; got != float64(2) {
		t.Fatalf("write claims entities_upserted = %#v, want 2", got)
	}
	if got := writePayload["relation_links_projected"]; got != float64(1) {
		t.Fatalf("write claims relation_links_projected = %#v, want 1", got)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	writeClaimsResp, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef: &cerebrov1.EntityRef{
					Urn:        issueURN,
					EntityType: "ticket",
					Label:      "ENG-123",
				},
				Predicate:  "exists",
				ClaimType:  "existence",
				ObservedAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
			},
		},
	}))
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if got := writeClaimsResp.Msg.GetClaimsWritten(); got != 1 {
		t.Fatalf("WriteClaims claims_written = %d, want 1", got)
	}
	if len(runtimeStore.claims) != 3 {
		t.Fatalf("len(runtimeStore.claims) = %d, want 3", len(runtimeStore.claims))
	}
	if len(runtimeStore.entities) != 2 {
		t.Fatalf("len(runtimeStore.entities) = %d, want 2", len(runtimeStore.entities))
	}
	if len(graphStore.links) != 1 {
		t.Fatalf("len(graphStore.links) = %d, want 1", len(graphStore.links))
	}

	listResp, err := server.Client().Get(server.URL + "/source-runtimes/writer-jira/claims?predicate=assigned_to&source_event_id=jira-event-1&limit=1")
	if err != nil {
		t.Fatalf("GET /source-runtimes/{id}/claims error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close list claims response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode list claims response: %v", err)
	}
	listedClaims, ok := listPayload["claims"].([]any)
	if !ok || len(listedClaims) != 1 {
		t.Fatalf("list claims payload = %#v, want 1 claim", listPayload["claims"])
	}
	listedClaim, ok := listedClaims[0].(map[string]any)
	if !ok {
		t.Fatalf("list claims entry = %#v, want object", listedClaims[0])
	}
	if got := listedClaim["predicate"]; got != "assigned_to" {
		t.Fatalf("list claims predicate = %#v, want assigned_to", got)
	}

	listClaimsResp, err := client.ListClaims(context.Background(), connect.NewRequest(&cerebrov1.ListClaimsRequest{
		RuntimeId:     "writer-jira",
		Predicate:     "status",
		ObjectValue:   "in_progress",
		SourceEventId: "jira-event-1",
		Limit:         1,
	}))
	if err != nil {
		t.Fatalf("ListClaims() error = %v", err)
	}
	if got := len(listClaimsResp.Msg.GetClaims()); got != 1 {
		t.Fatalf("len(ListClaims().Claims) = %d, want 1", got)
	}
	if got := listClaimsResp.Msg.GetClaims()[0].GetObjectValue(); got != "in_progress" {
		t.Fatalf("ListClaims().Claims[0].ObjectValue = %q, want in_progress", got)
	}
	if got := runtimeStore.claimListRequest.Predicate; got != "status" {
		t.Fatalf("runtimeStore.claimListRequest.Predicate = %q, want status", got)
	}
	if got := runtimeStore.claimListRequest.ObjectValue; got != "in_progress" {
		t.Fatalf("runtimeStore.claimListRequest.ObjectValue = %q, want in_progress", got)
	}
	if got := runtimeStore.claimListRequest.SourceEventID; got != "jira-event-1" {
		t.Fatalf("runtimeStore.claimListRequest.SourceEventID = %q, want jira-event-1", got)
	}
}

func TestWriteClaimsReplaceExistingReportsRetractedClaims(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-jira": {
				Id:       "writer-jira",
				SourceId: "sdk",
				TenantId: "writer",
				Config:   map[string]string{"integration": "jira"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	issueURN := "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123"
	userURN := "urn:cerebro:writer:runtime:writer-jira:user:acct:42"
	if _, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId: "writer-jira",
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "status",
				ObjectValue:   "in_progress",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-1",
			},
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "assigned_to",
				ObjectRef:     &cerebrov1.EntityRef{Urn: userURN, EntityType: "user", Label: "Alice"},
				ClaimType:     "relation",
				SourceEventId: "jira-event-1",
			},
		},
	})); err != nil {
		t.Fatalf("seed WriteClaims() error = %v", err)
	}

	resp, err := client.WriteClaims(context.Background(), connect.NewRequest(&cerebrov1.WriteClaimsRequest{
		RuntimeId:       "writer-jira",
		ReplaceExisting: true,
		Claims: []*cerebrov1.Claim{
			{
				SubjectRef:    &cerebrov1.EntityRef{Urn: issueURN, EntityType: "ticket", Label: "ENG-123"},
				Predicate:     "status",
				ObjectValue:   "done",
				ClaimType:     "attribute",
				SourceEventId: "jira-event-2",
				ObservedAt:    timestamppb.New(time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
			},
		},
	}))
	if err != nil {
		t.Fatalf("replace WriteClaims() error = %v", err)
	}
	if got := resp.Msg.GetClaimsWritten(); got != 1 {
		t.Fatalf("replace claims_written = %d, want 1", got)
	}
	if got := resp.Msg.GetClaimsRetracted(); got != 2 {
		t.Fatalf("replace claims_retracted = %d, want 2", got)
	}
	if len(runtimeStore.claims) != 3 {
		t.Fatalf("len(runtimeStore.claims) = %d, want 3", len(runtimeStore.claims))
	}
	var retracted *ports.ClaimRecord
	for _, claim := range runtimeStore.claims {
		if claim != nil && claim.Predicate == "assigned_to" {
			retracted = claim
			break
		}
	}
	if retracted == nil {
		t.Fatal("retracted assigned_to claim = nil, want non-nil")
	}
	if got := retracted.Status; got != "retracted" {
		t.Fatalf("retracted claim status = %q, want retracted", got)
	}
	if got := retracted.SourceEventID; got != "jira-event-2" {
		t.Fatalf("retracted claim source_event_id = %q, want jira-event-2", got)
	}
}

func TestGraphNeighborhoodEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:github_pull_request:writer/cerebro#447",
				EntityType: "github.pull_request",
				Label:      "writer/cerebro#447",
			},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:github_repo:writer/cerebro", EntityType: "github.repo", Label: "writer/cerebro"},
				{URN: "urn:cerebro:writer:github_user:alice", EntityType: "github.user", Label: "Alice"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:github_user:alice", Relation: "authored", ToURN: "urn:cerebro:writer:github_pull_request:writer/cerebro#447"},
				{FromURN: "urn:cerebro:writer:github_pull_request:writer/cerebro#447", Relation: "belongs_to", ToURN: "urn:cerebro:writer:github_repo:writer/cerebro"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: &stubRuntimeStore{},
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/graph/neighborhood?root_urn=urn:cerebro:writer:github_pull_request:writer/cerebro%23447&limit=5")
	if err != nil {
		t.Fatalf("GET /graph/neighborhood error = %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatalf("close /graph/neighborhood response body: %v", closeErr)
		}
	}()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /graph/neighborhood response: %v", err)
	}
	rootPayload, ok := payload["root"].(map[string]any)
	if !ok {
		t.Fatalf("graph root payload = %#v, want object", payload["root"])
	}
	if got := rootPayload["entity_type"]; got != "github.pull_request" {
		t.Fatalf("graph root entity_type = %#v, want github.pull_request", got)
	}
	neighborsPayload, ok := payload["neighbors"].([]any)
	if !ok || len(neighborsPayload) != 2 {
		t.Fatalf("graph neighbors payload = %#v, want 2 entries", payload["neighbors"])
	}
	if graphStore.neighborhoodRootURN != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("graph neighborhood root urn = %q, want pull request urn", graphStore.neighborhoodRootURN)
	}
	if graphStore.neighborhoodLimit != 5 {
		t.Fatalf("graph neighborhood limit = %d, want 5", graphStore.neighborhoodLimit)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	neighborhoodResp, err := client.GetEntityNeighborhood(context.Background(), connect.NewRequest(&cerebrov1.GetEntityNeighborhoodRequest{
		RootUrn: "urn:cerebro:writer:github_pull_request:writer/cerebro#447",
		Limit:   2,
	}))
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if got := neighborhoodResp.Msg.GetRoot().GetUrn(); got != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("GetEntityNeighborhood root urn = %q, want pull request urn", got)
	}
	if len(neighborhoodResp.Msg.GetNeighbors()) != 2 {
		t.Fatalf("len(GetEntityNeighborhood.Neighbors) = %d, want 2", len(neighborhoodResp.Msg.GetNeighbors()))
	}
	if len(neighborhoodResp.Msg.GetRelations()) != 2 {
		t.Fatalf("len(GetEntityNeighborhood.Relations) = %d, want 2", len(neighborhoodResp.Msg.GetRelations()))
	}
}

func TestReportEndpoints(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	runtimeStore := &stubRuntimeStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
			"finding-2": {
				ID:           "finding-2",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-okta-policy-rule-lifecycle-tampering",
				Severity:     "HIGH",
				Status:       "resolved",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				EntityType: "okta.resource",
				Label:      "Require MFA",
			},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:okta_user:00u2", EntityType: "okta.user", Label: "admin@writer.com"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:okta_user:00u2", Relation: "acted_on", ToURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1"},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  &recordingAppendLog{},
		StateStore: runtimeStore,
		GraphStore: graphStore,
	}, registry)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	listResp, err := server.Client().Get(server.URL + "/reports")
	if err != nil {
		t.Fatalf("GET /reports error = %v", err)
	}
	defer func() {
		if closeErr := listResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /reports response body: %v", closeErr)
		}
	}()
	var listPayload map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("decode /reports response: %v", err)
	}
	reportsPayload, ok := listPayload["reports"].([]any)
	if !ok || len(reportsPayload) != 1 {
		t.Fatalf("/reports payload = %#v, want 1 entry", listPayload["reports"])
	}

	runReq, err := http.NewRequest(http.MethodPost, server.URL+"/reports/finding-summary/runs?tenant_id=writer&runtime_id=writer-okta-audit&graph_limit=2", nil)
	if err != nil {
		t.Fatalf("new run report request: %v", err)
	}
	runReq.Header.Set("X-Cerebro-Source-Config", `{"token":"secret","api_key":"secret"}`)
	runResp, err := server.Client().Do(runReq)
	if err != nil {
		t.Fatalf("POST /reports/{id}/runs error = %v", err)
	}
	defer func() {
		if closeErr := runResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /reports/{id}/runs response body: %v", closeErr)
		}
	}()
	var runPayload map[string]any
	if err := json.NewDecoder(runResp.Body).Decode(&runPayload); err != nil {
		t.Fatalf("decode /reports/{id}/runs response: %v", err)
	}
	runBody, ok := runPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("run payload = %#v, want object", runPayload["run"])
	}
	if got := runBody["report_id"]; got != "finding-summary" {
		t.Fatalf("run report_id = %#v, want finding-summary", got)
	}
	resultBody, ok := runBody["result"].(map[string]any)
	if !ok {
		t.Fatalf("run result payload = %#v, want object", runBody["result"])
	}
	if got := resultBody["total_findings"]; got != float64(2) {
		t.Fatalf("run total_findings = %#v, want 2", got)
	}
	if got := resultBody["graph_evidence_status"]; got != "included" {
		t.Fatalf("run graph_evidence_status = %#v, want included", got)
	}
	graphEvidencePayload, ok := resultBody["graph_evidence"].([]any)
	if !ok || len(graphEvidencePayload) != 1 {
		t.Fatalf("run graph_evidence = %#v, want 1 entry", resultBody["graph_evidence"])
	}
	graphEvidenceEntry, ok := graphEvidencePayload[0].(map[string]any)
	if !ok {
		t.Fatalf("run graph evidence entry = %#v, want object", graphEvidencePayload[0])
	}
	if got := graphEvidenceEntry["resource_urn"]; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("run graph evidence resource_urn = %#v, want policy rule urn", got)
	}
	runID, ok := runBody["id"].(string)
	if !ok || runID == "" {
		t.Fatalf("run id = %#v, want non-empty string", runBody["id"])
	}
	if len(runtimeStore.reportRuns) != 1 {
		t.Fatalf("len(runtimeStore.reportRuns) = %d, want 1", len(runtimeStore.reportRuns))
	}
	storedRun := runtimeStore.reportRuns[runID]
	if _, ok := storedRun.GetParameters()["token"]; ok {
		t.Fatalf("stored report parameters include token")
	}
	if _, ok := storedRun.GetParameters()["api_key"]; ok {
		t.Fatalf("stored report parameters include api_key")
	}
	if graphStore.neighborhoodRootURN != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("graph evidence root urn = %q, want policy rule urn", graphStore.neighborhoodRootURN)
	}
	if graphStore.neighborhoodLimit != 2 {
		t.Fatalf("graph evidence limit = %d, want 2", graphStore.neighborhoodLimit)
	}

	getResp, err := server.Client().Get(server.URL + "/report-runs/" + runID)
	if err != nil {
		t.Fatalf("GET /report-runs/{id} error = %v", err)
	}
	defer func() {
		if closeErr := getResp.Body.Close(); closeErr != nil {
			t.Fatalf("close /report-runs/{id} response body: %v", closeErr)
		}
	}()
	var getPayload map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&getPayload); err != nil {
		t.Fatalf("decode /report-runs/{id} response: %v", err)
	}
	getRunPayload, ok := getPayload["run"].(map[string]any)
	if !ok {
		t.Fatalf("get run payload = %#v, want object", getPayload["run"])
	}
	if got := getRunPayload["id"]; got != runID {
		t.Fatalf("get run id = %#v, want %q", got, runID)
	}

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	listReportsResp, err := client.ListReportDefinitions(context.Background(), connect.NewRequest(&cerebrov1.ListReportDefinitionsRequest{}))
	if err != nil {
		t.Fatalf("ListReportDefinitions() error = %v", err)
	}
	if len(listReportsResp.Msg.GetReports()) != 1 {
		t.Fatalf("len(ListReportDefinitions.Reports) = %d, want 1", len(listReportsResp.Msg.GetReports()))
	}
	runReportResp, err := client.RunReport(context.Background(), connect.NewRequest(&cerebrov1.RunReportRequest{
		ReportId: "finding-summary",
		Parameters: map[string]string{
			"tenant_id":  "writer",
			"runtime_id": "writer-okta-audit",
		},
	}))
	if err != nil {
		t.Fatalf("RunReport() error = %v", err)
	}
	if got := runReportResp.Msg.GetRun().GetReportId(); got != "finding-summary" {
		t.Fatalf("RunReport report id = %q, want finding-summary", got)
	}
	getRunResp, err := client.GetReportRun(context.Background(), connect.NewRequest(&cerebrov1.GetReportRunRequest{
		Id: runReportResp.Msg.GetRun().GetId(),
	}))
	if err != nil {
		t.Fatalf("GetReportRun() error = %v", err)
	}
	if got := getRunResp.Msg.GetRun().GetId(); got != runReportResp.Msg.GetRun().GetId() {
		t.Fatalf("GetReportRun id = %q, want %q", got, runReportResp.Msg.GetRun().GetId())
	}
}

func newFixtureRegistry() (*sourcecdk.Registry, error) {
	source, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	okta, err := oktasource.NewFixture()
	if err != nil {
		return nil, err
	}
	sdk, err := sdksource.New()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source, okta, sdk)
}

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	resourceURNs := make([]string, len(finding.ResourceURNs))
	copy(resourceURNs, finding.ResourceURNs)
	eventIDs := make([]string, len(finding.EventIDs))
	copy(eventIDs, finding.EventIDs)
	observedPolicyIDs := make([]string, len(finding.ObservedPolicyIDs))
	copy(observedPolicyIDs, finding.ObservedPolicyIDs)
	controlRefs := make([]ports.FindingControlRef, len(finding.ControlRefs))
	copy(controlRefs, finding.ControlRefs)
	notes := make([]ports.FindingNote, len(finding.Notes))
	copy(notes, finding.Notes)
	tickets := make([]ports.FindingTicket, len(finding.Tickets))
	copy(tickets, finding.Tickets)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantID:          finding.TenantID,
		RuntimeID:         finding.RuntimeID,
		RuleID:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            finding.Status,
		Summary:           finding.Summary,
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckID:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       controlRefs,
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           notes,
			Tickets:         tickets,
			Assignee:        finding.Assignee,
			DueAt:           finding.DueAt,
			StatusReason:    finding.StatusReason,
			StatusUpdatedAt: finding.StatusUpdatedAt,
		},
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func preserveFindingWorkflow(existing *ports.FindingRecord, incoming *ports.FindingRecord) *ports.FindingRecord {
	if existing == nil || incoming == nil {
		return incoming
	}
	if strings.TrimSpace(existing.Assignee) != "" && strings.TrimSpace(incoming.Assignee) == "" {
		incoming.Assignee = strings.TrimSpace(existing.Assignee)
	}
	if !existing.DueAt.IsZero() && incoming.DueAt.IsZero() {
		incoming.DueAt = existing.DueAt
	}
	if len(existing.Notes) != 0 && len(incoming.Notes) == 0 {
		incoming.Notes = append([]ports.FindingNote(nil), existing.Notes...)
	}
	if len(existing.Tickets) != 0 && len(incoming.Tickets) == 0 {
		incoming.Tickets = append([]ports.FindingTicket(nil), existing.Tickets...)
	}
	if strings.TrimSpace(incoming.Status) == "open" {
		switch strings.TrimSpace(existing.Status) {
		case "resolved", "suppressed":
			incoming.Status = strings.TrimSpace(existing.Status)
			incoming.StatusReason = strings.TrimSpace(existing.StatusReason)
			incoming.StatusUpdatedAt = existing.StatusUpdatedAt
		}
	}
	return incoming
}

func findingMatches(request ports.ListFindingsRequest, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if request.TenantID != "" && strings.TrimSpace(finding.TenantID) != strings.TrimSpace(request.TenantID) {
		return false
	}
	if strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(finding.ID) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(finding.RuleID) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Severity != "" && strings.TrimSpace(finding.Severity) != strings.TrimSpace(request.Severity) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(finding.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.ResourceURN != "" && !containsTrimmed(finding.ResourceURNs, request.ResourceURN) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(finding.EventIDs, request.EventID) {
		return false
	}
	if request.PolicyID != "" && strings.TrimSpace(finding.PolicyID) != strings.TrimSpace(request.PolicyID) {
		return false
	}
	return true
}

func cloneClaim(claim *ports.ClaimRecord) *ports.ClaimRecord {
	if claim == nil {
		return nil
	}
	attributes := make(map[string]string, len(claim.Attributes))
	for key, value := range claim.Attributes {
		attributes[key] = value
	}
	return &ports.ClaimRecord{
		ID:            claim.ID,
		RuntimeID:     claim.RuntimeID,
		TenantID:      claim.TenantID,
		SubjectURN:    claim.SubjectURN,
		SubjectRef:    cloneEntityRef(claim.SubjectRef),
		Predicate:     claim.Predicate,
		ObjectURN:     claim.ObjectURN,
		ObjectRef:     cloneEntityRef(claim.ObjectRef),
		ObjectValue:   claim.ObjectValue,
		ClaimType:     claim.ClaimType,
		Status:        claim.Status,
		SourceEventID: claim.SourceEventID,
		ObservedAt:    claim.ObservedAt,
		ValidFrom:     claim.ValidFrom,
		ValidTo:       claim.ValidTo,
		Attributes:    attributes,
	}
}

func claimMatches(request ports.ListClaimsRequest, claim *ports.ClaimRecord) bool {
	if claim == nil {
		return false
	}
	if strings.TrimSpace(claim.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.ClaimID != "" && strings.TrimSpace(claim.ID) != strings.TrimSpace(request.ClaimID) {
		return false
	}
	if request.SubjectURN != "" && strings.TrimSpace(claim.SubjectURN) != strings.TrimSpace(request.SubjectURN) {
		return false
	}
	if request.Predicate != "" && strings.TrimSpace(claim.Predicate) != strings.TrimSpace(request.Predicate) {
		return false
	}
	if request.ObjectURN != "" && strings.TrimSpace(claim.ObjectURN) != strings.TrimSpace(request.ObjectURN) {
		return false
	}
	if request.ObjectValue != "" && strings.TrimSpace(claim.ObjectValue) != strings.TrimSpace(request.ObjectValue) {
		return false
	}
	if request.ClaimType != "" && strings.TrimSpace(claim.ClaimType) != strings.TrimSpace(request.ClaimType) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(claim.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.SourceEventID != "" && strings.TrimSpace(claim.SourceEventID) != strings.TrimSpace(request.SourceEventID) {
		return false
	}
	return true
}

func containsTrimmed(values []string, expected string) bool {
	trimmedExpected := strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedExpected {
			return true
		}
	}
	return false
}

func findingEvaluationRunMatches(request ports.ListFindingEvaluationRunsRequest, run *cerebrov1.FindingEvaluationRun) bool {
	if run == nil {
		return false
	}
	if strings.TrimSpace(run.GetRuntimeId()) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(run.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(run.GetStatus()) != strings.TrimSpace(request.Status) {
		return false
	}
	return true
}

func findingEvidenceMatches(request ports.ListFindingEvidenceRequest, evidence *cerebrov1.FindingEvidence) bool {
	if evidence == nil {
		return false
	}
	if strings.TrimSpace(evidence.GetRuntimeId()) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(evidence.GetFindingId()) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RunID != "" && strings.TrimSpace(evidence.GetRunId()) != strings.TrimSpace(request.RunID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(evidence.GetRuleId()) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.ClaimID != "" && !containsTrimmed(evidence.GetClaimIds(), request.ClaimID) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(evidence.GetEventIds(), request.EventID) {
		return false
	}
	if request.GraphRootURN != "" && !containsTrimmed(evidence.GetGraphRootUrns(), request.GraphRootURN) {
		return false
	}
	return true
}

func cloneReportRun(run *cerebrov1.ReportRun) *cerebrov1.ReportRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.ReportRun)
}

func cloneFindingEvaluationRun(run *cerebrov1.FindingEvaluationRun) *cerebrov1.FindingEvaluationRun {
	if run == nil {
		return nil
	}
	return proto.Clone(run).(*cerebrov1.FindingEvaluationRun)
}

func cloneFindingEvidence(evidence *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	if evidence == nil {
		return nil
	}
	return proto.Clone(evidence).(*cerebrov1.FindingEvidence)
}

func cloneNeighborhood(neighborhood *ports.EntityNeighborhood) *ports.EntityNeighborhood {
	if neighborhood == nil {
		return nil
	}
	cloned := &ports.EntityNeighborhood{
		Root:      cloneNeighborhoodNode(neighborhood.Root),
		Neighbors: make([]*ports.NeighborhoodNode, 0, len(neighborhood.Neighbors)),
		Relations: make([]*ports.NeighborhoodRelation, 0, len(neighborhood.Relations)),
	}
	for _, neighbor := range neighborhood.Neighbors {
		cloned.Neighbors = append(cloned.Neighbors, cloneNeighborhoodNode(neighbor))
	}
	for _, relation := range neighborhood.Relations {
		cloned.Relations = append(cloned.Relations, cloneNeighborhoodRelation(relation))
	}
	return cloned
}

func cloneNeighborhoodNode(node *ports.NeighborhoodNode) *ports.NeighborhoodNode {
	if node == nil {
		return nil
	}
	return &ports.NeighborhoodNode{
		URN:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func cloneNeighborhoodRelation(relation *ports.NeighborhoodRelation) *ports.NeighborhoodRelation {
	if relation == nil {
		return nil
	}
	return &ports.NeighborhoodRelation{
		FromURN:    relation.FromURN,
		Relation:   relation.Relation,
		ToURN:      relation.ToURN,
		Attributes: cloneStringMap(relation.Attributes),
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func findingTestEvent(id string, eventType string, outcome string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/audit/v1",
		Attributes: map[string]string{
			"domain":                            "writer.okta.com",
			"event_type":                        eventType,
			"resource_id":                       "pol-1",
			"resource_type":                     "PolicyRule",
			"actor_id":                          "00u2",
			"actor_type":                        "User",
			"actor_alternate_id":                "admin@writer.com",
			"actor_display_name":                "Admin Example",
			"outcome_result":                    outcome,
			ports.EventAttributeSourceRuntimeID: "writer-okta-audit",
		},
	}
}

func projectedLinkKey(link *ports.ProjectedLink) string {
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
}

func cloneEntityRef(ref *cerebrov1.EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return proto.Clone(ref).(*cerebrov1.EntityRef)
}
