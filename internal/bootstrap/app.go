package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/claims"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/workflowprojection"
)

// Dependencies are the future store/log boundaries that will be wired into the rewrite.
type Dependencies struct {
	AppendLog  ports.AppendLog
	StateStore ports.StateStore
	GraphStore ports.GraphStore
}

// App is the minimal Connect/bootstrap composition root for the rewrite skeleton.
type App struct {
	cfg     config.Config
	deps    Dependencies
	sources *sourcecdk.Registry
	mux     *http.ServeMux
	server  *http.Server
}

type bootstrapService struct {
	deps    Dependencies
	sources *sourcecdk.Registry
}

// New constructs the minimal bootstrap app and registers the Connect handlers.
func New(cfg config.Config, deps Dependencies, sources *sourcecdk.Registry) *App {
	mux := http.NewServeMux()
	service := &bootstrapService{deps: deps, sources: sources}
	path, handler := cerebrov1connect.NewBootstrapServiceHandler(service)
	mux.Handle(path, handler)

	app := &App{cfg: cfg, deps: deps, sources: sources, mux: mux}
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/healthz", app.handleHealth)
	mux.HandleFunc("GET /reports", app.handleListReportDefinitions)
	mux.HandleFunc("GET /finding-rules", app.handleListFindingRules)
	mux.HandleFunc("POST /reports/{reportID}/runs", app.handleRunReport)
	mux.HandleFunc("GET /report-runs/{runID}", app.handleGetReportRun)
	mux.HandleFunc("GET /findings/{findingID}", app.handleGetFinding)
	mux.HandleFunc("POST /findings/{findingID}/resolve", app.handleResolveFinding)
	mux.HandleFunc("POST /findings/{findingID}/suppress", app.handleSuppressFinding)
	mux.HandleFunc("PUT /findings/{findingID}/assign", app.handleAssignFinding)
	mux.HandleFunc("PUT /findings/{findingID}/due", app.handleSetFindingDueDate)
	mux.HandleFunc("POST /findings/{findingID}/notes", app.handleAddFindingNote)
	mux.HandleFunc("POST /findings/{findingID}/tickets", app.handleLinkFindingTicket)
	mux.HandleFunc("GET /finding-evaluation-runs/{runID}", app.handleGetFindingEvaluationRun)
	mux.HandleFunc("GET /finding-evidence/{evidenceID}", app.handleGetFindingEvidence)
	mux.HandleFunc("/sources", app.handleSources)
	mux.HandleFunc("GET /sources/{sourceID}/check", app.handleCheckSource)
	mux.HandleFunc("GET /sources/{sourceID}/discover", app.handleDiscoverSource)
	mux.HandleFunc("GET /sources/{sourceID}/read", app.handleReadSource)
	mux.HandleFunc("POST /platform/knowledge/decisions", app.handleWriteDecision)
	mux.HandleFunc("POST /platform/knowledge/actions", app.handleWriteAction)
	mux.HandleFunc("POST /graph/actuate/recommendation", app.handleWriteAction)
	mux.HandleFunc("POST /graph/write/outcome", app.handleWriteOutcome)
	mux.HandleFunc("POST /platform/workflow/replay", app.handleReplayWorkflowEvents)
	mux.HandleFunc("GET /graph/neighborhood", app.handleGetEntityNeighborhood)
	mux.HandleFunc("PUT /source-runtimes/{runtimeID}", app.handlePutSourceRuntime)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}", app.handleGetSourceRuntime)
	mux.HandleFunc("POST /source-runtimes/{runtimeID}/sync", app.handleSyncSourceRuntime)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}/claims", app.handleListClaims)
	mux.HandleFunc("POST /source-runtimes/{runtimeID}/claims", app.handleWriteClaims)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}/findings", app.handleListFindings)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}/finding-evidence", app.handleListFindingEvidence)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}/finding-evaluation-runs", app.handleListFindingEvaluationRuns)
	mux.HandleFunc("POST /source-runtimes/{runtimeID}/finding-rules/evaluate", app.handleEvaluateSourceRuntimeFindingRules)
	mux.HandleFunc("POST /source-runtimes/{runtimeID}/findings/evaluate", app.handleEvaluateSourceRuntimeFindings)
	app.server = &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return app
}

// Handler returns the composed HTTP handler for embedding in tests or another server.
func (a *App) Handler() http.Handler {
	return a.mux
}

// ListenAndServe starts the bootstrap HTTP server.
func (a *App) ListenAndServe() error {
	if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the bootstrap HTTP server.
func (a *App) Shutdown(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := healthResponse(r.Context(), a.deps)
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleSources(w http.ResponseWriter, r *http.Request) {
	writeProtoJSON(w, http.StatusOK, a.sourceService().List())
}

func (a *App) handleListReportDefinitions(w http.ResponseWriter, r *http.Request) {
	writeProtoJSON(w, http.StatusOK, a.reportService().List())
}

func (a *App) handleListFindingRules(w http.ResponseWriter, r *http.Request) {
	writeProtoJSON(w, http.StatusOK, a.findingService().ListRules())
}

func (a *App) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	finding, err := a.findingService().GetFinding(r.Context(), r.PathValue("findingID"))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleResolveFinding(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ResolveFindingRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if rawReason := r.URL.Query().Get("reason"); rawReason != "" {
		request.Reason = rawReason
	}
	finding, err := a.findingService().ResolveFinding(r.Context(), request.GetId(), request.GetReason())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ResolveFindingResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleSuppressFinding(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.SuppressFindingRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if rawReason := r.URL.Query().Get("reason"); rawReason != "" {
		request.Reason = rawReason
	}
	finding, err := a.findingService().SuppressFinding(r.Context(), request.GetId(), request.GetReason())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.SuppressFindingResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleAssignFinding(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.AssignFindingRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if rawAssignee, ok := r.URL.Query()["assignee"]; ok && len(rawAssignee) != 0 {
		request.Assignee = rawAssignee[len(rawAssignee)-1]
	}
	finding, err := a.findingService().AssignFinding(r.Context(), request.GetId(), request.GetAssignee())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.AssignFindingResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleSetFindingDueDate(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.SetFindingDueDateRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	var dueAt time.Time
	if request.GetDueAt() != nil {
		dueAt = request.GetDueAt().AsTime()
	}
	finding, err := a.findingService().SetFindingDueDate(r.Context(), request.GetId(), dueAt)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.SetFindingDueDateResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleAddFindingNote(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.AddFindingNoteRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	finding, err := a.findingService().AddFindingNote(r.Context(), request.GetId(), request.GetNote())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.AddFindingNoteResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleLinkFindingTicket(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.LinkFindingTicketRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	finding, err := a.findingService().LinkFindingTicket(
		r.Context(),
		request.GetId(),
		request.GetUrl(),
		request.GetName(),
		request.GetExternalId(),
	)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.LinkFindingTicketResponse{
		Finding: findingMessage(finding),
	})
}

func (a *App) handleGetFindingEvaluationRun(w http.ResponseWriter, r *http.Request) {
	response, err := a.findingService().GetEvaluationRun(r.Context(), r.PathValue("runID"))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingEvaluationRunResponse{
		Run: response,
	})
}

func (a *App) handleGetFindingEvidence(w http.ResponseWriter, r *http.Request) {
	response, err := a.findingService().GetEvidence(r.Context(), r.PathValue("evidenceID"))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingEvidenceResponse{
		Evidence: response,
	})
}

func (a *App) handleRunReport(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.RunReportRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeReportError(w, err)
		return
	}
	request.ReportId = r.PathValue("reportID")
	if request.Parameters == nil {
		request.Parameters = map[string]string{}
	}
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeReportError(w, err)
		return
	}
	for key, value := range config {
		request.Parameters[key] = value
	}
	response, err := a.reportService().Run(r.Context(), request)
	if err != nil {
		writeReportError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleGetReportRun(w http.ResponseWriter, r *http.Request) {
	response, err := a.reportService().Get(r.Context(), &cerebrov1.GetReportRunRequest{
		Id: r.PathValue("runID"),
	})
	if err != nil {
		writeReportError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleCheckSource(w http.ResponseWriter, r *http.Request) {
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	response, err := a.sourceService().Check(r.Context(), &cerebrov1.CheckSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   config,
	})
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleDiscoverSource(w http.ResponseWriter, r *http.Request) {
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	response, err := a.sourceService().Discover(r.Context(), &cerebrov1.DiscoverSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   config,
	})
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleReadSource(w http.ResponseWriter, r *http.Request) {
	config, err := sourceConfigFromRequest(r)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	request := &cerebrov1.ReadSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   config,
	}
	rawCursors := r.URL.Query()["cursor"]
	if len(rawCursors) > 0 {
		cursor := rawCursors[len(rawCursors)-1]
		if cursor != "" {
			request.Cursor = &cerebrov1.SourceCursor{Opaque: cursor}
		}
	}
	response, err := a.sourceService().Read(r.Context(), request)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleWriteDecision(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteDecisionRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	metadata := map[string]any{}
	if request.GetMetadata() != nil {
		metadata = request.GetMetadata().AsMap()
	}
	result, err := a.knowledgeService().WriteDecision(r.Context(), knowledge.DecisionWriteRequest{
		ID:            request.GetId(),
		DecisionType:  request.GetDecisionType(),
		Status:        request.GetStatus(),
		MadeBy:        request.GetMadeBy(),
		Rationale:     request.GetRationale(),
		TargetIDs:     request.GetTargetIds(),
		EvidenceIDs:   request.GetEvidenceIds(),
		ActionIDs:     request.GetActionIds(),
		SourceSystem:  request.GetSourceSystem(),
		SourceEventID: request.GetSourceEventId(),
		ObservedAt:    timestampValue(request.GetObservedAt()),
		ValidFrom:     timestampValue(request.GetValidFrom()),
		ValidTo:       timestampValue(request.GetValidTo()),
		Confidence:    request.GetConfidence(),
		Metadata:      metadata,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusCreated, &cerebrov1.WriteDecisionResponse{
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	})
}

func (a *App) handleWriteAction(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteActionRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	metadata := map[string]any{}
	if request.GetMetadata() != nil {
		metadata = request.GetMetadata().AsMap()
	}
	result, err := a.knowledgeService().WriteAction(r.Context(), knowledge.ActionWriteRequest{
		ID:               request.GetId(),
		RecommendationID: request.GetRecommendationId(),
		InsightType:      request.GetInsightType(),
		Title:            request.GetTitle(),
		Summary:          request.GetSummary(),
		DecisionID:       request.GetDecisionId(),
		TargetIDs:        request.GetTargetIds(),
		SourceSystem:     request.GetSourceSystem(),
		SourceEventID:    request.GetSourceEventId(),
		ObservedAt:       timestampValue(request.GetObservedAt()),
		ValidFrom:        timestampValue(request.GetValidFrom()),
		ValidTo:          timestampValue(request.GetValidTo()),
		Confidence:       request.GetConfidence(),
		AutoGenerated:    request.GetAutoGenerated(),
		Metadata:         metadata,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusCreated, &cerebrov1.WriteActionResponse{
		ActionId:    result.ActionID,
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	})
}

func (a *App) handleWriteOutcome(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteOutcomeRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	metadata := map[string]any{}
	if request.GetMetadata() != nil {
		metadata = request.GetMetadata().AsMap()
	}
	result, err := a.knowledgeService().WriteOutcome(r.Context(), knowledge.OutcomeWriteRequest{
		ID:            request.GetId(),
		DecisionID:    request.GetDecisionId(),
		OutcomeType:   request.GetOutcomeType(),
		Verdict:       request.GetVerdict(),
		ImpactScore:   request.GetImpactScore(),
		TargetIDs:     request.GetTargetIds(),
		SourceSystem:  request.GetSourceSystem(),
		SourceEventID: request.GetSourceEventId(),
		ObservedAt:    timestampValue(request.GetObservedAt()),
		ValidFrom:     timestampValue(request.GetValidFrom()),
		ValidTo:       timestampValue(request.GetValidTo()),
		Confidence:    request.GetConfidence(),
		Metadata:      metadata,
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusCreated, &cerebrov1.WriteOutcomeResponse{
		OutcomeId:   result.OutcomeID,
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	})
}

func (a *App) handleReplayWorkflowEvents(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ReplayWorkflowEventsRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeWorkflowReplayError(w, err)
		return
	}
	result, err := a.workflowReplayService().Replay(r.Context(), workflowprojection.ReplayRequest{
		KindPrefix:      request.GetKindPrefix(),
		TenantID:        request.GetTenantId(),
		AttributeEquals: request.GetAttributeEquals(),
		Limit:           request.GetLimit(),
	})
	if err != nil {
		writeWorkflowReplayError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, workflowReplayResponse(result))
}

func (a *App) handleGetEntityNeighborhood(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.GetEntityNeighborhoodRequest{}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeGraphQueryError(w, err)
			return
		}
	}
	request.RootUrn = r.URL.Query().Get("root_urn")
	response, err := a.graphQueryService().GetEntityNeighborhood(r.Context(), graphquery.NeighborhoodRequest{
		RootURN: request.GetRootUrn(),
		Limit:   request.GetLimit(),
	})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, graphNeighborhoodResponse(response))
}

func (a *App) handlePutSourceRuntime(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.PutSourceRuntimeRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	if request.Runtime == nil {
		request.Runtime = &cerebrov1.SourceRuntime{}
	}
	request.Runtime.Id = r.PathValue("runtimeID")
	response, err := a.runtimeService().Put(r.Context(), request)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleGetSourceRuntime(w http.ResponseWriter, r *http.Request) {
	response, err := a.runtimeService().Get(r.Context(), &cerebrov1.GetSourceRuntimeRequest{
		Id: r.PathValue("runtimeID"),
	})
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleSyncSourceRuntime(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.SyncSourceRuntimeRequest{}
	if pageLimit := r.URL.Query().Get("page_limit"); pageLimit != "" {
		body := []byte(`{"page_limit":` + pageLimit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeSourceRuntimeError(w, err)
			return
		}
	}
	request.Id = r.PathValue("runtimeID")
	response, err := a.runtimeService().Sync(r.Context(), request)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleListClaims(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListClaimsRequest{
		RuntimeId:     r.PathValue("runtimeID"),
		ClaimId:       r.URL.Query().Get("claim_id"),
		SubjectUrn:    r.URL.Query().Get("subject_urn"),
		Predicate:     r.URL.Query().Get("predicate"),
		ObjectUrn:     r.URL.Query().Get("object_urn"),
		ObjectValue:   r.URL.Query().Get("object_value"),
		ClaimType:     r.URL.Query().Get("claim_type"),
		Status:        r.URL.Query().Get("status"),
		SourceEventId: r.URL.Query().Get("source_event_id"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeClaimError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.ClaimId = r.URL.Query().Get("claim_id")
		request.SubjectUrn = r.URL.Query().Get("subject_urn")
		request.Predicate = r.URL.Query().Get("predicate")
		request.ObjectUrn = r.URL.Query().Get("object_urn")
		request.ObjectValue = r.URL.Query().Get("object_value")
		request.ClaimType = r.URL.Query().Get("claim_type")
		request.Status = r.URL.Query().Get("status")
		request.SourceEventId = r.URL.Query().Get("source_event_id")
	}
	response, err := a.claimService().ListClaims(r.Context(), claims.ListRequest{
		RuntimeID:     request.GetRuntimeId(),
		ClaimID:       request.GetClaimId(),
		SubjectURN:    request.GetSubjectUrn(),
		Predicate:     request.GetPredicate(),
		ObjectURN:     request.GetObjectUrn(),
		ObjectValue:   request.GetObjectValue(),
		ClaimType:     request.GetClaimType(),
		Status:        request.GetStatus(),
		SourceEventID: request.GetSourceEventId(),
		Limit:         request.GetLimit(),
	})
	if err != nil {
		writeClaimError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ListClaimsResponse{
		Claims: response.Claims,
	})
}

func (a *App) handleWriteClaims(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteClaimsRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeClaimError(w, err)
		return
	}
	request.RuntimeId = r.PathValue("runtimeID")
	response, err := a.claimService().WriteClaims(r.Context(), claims.WriteRequest{
		RuntimeID:       request.GetRuntimeId(),
		Claims:          request.GetClaims(),
		ReplaceExisting: request.GetReplaceExisting(),
	})
	if err != nil {
		writeClaimError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.WriteClaimsResponse{
		ClaimsWritten:          response.ClaimsWritten,
		EntitiesUpserted:       response.EntitiesUpserted,
		RelationLinksProjected: response.RelationLinksProjected,
		ClaimsRetracted:        response.ClaimsRetracted,
	})
}

func (a *App) handleEvaluateSourceRuntimeFindings(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.EvaluateSourceRuntimeFindingsRequest{}
	request.RuleId = r.URL.Query().Get("rule_id")
	if eventLimit := r.URL.Query().Get("event_limit"); eventLimit != "" {
		body := []byte(`{"event_limit":` + eventLimit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
	}
	request.Id = r.PathValue("runtimeID")
	request.RuleId = r.URL.Query().Get("rule_id")
	response, err := a.findingService().EvaluateSourceRuntime(r.Context(), findings.EvaluateRequest{
		RuntimeID:  request.GetId(),
		RuleID:     request.GetRuleId(),
		EventLimit: request.GetEventLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, findingResponse(response))
}

func (a *App) handleEvaluateSourceRuntimeFindingRules(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	if eventLimit := r.URL.Query().Get("event_limit"); eventLimit != "" {
		body := []byte(`{"event_limit":` + eventLimit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
	}
	request.Id = r.PathValue("runtimeID")
	if ruleIDs := r.URL.Query()["rule_id"]; len(ruleIDs) != 0 {
		request.RuleIds = ruleIDs
	}
	response, err := a.findingService().EvaluateSourceRuntimeRules(r.Context(), findings.EvaluateRulesRequest{
		RuntimeID:  request.GetId(),
		RuleIDs:    request.GetRuleIds(),
		EventLimit: request.GetEventLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, findingRulesResponse(response))
}

func (a *App) handleListFindings(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingsRequest{
		RuntimeId:   r.PathValue("runtimeID"),
		FindingId:   r.URL.Query().Get("finding_id"),
		RuleId:      r.URL.Query().Get("rule_id"),
		Severity:    r.URL.Query().Get("severity"),
		ResourceUrn: r.URL.Query().Get("resource_urn"),
		EventId:     r.URL.Query().Get("event_id"),
		PolicyId:    r.URL.Query().Get("policy_id"),
	}
	if rawStatus := r.URL.Query().Get("status"); rawStatus != "" {
		status, err := parseFindingStatus(rawStatus)
		if err != nil {
			writeFindingError(w, err)
			return
		}
		request.Status = status
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.FindingId = r.URL.Query().Get("finding_id")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.Severity = r.URL.Query().Get("severity")
		request.ResourceUrn = r.URL.Query().Get("resource_urn")
		request.EventId = r.URL.Query().Get("event_id")
		request.PolicyId = r.URL.Query().Get("policy_id")
		if rawStatus := r.URL.Query().Get("status"); rawStatus != "" {
			status, err := parseFindingStatus(rawStatus)
			if err != nil {
				writeFindingError(w, err)
				return
			}
			request.Status = status
		}
	}
	response, err := a.findingService().ListFindings(r.Context(), findings.ListRequest{
		RuntimeID:   request.GetRuntimeId(),
		FindingID:   request.GetFindingId(),
		RuleID:      request.GetRuleId(),
		Severity:    request.GetSeverity(),
		Status:      findingStatusString(request.GetStatus()),
		ResourceURN: request.GetResourceUrn(),
		EventID:     request.GetEventId(),
		PolicyID:    request.GetPolicyId(),
		Limit:       request.GetLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, listFindingsResponse(response))
}

func (a *App) handleListFindingEvidence(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingEvidenceRequest{
		RuntimeId:    r.PathValue("runtimeID"),
		FindingId:    r.URL.Query().Get("finding_id"),
		RunId:        r.URL.Query().Get("run_id"),
		RuleId:       r.URL.Query().Get("rule_id"),
		ClaimId:      r.URL.Query().Get("claim_id"),
		EventId:      r.URL.Query().Get("event_id"),
		GraphRootUrn: r.URL.Query().Get("graph_root_urn"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.FindingId = r.URL.Query().Get("finding_id")
		request.RunId = r.URL.Query().Get("run_id")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.ClaimId = r.URL.Query().Get("claim_id")
		request.EventId = r.URL.Query().Get("event_id")
		request.GraphRootUrn = r.URL.Query().Get("graph_root_urn")
	}
	response, err := a.findingService().ListEvidence(r.Context(), findings.ListEvidenceRequest{
		RuntimeID:    request.GetRuntimeId(),
		FindingID:    request.GetFindingId(),
		RunID:        request.GetRunId(),
		RuleID:       request.GetRuleId(),
		ClaimID:      request.GetClaimId(),
		EventID:      request.GetEventId(),
		GraphRootURN: request.GetGraphRootUrn(),
		Limit:        request.GetLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ListFindingEvidenceResponse{
		Evidence: response.Evidence,
	})
}

func (a *App) handleListFindingEvaluationRuns(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingEvaluationRunsRequest{
		RuntimeId: r.PathValue("runtimeID"),
		RuleId:    r.URL.Query().Get("rule_id"),
		Status:    r.URL.Query().Get("status"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.Status = r.URL.Query().Get("status")
	}
	response, err := a.findingService().ListEvaluationRuns(r.Context(), findings.ListEvaluationRunsRequest{
		RuntimeID: request.GetRuntimeId(),
		RuleID:    request.GetRuleId(),
		Status:    request.GetStatus(),
		Limit:     request.GetLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ListFindingEvaluationRunsResponse{
		Runs: response.Runs,
	})
}

func (s *bootstrapService) GetVersion(_ context.Context, _ *connect.Request[cerebrov1.GetVersionRequest]) (*connect.Response[cerebrov1.GetVersionResponse], error) {
	return connect.NewResponse(&cerebrov1.GetVersionResponse{
		ServiceName: buildinfo.ServiceName,
		Version:     buildinfo.Version,
		Commit:      buildinfo.Commit,
		BuildDate:   buildinfo.BuildDate,
		ApiVersion:  buildinfo.APIVersion,
	}), nil
}

func (s *bootstrapService) CheckHealth(ctx context.Context, _ *connect.Request[cerebrov1.CheckHealthRequest]) (*connect.Response[cerebrov1.CheckHealthResponse], error) {
	return connect.NewResponse(healthResponse(ctx, s.deps)), nil
}

func (s *bootstrapService) ListReportDefinitions(_ context.Context, _ *connect.Request[cerebrov1.ListReportDefinitionsRequest]) (*connect.Response[cerebrov1.ListReportDefinitionsResponse], error) {
	return connect.NewResponse(reports.New(
		findingStore(s.deps.StateStore),
		graphQueryStore(s.deps.GraphStore),
		reportStore(s.deps.StateStore),
	).List()), nil
}

func (s *bootstrapService) ListFindingRules(_ context.Context, _ *connect.Request[cerebrov1.ListFindingRulesRequest]) (*connect.Response[cerebrov1.ListFindingRulesResponse], error) {
	return connect.NewResponse(findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).ListRules()), nil
}

func (s *bootstrapService) RunReport(ctx context.Context, req *connect.Request[cerebrov1.RunReportRequest]) (*connect.Response[cerebrov1.RunReportResponse], error) {
	response, err := reports.New(
		findingStore(s.deps.StateStore),
		graphQueryStore(s.deps.GraphStore),
		reportStore(s.deps.StateStore),
	).Run(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) GetReportRun(ctx context.Context, req *connect.Request[cerebrov1.GetReportRunRequest]) (*connect.Response[cerebrov1.GetReportRunResponse], error) {
	response, err := reports.New(
		findingStore(s.deps.StateStore),
		graphQueryStore(s.deps.GraphStore),
		reportStore(s.deps.StateStore),
	).Get(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) ListSources(_ context.Context, _ *connect.Request[cerebrov1.ListSourcesRequest]) (*connect.Response[cerebrov1.ListSourcesResponse], error) {
	return connect.NewResponse(sourceops.New(s.sources).List()), nil
}

func (s *bootstrapService) CheckSource(ctx context.Context, req *connect.Request[cerebrov1.CheckSourceRequest]) (*connect.Response[cerebrov1.CheckSourceResponse], error) {
	response, err := sourceops.New(s.sources).Check(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) DiscoverSource(ctx context.Context, req *connect.Request[cerebrov1.DiscoverSourceRequest]) (*connect.Response[cerebrov1.DiscoverSourceResponse], error) {
	response, err := sourceops.New(s.sources).Discover(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) ReadSource(ctx context.Context, req *connect.Request[cerebrov1.ReadSourceRequest]) (*connect.Response[cerebrov1.ReadSourceResponse], error) {
	response, err := sourceops.New(s.sources).Read(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) PutSourceRuntime(ctx context.Context, req *connect.Request[cerebrov1.PutSourceRuntimeRequest]) (*connect.Response[cerebrov1.PutSourceRuntimeResponse], error) {
	response, err := sourceruntime.New(
		s.sources,
		sourceRuntimeStore(s.deps.StateStore),
		s.deps.AppendLog,
		sourceProjector(s.deps.StateStore, s.deps.GraphStore),
	).Put(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) GetSourceRuntime(ctx context.Context, req *connect.Request[cerebrov1.GetSourceRuntimeRequest]) (*connect.Response[cerebrov1.GetSourceRuntimeResponse], error) {
	response, err := sourceruntime.New(
		s.sources,
		sourceRuntimeStore(s.deps.StateStore),
		s.deps.AppendLog,
		sourceProjector(s.deps.StateStore, s.deps.GraphStore),
	).Get(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) SyncSourceRuntime(ctx context.Context, req *connect.Request[cerebrov1.SyncSourceRuntimeRequest]) (*connect.Response[cerebrov1.SyncSourceRuntimeResponse], error) {
	response, err := sourceruntime.New(
		s.sources,
		sourceRuntimeStore(s.deps.StateStore),
		s.deps.AppendLog,
		sourceProjector(s.deps.StateStore, s.deps.GraphStore),
	).Sync(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) WriteClaims(ctx context.Context, req *connect.Request[cerebrov1.WriteClaimsRequest]) (*connect.Response[cerebrov1.WriteClaimsResponse], error) {
	response, err := claims.New(
		sourceRuntimeStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
		sourceProjectionStateStore(s.deps.StateStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WriteClaims(ctx, claims.WriteRequest{
		RuntimeID:       req.Msg.GetRuntimeId(),
		Claims:          req.Msg.GetClaims(),
		ReplaceExisting: req.Msg.GetReplaceExisting(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.WriteClaimsResponse{
		ClaimsWritten:          response.ClaimsWritten,
		EntitiesUpserted:       response.EntitiesUpserted,
		RelationLinksProjected: response.RelationLinksProjected,
		ClaimsRetracted:        response.ClaimsRetracted,
	}), nil
}

func (s *bootstrapService) ListClaims(ctx context.Context, req *connect.Request[cerebrov1.ListClaimsRequest]) (*connect.Response[cerebrov1.ListClaimsResponse], error) {
	response, err := claims.New(
		sourceRuntimeStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
		sourceProjectionStateStore(s.deps.StateStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).ListClaims(ctx, claims.ListRequest{
		RuntimeID:     req.Msg.GetRuntimeId(),
		ClaimID:       req.Msg.GetClaimId(),
		SubjectURN:    req.Msg.GetSubjectUrn(),
		Predicate:     req.Msg.GetPredicate(),
		ObjectURN:     req.Msg.GetObjectUrn(),
		ObjectValue:   req.Msg.GetObjectValue(),
		ClaimType:     req.Msg.GetClaimType(),
		Status:        req.Msg.GetStatus(),
		SourceEventID: req.Msg.GetSourceEventId(),
		Limit:         req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.ListClaimsResponse{
		Claims: response.Claims,
	}), nil
}

func (s *bootstrapService) ListFindings(ctx context.Context, req *connect.Request[cerebrov1.ListFindingsRequest]) (*connect.Response[cerebrov1.ListFindingsResponse], error) {
	response, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).ListFindings(ctx, findings.ListRequest{
		RuntimeID:   req.Msg.GetRuntimeId(),
		FindingID:   req.Msg.GetFindingId(),
		RuleID:      req.Msg.GetRuleId(),
		Severity:    req.Msg.GetSeverity(),
		Status:      findingStatusString(req.Msg.GetStatus()),
		ResourceURN: req.Msg.GetResourceUrn(),
		EventID:     req.Msg.GetEventId(),
		PolicyID:    req.Msg.GetPolicyId(),
		Limit:       req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(listFindingsResponse(response)), nil
}

func (s *bootstrapService) GetFinding(ctx context.Context, req *connect.Request[cerebrov1.GetFindingRequest]) (*connect.Response[cerebrov1.GetFindingResponse], error) {
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).GetFinding(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.GetFindingResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) ResolveFinding(ctx context.Context, req *connect.Request[cerebrov1.ResolveFindingRequest]) (*connect.Response[cerebrov1.ResolveFindingResponse], error) {
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(s.deps.GraphStore)).WithGraphQueryStore(graphQueryStore(s.deps.GraphStore)).WithAppendLog(s.deps.AppendLog).ResolveFinding(ctx, req.Msg.GetId(), req.Msg.GetReason())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.ResolveFindingResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) SuppressFinding(ctx context.Context, req *connect.Request[cerebrov1.SuppressFindingRequest]) (*connect.Response[cerebrov1.SuppressFindingResponse], error) {
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(s.deps.GraphStore)).WithGraphQueryStore(graphQueryStore(s.deps.GraphStore)).WithAppendLog(s.deps.AppendLog).SuppressFinding(ctx, req.Msg.GetId(), req.Msg.GetReason())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.SuppressFindingResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) AssignFinding(ctx context.Context, req *connect.Request[cerebrov1.AssignFindingRequest]) (*connect.Response[cerebrov1.AssignFindingResponse], error) {
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).AssignFinding(ctx, req.Msg.GetId(), req.Msg.GetAssignee())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.AssignFindingResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) SetFindingDueDate(ctx context.Context, req *connect.Request[cerebrov1.SetFindingDueDateRequest]) (*connect.Response[cerebrov1.SetFindingDueDateResponse], error) {
	var dueAt time.Time
	if req.Msg.GetDueAt() != nil {
		dueAt = req.Msg.GetDueAt().AsTime()
	}
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).SetFindingDueDate(ctx, req.Msg.GetId(), dueAt)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.SetFindingDueDateResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) AddFindingNote(ctx context.Context, req *connect.Request[cerebrov1.AddFindingNoteRequest]) (*connect.Response[cerebrov1.AddFindingNoteResponse], error) {
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(s.deps.GraphStore)).WithGraphQueryStore(graphQueryStore(s.deps.GraphStore)).WithAppendLog(s.deps.AppendLog).AddFindingNote(ctx, req.Msg.GetId(), req.Msg.GetNote())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.AddFindingNoteResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) LinkFindingTicket(ctx context.Context, req *connect.Request[cerebrov1.LinkFindingTicketRequest]) (*connect.Response[cerebrov1.LinkFindingTicketResponse], error) {
	finding, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(s.deps.GraphStore)).WithGraphQueryStore(graphQueryStore(s.deps.GraphStore)).WithAppendLog(s.deps.AppendLog).LinkFindingTicket(
		ctx,
		req.Msg.GetId(),
		req.Msg.GetUrl(),
		req.Msg.GetName(),
		req.Msg.GetExternalId(),
	)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.LinkFindingTicketResponse{Finding: findingMessage(finding)}), nil
}

func (s *bootstrapService) ListFindingEvidence(ctx context.Context, req *connect.Request[cerebrov1.ListFindingEvidenceRequest]) (*connect.Response[cerebrov1.ListFindingEvidenceResponse], error) {
	response, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).ListEvidence(ctx, findings.ListEvidenceRequest{
		RuntimeID:    req.Msg.GetRuntimeId(),
		FindingID:    req.Msg.GetFindingId(),
		RunID:        req.Msg.GetRunId(),
		RuleID:       req.Msg.GetRuleId(),
		ClaimID:      req.Msg.GetClaimId(),
		EventID:      req.Msg.GetEventId(),
		GraphRootURN: req.Msg.GetGraphRootUrn(),
		Limit:        req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.ListFindingEvidenceResponse{
		Evidence: response.Evidence,
	}), nil
}

func (s *bootstrapService) ListFindingEvaluationRuns(ctx context.Context, req *connect.Request[cerebrov1.ListFindingEvaluationRunsRequest]) (*connect.Response[cerebrov1.ListFindingEvaluationRunsResponse], error) {
	response, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).ListEvaluationRuns(ctx, findings.ListEvaluationRunsRequest{
		RuntimeID: req.Msg.GetRuntimeId(),
		RuleID:    req.Msg.GetRuleId(),
		Status:    req.Msg.GetStatus(),
		Limit:     req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.ListFindingEvaluationRunsResponse{
		Runs: response.Runs,
	}), nil
}

func (s *bootstrapService) GetFindingEvaluationRun(ctx context.Context, req *connect.Request[cerebrov1.GetFindingEvaluationRunRequest]) (*connect.Response[cerebrov1.GetFindingEvaluationRunResponse], error) {
	run, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).GetEvaluationRun(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.GetFindingEvaluationRunResponse{Run: run}), nil
}

func (s *bootstrapService) GetFindingEvidence(ctx context.Context, req *connect.Request[cerebrov1.GetFindingEvidenceRequest]) (*connect.Response[cerebrov1.GetFindingEvidenceResponse], error) {
	evidence, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).GetEvidence(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.GetFindingEvidenceResponse{Evidence: evidence}), nil
}

func (s *bootstrapService) EvaluateSourceRuntimeFindingRules(ctx context.Context, req *connect.Request[cerebrov1.EvaluateSourceRuntimeFindingRulesRequest]) (*connect.Response[cerebrov1.EvaluateSourceRuntimeFindingRulesResponse], error) {
	response, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID:  req.Msg.GetId(),
		RuleIDs:    req.Msg.GetRuleIds(),
		EventLimit: req.Msg.GetEventLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(findingRulesResponse(response)), nil
}

func (s *bootstrapService) EvaluateSourceRuntimeFindings(ctx context.Context, req *connect.Request[cerebrov1.EvaluateSourceRuntimeFindingsRequest]) (*connect.Response[cerebrov1.EvaluateSourceRuntimeFindingsResponse], error) {
	response, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
		findingEvaluationRunStore(s.deps.StateStore),
		findingEvidenceStore(s.deps.StateStore),
		claimStore(s.deps.StateStore),
	).EvaluateSourceRuntime(ctx, findings.EvaluateRequest{
		RuntimeID:  req.Msg.GetId(),
		RuleID:     req.Msg.GetRuleId(),
		EventLimit: req.Msg.GetEventLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(findingResponse(response)), nil
}

func (s *bootstrapService) WriteDecision(ctx context.Context, req *connect.Request[cerebrov1.WriteDecisionRequest]) (*connect.Response[cerebrov1.WriteDecisionResponse], error) {
	metadata := map[string]any{}
	if req.Msg.GetMetadata() != nil {
		metadata = req.Msg.GetMetadata().AsMap()
	}
	result, err := knowledge.New(
		graphQueryStore(s.deps.GraphStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WithAppendLog(s.deps.AppendLog).WriteDecision(ctx, knowledge.DecisionWriteRequest{
		ID:            req.Msg.GetId(),
		DecisionType:  req.Msg.GetDecisionType(),
		Status:        req.Msg.GetStatus(),
		MadeBy:        req.Msg.GetMadeBy(),
		Rationale:     req.Msg.GetRationale(),
		TargetIDs:     req.Msg.GetTargetIds(),
		EvidenceIDs:   req.Msg.GetEvidenceIds(),
		ActionIDs:     req.Msg.GetActionIds(),
		SourceSystem:  req.Msg.GetSourceSystem(),
		SourceEventID: req.Msg.GetSourceEventId(),
		ObservedAt:    timestampValue(req.Msg.GetObservedAt()),
		ValidFrom:     timestampValue(req.Msg.GetValidFrom()),
		ValidTo:       timestampValue(req.Msg.GetValidTo()),
		Confidence:    req.Msg.GetConfidence(),
		Metadata:      metadata,
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.WriteDecisionResponse{
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	}), nil
}

func (s *bootstrapService) WriteAction(ctx context.Context, req *connect.Request[cerebrov1.WriteActionRequest]) (*connect.Response[cerebrov1.WriteActionResponse], error) {
	metadata := map[string]any{}
	if req.Msg.GetMetadata() != nil {
		metadata = req.Msg.GetMetadata().AsMap()
	}
	result, err := knowledge.New(
		graphQueryStore(s.deps.GraphStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WithAppendLog(s.deps.AppendLog).WriteAction(ctx, knowledge.ActionWriteRequest{
		ID:               req.Msg.GetId(),
		RecommendationID: req.Msg.GetRecommendationId(),
		InsightType:      req.Msg.GetInsightType(),
		Title:            req.Msg.GetTitle(),
		Summary:          req.Msg.GetSummary(),
		DecisionID:       req.Msg.GetDecisionId(),
		TargetIDs:        req.Msg.GetTargetIds(),
		SourceSystem:     req.Msg.GetSourceSystem(),
		SourceEventID:    req.Msg.GetSourceEventId(),
		ObservedAt:       timestampValue(req.Msg.GetObservedAt()),
		ValidFrom:        timestampValue(req.Msg.GetValidFrom()),
		ValidTo:          timestampValue(req.Msg.GetValidTo()),
		Confidence:       req.Msg.GetConfidence(),
		AutoGenerated:    req.Msg.GetAutoGenerated(),
		Metadata:         metadata,
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.WriteActionResponse{
		ActionId:    result.ActionID,
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	}), nil
}

func (s *bootstrapService) WriteOutcome(ctx context.Context, req *connect.Request[cerebrov1.WriteOutcomeRequest]) (*connect.Response[cerebrov1.WriteOutcomeResponse], error) {
	metadata := map[string]any{}
	if req.Msg.GetMetadata() != nil {
		metadata = req.Msg.GetMetadata().AsMap()
	}
	result, err := knowledge.New(
		graphQueryStore(s.deps.GraphStore),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).WithAppendLog(s.deps.AppendLog).WriteOutcome(ctx, knowledge.OutcomeWriteRequest{
		ID:            req.Msg.GetId(),
		DecisionID:    req.Msg.GetDecisionId(),
		OutcomeType:   req.Msg.GetOutcomeType(),
		Verdict:       req.Msg.GetVerdict(),
		ImpactScore:   req.Msg.GetImpactScore(),
		TargetIDs:     req.Msg.GetTargetIds(),
		SourceSystem:  req.Msg.GetSourceSystem(),
		SourceEventID: req.Msg.GetSourceEventId(),
		ObservedAt:    timestampValue(req.Msg.GetObservedAt()),
		ValidFrom:     timestampValue(req.Msg.GetValidFrom()),
		ValidTo:       timestampValue(req.Msg.GetValidTo()),
		Confidence:    req.Msg.GetConfidence(),
		Metadata:      metadata,
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&cerebrov1.WriteOutcomeResponse{
		OutcomeId:   result.OutcomeID,
		DecisionId:  result.DecisionID,
		TargetCount: result.TargetCount,
	}), nil
}

func (s *bootstrapService) ReplayWorkflowEvents(ctx context.Context, req *connect.Request[cerebrov1.ReplayWorkflowEventsRequest]) (*connect.Response[cerebrov1.ReplayWorkflowEventsResponse], error) {
	result, err := workflowprojection.NewReplayer(
		eventReplayer(s.deps.AppendLog),
		sourceProjectionGraphStore(s.deps.GraphStore),
	).Replay(ctx, workflowprojection.ReplayRequest{
		KindPrefix:      req.Msg.GetKindPrefix(),
		TenantID:        req.Msg.GetTenantId(),
		AttributeEquals: req.Msg.GetAttributeEquals(),
		Limit:           req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(workflowReplayResponse(result)), nil
}

func (s *bootstrapService) GetEntityNeighborhood(ctx context.Context, req *connect.Request[cerebrov1.GetEntityNeighborhoodRequest]) (*connect.Response[cerebrov1.GetEntityNeighborhoodResponse], error) {
	response, err := graphquery.New(
		graphQueryStore(s.deps.GraphStore),
	).GetEntityNeighborhood(ctx, graphquery.NeighborhoodRequest{
		RootURN: req.Msg.GetRootUrn(),
		Limit:   req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(graphNeighborhoodResponse(response)), nil
}

func healthResponse(ctx context.Context, deps Dependencies) *cerebrov1.CheckHealthResponse {
	components := []*cerebrov1.ComponentStatus{
		componentStatus(ctx, "append_log", deps.AppendLog),
		componentStatus(ctx, "state_store", deps.StateStore),
		componentStatus(ctx, "graph_store", deps.GraphStore),
	}
	status := "ready"
	for _, component := range components {
		if component.Status == "error" {
			status = "degraded"
			break
		}
	}
	return &cerebrov1.CheckHealthResponse{
		Status:     status,
		CheckedAt:  timestamppb.Now(),
		Components: components,
	}
}

func writeProtoJSON(w http.ResponseWriter, statusCode int, message proto.Message) {
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func (a *App) sourceService() *sourceops.Service {
	return sourceops.New(a.sources)
}

func (a *App) reportService() *reports.Service {
	return reports.New(
		findingStore(a.deps.StateStore),
		graphQueryStore(a.deps.GraphStore),
		reportStore(a.deps.StateStore),
	)
}

func (a *App) runtimeService() *sourceruntime.Service {
	return sourceruntime.New(
		a.sources,
		sourceRuntimeStore(a.deps.StateStore),
		a.deps.AppendLog,
		sourceProjector(a.deps.StateStore, a.deps.GraphStore),
	)
}

func (a *App) claimService() *claims.Service {
	return claims.New(
		sourceRuntimeStore(a.deps.StateStore),
		claimStore(a.deps.StateStore),
		sourceProjectionStateStore(a.deps.StateStore),
		sourceProjectionGraphStore(a.deps.GraphStore),
	)
}

func (a *App) findingService() *findings.Service {
	return findings.New(
		sourceRuntimeStore(a.deps.StateStore),
		eventReplayer(a.deps.AppendLog),
		findingStore(a.deps.StateStore),
		findingEvaluationRunStore(a.deps.StateStore),
		findingEvidenceStore(a.deps.StateStore),
		claimStore(a.deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(a.deps.GraphStore)).WithGraphQueryStore(graphQueryStore(a.deps.GraphStore)).WithAppendLog(a.deps.AppendLog)
}

func (a *App) knowledgeService() *knowledge.Service {
	return knowledge.New(
		graphQueryStore(a.deps.GraphStore),
		sourceProjectionGraphStore(a.deps.GraphStore),
	).WithAppendLog(a.deps.AppendLog)
}

func (a *App) graphQueryService() *graphquery.Service {
	return graphquery.New(graphQueryStore(a.deps.GraphStore))
}

func (a *App) workflowReplayService() *workflowprojection.Replayer {
	return workflowprojection.NewReplayer(
		eventReplayer(a.deps.AppendLog),
		sourceProjectionGraphStore(a.deps.GraphStore),
	)
}

func sourceConfigFromRequest(r *http.Request) (map[string]string, error) {
	values := make(map[string]string)
	for key, rawValues := range r.URL.Query() {
		if key == "cursor" || len(rawValues) == 0 {
			continue
		}
		if sensitiveSourceConfigKey(key) {
			return nil, fmt.Errorf("source config key %q must not be supplied in query parameters", key)
		}
		values[key] = rawValues[len(rawValues)-1]
	}
	if rawConfig := strings.TrimSpace(r.Header.Get("X-Cerebro-Source-Config")); rawConfig != "" {
		headerValues := map[string]string{}
		if err := json.Unmarshal([]byte(rawConfig), &headerValues); err != nil {
			return nil, fmt.Errorf("decode source config header: %w", err)
		}
		for key, value := range headerValues {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey != "" {
				values[trimmedKey] = value
			}
		}
	}
	return values, nil
}

func sensitiveSourceConfigKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(value, "token") || strings.Contains(value, "secret") || strings.Contains(value, "password")
}

func writeSourceError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	if errors.Is(err, sourceops.ErrSourceNotFound) {
		statusCode = http.StatusNotFound
	}
	http.Error(w, err.Error(), statusCode)
}

func writeReportError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, reports.ErrReportNotFound), errors.Is(err, ports.ErrReportRunNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, reports.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeSourceRuntimeError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, ports.ErrSourceRuntimeNotFound), errors.Is(err, sourceops.ErrSourceNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeClaimError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, claims.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeFindingError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, findings.ErrRuleNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, ports.ErrFindingNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, ports.ErrFindingEvaluationRunNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, ports.ErrFindingEvidenceNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, findings.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeKnowledgeError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, ports.ErrGraphEntityNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, knowledge.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeGraphQueryError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, ports.ErrGraphEntityNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, graphquery.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeWorkflowReplayError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	if errors.Is(err, workflowprojection.ErrRuntimeUnavailable) {
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func timestampValue(value *timestamppb.Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime()
}
func readProtoJSON(r *http.Request, message proto.Message) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return protojson.Unmarshal(body, message)
}

func sourceRuntimeStore(store ports.StateStore) ports.SourceRuntimeStore {
	runtimeStore, ok := store.(ports.SourceRuntimeStore)
	if !ok {
		return nil
	}
	return runtimeStore
}

func sourceProjectionStateStore(store ports.StateStore) ports.ProjectionStateStore {
	projectionStore, ok := store.(ports.ProjectionStateStore)
	if !ok {
		return nil
	}
	return projectionStore
}

func sourceProjectionGraphStore(store ports.GraphStore) ports.ProjectionGraphStore {
	projectionStore, ok := store.(ports.ProjectionGraphStore)
	if !ok {
		return nil
	}
	return projectionStore
}

func sourceProjector(stateStore ports.StateStore, graphStore ports.GraphStore) ports.SourceProjector {
	state := sourceProjectionStateStore(stateStore)
	graph := sourceProjectionGraphStore(graphStore)
	if state == nil && graph == nil {
		return nil
	}
	return sourceprojection.New(state, graph)
}

func graphQueryStore(store ports.GraphStore) ports.GraphQueryStore {
	queryStore, ok := store.(ports.GraphQueryStore)
	if !ok {
		return nil
	}
	return queryStore
}

func findingStore(store ports.StateStore) ports.FindingStore {
	findingStore, ok := store.(ports.FindingStore)
	if !ok {
		return nil
	}
	return findingStore
}

func findingEvaluationRunStore(store ports.StateStore) ports.FindingEvaluationRunStore {
	runStore, ok := store.(ports.FindingEvaluationRunStore)
	if !ok {
		return nil
	}
	return runStore
}

func findingEvidenceStore(store ports.StateStore) ports.FindingEvidenceStore {
	evidenceStore, ok := store.(ports.FindingEvidenceStore)
	if !ok {
		return nil
	}
	return evidenceStore
}

func claimStore(store ports.StateStore) ports.ClaimStore {
	claimStore, ok := store.(ports.ClaimStore)
	if !ok {
		return nil
	}
	return claimStore
}

func reportStore(store ports.StateStore) ports.ReportStore {
	reportStore, ok := store.(ports.ReportStore)
	if !ok {
		return nil
	}
	return reportStore
}

func eventReplayer(appendLog ports.AppendLog) ports.EventReplayer {
	replayer, ok := appendLog.(ports.EventReplayer)
	if !ok {
		return nil
	}
	return replayer
}

func findingResponse(result *findings.EvaluateResult) *cerebrov1.EvaluateSourceRuntimeFindingsResponse {
	if result == nil {
		return &cerebrov1.EvaluateSourceRuntimeFindingsResponse{}
	}
	response := &cerebrov1.EvaluateSourceRuntimeFindingsResponse{
		Runtime:          result.Runtime,
		Rule:             result.Rule,
		EventsEvaluated:  result.EventsEvaluated,
		FindingsUpserted: uint32(len(result.Findings)),
		Findings:         findingMessages(result.Findings),
		Run:              result.Run,
		Evidence:         result.Evidence,
	}
	return response
}

func findingRulesResponse(result *findings.EvaluateRulesResult) *cerebrov1.EvaluateSourceRuntimeFindingRulesResponse {
	if result == nil {
		return &cerebrov1.EvaluateSourceRuntimeFindingRulesResponse{}
	}
	evaluations := make([]*cerebrov1.FindingRuleEvaluation, 0, len(result.Evaluations))
	for _, evaluation := range result.Evaluations {
		evaluations = append(evaluations, findingRuleEvaluationMessage(evaluation))
	}
	return &cerebrov1.EvaluateSourceRuntimeFindingRulesResponse{
		Runtime:         result.Runtime,
		EventsEvaluated: result.EventsEvaluated,
		Evaluations:     evaluations,
	}
}

func findingRuleEvaluationMessage(result *findings.RuleEvaluationResult) *cerebrov1.FindingRuleEvaluation {
	if result == nil {
		return &cerebrov1.FindingRuleEvaluation{}
	}
	return &cerebrov1.FindingRuleEvaluation{
		Rule:     result.Rule,
		Findings: findingMessages(result.Findings),
		Run:      result.Run,
		Evidence: result.Evidence,
	}
}

func listFindingsResponse(result *findings.ListResult) *cerebrov1.ListFindingsResponse {
	if result == nil {
		return &cerebrov1.ListFindingsResponse{}
	}
	return &cerebrov1.ListFindingsResponse{
		Findings: findingMessages(result.Findings),
	}
}

func findingMessages(findings []*ports.FindingRecord) []*cerebrov1.Finding {
	messages := make([]*cerebrov1.Finding, 0, len(findings))
	for _, finding := range findings {
		messages = append(messages, findingMessage(finding))
	}
	return messages
}

func findingMessage(finding *ports.FindingRecord) *cerebrov1.Finding {
	if finding == nil {
		return nil
	}
	message := &cerebrov1.Finding{
		Id:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantId:          finding.TenantID,
		RuntimeId:         finding.RuntimeID,
		RuleId:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            findingStatusMessage(finding.Status),
		Summary:           finding.Summary,
		ResourceUrns:      append([]string(nil), finding.ResourceURNs...),
		EventIds:          append([]string(nil), finding.EventIDs...),
		ObservedPolicyIds: append([]string(nil), finding.ObservedPolicyIDs...),
		PolicyId:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckId:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       findingControlRefMessages(finding.ControlRefs),
		Notes:             findingNoteMessages(finding.Notes),
		Tickets:           findingTicketMessages(finding.Tickets),
		Attributes:        make(map[string]string, len(finding.Attributes)),
		Assignee:          finding.Assignee,
		StatusReason:      finding.StatusReason,
	}
	for key, value := range finding.Attributes {
		message.Attributes[key] = value
	}
	if !finding.StatusUpdatedAt.IsZero() {
		message.StatusUpdatedAt = timestamppb.New(finding.StatusUpdatedAt)
	}
	if !finding.DueAt.IsZero() {
		message.DueAt = timestamppb.New(finding.DueAt)
	}
	if !finding.FirstObservedAt.IsZero() {
		message.FirstObservedAt = timestamppb.New(finding.FirstObservedAt)
	}
	if !finding.LastObservedAt.IsZero() {
		message.LastObservedAt = timestamppb.New(finding.LastObservedAt)
	}
	return message
}

func findingControlRefMessages(values []ports.FindingControlRef) []*cerebrov1.FindingControlRef {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingControlRef, 0, len(values))
	for _, value := range values {
		frameworkName := strings.TrimSpace(value.FrameworkName)
		controlID := strings.TrimSpace(value.ControlID)
		if frameworkName == "" || controlID == "" {
			continue
		}
		messages = append(messages, &cerebrov1.FindingControlRef{
			FrameworkName: frameworkName,
			ControlId:     controlID,
		})
	}
	return messages
}

func findingNoteMessages(values []ports.FindingNote) []*cerebrov1.FindingNote {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingNote, 0, len(values))
	for _, value := range values {
		body := strings.TrimSpace(value.Body)
		if body == "" {
			continue
		}
		message := &cerebrov1.FindingNote{
			Id:   strings.TrimSpace(value.ID),
			Body: body,
		}
		if !value.CreatedAt.IsZero() {
			message.CreatedAt = timestamppb.New(value.CreatedAt)
		}
		messages = append(messages, message)
	}
	return messages
}

func findingTicketMessages(values []ports.FindingTicket) []*cerebrov1.FindingTicket {
	if len(values) == 0 {
		return nil
	}
	messages := make([]*cerebrov1.FindingTicket, 0, len(values))
	for _, value := range values {
		url := strings.TrimSpace(value.URL)
		if url == "" {
			continue
		}
		message := &cerebrov1.FindingTicket{
			Url:        url,
			Name:       strings.TrimSpace(value.Name),
			ExternalId: strings.TrimSpace(value.ExternalID),
		}
		if !value.LinkedAt.IsZero() {
			message.LinkedAt = timestamppb.New(value.LinkedAt)
		}
		messages = append(messages, message)
	}
	return messages
}

func findingStatusMessage(status string) cerebrov1.FindingStatus {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open":
		return cerebrov1.FindingStatus_FINDING_STATUS_OPEN
	case "resolved":
		return cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED
	case "suppressed":
		return cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED
	default:
		return cerebrov1.FindingStatus_FINDING_STATUS_UNSPECIFIED
	}
}

func findingStatusString(status cerebrov1.FindingStatus) string {
	switch status {
	case cerebrov1.FindingStatus_FINDING_STATUS_OPEN:
		return "open"
	case cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED:
		return "resolved"
	case cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED:
		return "suppressed"
	default:
		return ""
	}
}

func parseFindingStatus(raw string) (cerebrov1.FindingStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "open", "finding_status_open":
		return cerebrov1.FindingStatus_FINDING_STATUS_OPEN, nil
	case "resolved", "finding_status_resolved":
		return cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED, nil
	case "suppressed", "finding_status_suppressed":
		return cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED, nil
	default:
		return cerebrov1.FindingStatus_FINDING_STATUS_UNSPECIFIED, fmt.Errorf("unsupported finding status %q", raw)
	}
}

func workflowReplayResponse(result *workflowprojection.ReplayResult) *cerebrov1.ReplayWorkflowEventsResponse {
	if result == nil {
		return &cerebrov1.ReplayWorkflowEventsResponse{}
	}
	return &cerebrov1.ReplayWorkflowEventsResponse{
		EventsRead:        result.EventsRead,
		EventsProjected:   result.EventsProjected,
		EntitiesProjected: result.EntitiesProjected,
		LinksProjected:    result.LinksProjected,
	}
}

func graphNeighborhoodResponse(neighborhood *ports.EntityNeighborhood) *cerebrov1.GetEntityNeighborhoodResponse {
	if neighborhood == nil {
		return &cerebrov1.GetEntityNeighborhoodResponse{}
	}
	response := &cerebrov1.GetEntityNeighborhoodResponse{
		Root:      graphEntityMessage(neighborhood.Root),
		Neighbors: make([]*cerebrov1.GraphEntity, 0, len(neighborhood.Neighbors)),
		Relations: make([]*cerebrov1.GraphRelation, 0, len(neighborhood.Relations)),
	}
	for _, neighbor := range neighborhood.Neighbors {
		response.Neighbors = append(response.Neighbors, graphEntityMessage(neighbor))
	}
	for _, relation := range neighborhood.Relations {
		response.Relations = append(response.Relations, graphRelationMessage(relation))
	}
	return response
}

func graphEntityMessage(node *ports.NeighborhoodNode) *cerebrov1.GraphEntity {
	if node == nil {
		return nil
	}
	return &cerebrov1.GraphEntity{
		Urn:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func graphRelationMessage(relation *ports.NeighborhoodRelation) *cerebrov1.GraphRelation {
	if relation == nil {
		return nil
	}
	return &cerebrov1.GraphRelation{
		FromUrn:  relation.FromURN,
		Relation: relation.Relation,
		ToUrn:    relation.ToURN,
	}
}

type pinger interface {
	Ping(context.Context) error
}

func componentStatus(ctx context.Context, name string, dependency pinger) *cerebrov1.ComponentStatus {
	status := &cerebrov1.ComponentStatus{Name: name, Status: "unconfigured"}
	if dependency == nil {
		return status
	}
	if err := dependency.Ping(ctx); err != nil {
		status.Status = "error"
		status.Detail = "unhealthy"
		return status
	}
	status.Status = "ready"
	return status
}
