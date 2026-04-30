package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceruntime"
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
	mux.HandleFunc("POST /reports/{reportID}/runs", app.handleRunReport)
	mux.HandleFunc("GET /report-runs/{runID}", app.handleGetReportRun)
	mux.HandleFunc("/sources", app.handleSources)
	mux.HandleFunc("GET /sources/{sourceID}/check", app.handleCheckSource)
	mux.HandleFunc("GET /sources/{sourceID}/discover", app.handleDiscoverSource)
	mux.HandleFunc("GET /sources/{sourceID}/read", app.handleReadSource)
	mux.HandleFunc("GET /graph/neighborhood", app.handleGetEntityNeighborhood)
	mux.HandleFunc("PUT /source-runtimes/{runtimeID}", app.handlePutSourceRuntime)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}", app.handleGetSourceRuntime)
	mux.HandleFunc("POST /source-runtimes/{runtimeID}/sync", app.handleSyncSourceRuntime)
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
	for key, value := range sourceConfigFromQuery(r) {
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
	response, err := a.sourceService().Check(r.Context(), &cerebrov1.CheckSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   sourceConfigFromQuery(r),
	})
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleDiscoverSource(w http.ResponseWriter, r *http.Request) {
	response, err := a.sourceService().Discover(r.Context(), &cerebrov1.DiscoverSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   sourceConfigFromQuery(r),
	})
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleReadSource(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ReadSourceRequest{
		SourceId: r.PathValue("sourceID"),
		Config:   sourceConfigFromQuery(r),
	}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		request.Cursor = &cerebrov1.SourceCursor{Opaque: cursor}
	}
	response, err := a.sourceService().Read(r.Context(), request)
	if err != nil {
		writeSourceError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleGetEntityNeighborhood(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.GetEntityNeighborhoodRequest{}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

func (a *App) handleEvaluateSourceRuntimeFindings(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.EvaluateSourceRuntimeFindingsRequest{}
	if eventLimit := r.URL.Query().Get("event_limit"); eventLimit != "" {
		body := []byte(`{"event_limit":` + eventLimit + `}`)
		if err := protojson.Unmarshal(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
	}
	request.Id = r.PathValue("runtimeID")
	response, err := a.findingService().EvaluateSourceRuntime(r.Context(), findings.EvaluateRequest{
		RuntimeID:  request.GetId(),
		EventLimit: request.GetEventLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, findingResponse(response))
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
		reportStore(s.deps.StateStore),
	).List()), nil
}

func (s *bootstrapService) RunReport(ctx context.Context, req *connect.Request[cerebrov1.RunReportRequest]) (*connect.Response[cerebrov1.RunReportResponse], error) {
	response, err := reports.New(
		findingStore(s.deps.StateStore),
		reportStore(s.deps.StateStore),
	).Run(ctx, req.Msg)
	if err != nil {
		return nil, reportConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) GetReportRun(ctx context.Context, req *connect.Request[cerebrov1.GetReportRunRequest]) (*connect.Response[cerebrov1.GetReportRunResponse], error) {
	response, err := reports.New(
		findingStore(s.deps.StateStore),
		reportStore(s.deps.StateStore),
	).Get(ctx, req.Msg)
	if err != nil {
		return nil, reportConnectError(err)
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

func (s *bootstrapService) EvaluateSourceRuntimeFindings(ctx context.Context, req *connect.Request[cerebrov1.EvaluateSourceRuntimeFindingsRequest]) (*connect.Response[cerebrov1.EvaluateSourceRuntimeFindingsResponse], error) {
	response, err := findings.New(
		sourceRuntimeStore(s.deps.StateStore),
		eventReplayer(s.deps.AppendLog),
		findingStore(s.deps.StateStore),
	).EvaluateSourceRuntime(ctx, findings.EvaluateRequest{
		RuntimeID:  req.Msg.GetId(),
		EventLimit: req.Msg.GetEventLimit(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(findingResponse(response)), nil
}

func (s *bootstrapService) GetEntityNeighborhood(ctx context.Context, req *connect.Request[cerebrov1.GetEntityNeighborhoodRequest]) (*connect.Response[cerebrov1.GetEntityNeighborhoodResponse], error) {
	response, err := graphquery.New(
		graphQueryStore(s.deps.GraphStore),
	).GetEntityNeighborhood(ctx, graphquery.NeighborhoodRequest{
		RootURN: req.Msg.GetRootUrn(),
		Limit:   req.Msg.GetLimit(),
	})
	if err != nil {
		return nil, graphQueryConnectError(err)
	}
	return connect.NewResponse(graphNeighborhoodResponse(response)), nil
}

func graphQueryConnectError(err error) error {
	switch {
	case errors.Is(err, ports.ErrGraphEntityNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, graphquery.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, graphquery.ErrRuntimeUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
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

func (a *App) findingService() *findings.Service {
	return findings.New(
		sourceRuntimeStore(a.deps.StateStore),
		eventReplayer(a.deps.AppendLog),
		findingStore(a.deps.StateStore),
	)
}

func (a *App) graphQueryService() *graphquery.Service {
	return graphquery.New(graphQueryStore(a.deps.GraphStore))
}

func sourceConfigFromQuery(r *http.Request) map[string]string {
	values := make(map[string]string)
	for key, rawValues := range r.URL.Query() {
		if key == "cursor" || len(rawValues) == 0 {
			continue
		}
		values[key] = rawValues[len(rawValues)-1]
	}
	return values
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

func reportConnectError(err error) error {
	switch {
	case errors.Is(err, reports.ErrInvalidReportRequest):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, reports.ErrReportNotFound), errors.Is(err, ports.ErrReportRunNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, reports.ErrRuntimeUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	default:
		return err
	}
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

func writeFindingError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	switch {
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, findings.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func writeGraphQueryError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, graphquery.ErrInvalidArgument):
		statusCode = http.StatusBadRequest
	case errors.Is(err, ports.ErrGraphEntityNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, graphquery.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, err.Error(), statusCode)
}

func readProtoJSON(r *http.Request, message proto.Message) error {
	const maxBodyBytes int64 = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxBodyBytes {
		return errors.New("request body too large")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return protojson.Unmarshal(body, message)
}

func sourceRuntimeStore(store ports.StateStore) ports.SourceRuntimeStore {
	runtimeStore, ok := store.(ports.SourceRuntimeStore)
	if !ok || isNilInterface(runtimeStore) {
		return nil
	}
	return runtimeStore
}

func sourceProjectionStateStore(store ports.StateStore) ports.ProjectionStateStore {
	projectionStore, ok := store.(ports.ProjectionStateStore)
	if !ok || isNilInterface(projectionStore) {
		return nil
	}
	return projectionStore
}

func sourceProjectionGraphStore(store ports.GraphStore) ports.ProjectionGraphStore {
	projectionStore, ok := store.(ports.ProjectionGraphStore)
	if !ok || isNilInterface(projectionStore) {
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
	if !ok || isNilInterface(queryStore) {
		return nil
	}
	return queryStore
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func findingStore(store ports.StateStore) ports.FindingStore {
	findingStore, ok := store.(ports.FindingStore)
	if !ok || isNilInterface(findingStore) {
		return nil
	}
	return findingStore
}

func reportStore(store ports.StateStore) ports.ReportStore {
	reportStore, ok := store.(ports.ReportStore)
	if !ok || isNilInterface(reportStore) {
		return nil
	}
	return reportStore
}

func eventReplayer(appendLog ports.AppendLog) ports.EventReplayer {
	replayer, ok := appendLog.(ports.EventReplayer)
	if !ok || isNilInterface(replayer) {
		return nil
	}
	return replayer
}

func findingResponse(result *findings.EvaluateResult) *cerebrov1.EvaluateSourceRuntimeFindingsResponse {
	if result == nil {
		return &cerebrov1.EvaluateSourceRuntimeFindingsResponse{}
	}
	response := &cerebrov1.EvaluateSourceRuntimeFindingsResponse{
		Rule:             result.Rule,
		EventsEvaluated:  result.EventsEvaluated,
		FindingsUpserted: uint32(len(result.Findings)),
		Findings:         make([]*cerebrov1.Finding, 0, len(result.Findings)),
	}
	for _, finding := range result.Findings {
		response.Findings = append(response.Findings, findingMessage(finding))
	}
	return response
}

func findingMessage(finding *ports.FindingRecord) *cerebrov1.Finding {
	if finding == nil {
		return nil
	}
	message := &cerebrov1.Finding{
		Id:           finding.ID,
		Fingerprint:  finding.Fingerprint,
		TenantId:     finding.TenantID,
		RuntimeId:    finding.RuntimeID,
		RuleId:       finding.RuleID,
		Title:        finding.Title,
		Severity:     finding.Severity,
		Status:       finding.Status,
		Summary:      finding.Summary,
		ResourceUrns: append([]string(nil), finding.ResourceURNs...),
		EventIds:     append([]string(nil), finding.EventIDs...),
		Attributes:   make(map[string]string, len(finding.Attributes)),
	}
	for key, value := range finding.Attributes {
		message.Attributes[key] = value
	}
	if !finding.FirstObservedAt.IsZero() {
		message.FirstObservedAt = timestamppb.New(finding.FirstObservedAt)
	}
	if !finding.LastObservedAt.IsZero() {
		message.LastObservedAt = timestamppb.New(finding.LastObservedAt)
	}
	return message
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
		status.Detail = err.Error()
		return status
	}
	status.Status = "ready"
	return status
}
