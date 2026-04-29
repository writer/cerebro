package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/buildinfo"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
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
	mux.HandleFunc("/sources", app.handleSources)
	mux.HandleFunc("GET /sources/{sourceID}/check", app.handleCheckSource)
	mux.HandleFunc("GET /sources/{sourceID}/discover", app.handleDiscoverSource)
	mux.HandleFunc("GET /sources/{sourceID}/read", app.handleReadSource)
	mux.HandleFunc("PUT /source-runtimes/{runtimeID}", app.handlePutSourceRuntime)
	mux.HandleFunc("GET /source-runtimes/{runtimeID}", app.handleGetSourceRuntime)
	mux.HandleFunc("POST /source-runtimes/{runtimeID}/sync", app.handleSyncSourceRuntime)
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

func (a *App) handlePutSourceRuntime(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.PutSourceRuntimeRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeSourceRuntimeError(w, fmt.Errorf("%w: decode request body", sourceruntime.ErrInvalidRequest))
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
		parsed, err := strconv.ParseUint(strings.TrimSpace(pageLimit), 10, 32)
		if err != nil {
			writeSourceRuntimeError(w, fmt.Errorf("%w: invalid page_limit", sourceruntime.ErrInvalidRequest))
			return
		}
		request.PageLimit = uint32(parsed)
	}
	request.Id = r.PathValue("runtimeID")
	response, err := a.runtimeService().Sync(r.Context(), request)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
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

func (s *bootstrapService) ListSources(_ context.Context, _ *connect.Request[cerebrov1.ListSourcesRequest]) (*connect.Response[cerebrov1.ListSourcesResponse], error) {
	return connect.NewResponse(sourceops.New(s.sources).List()), nil
}

func (s *bootstrapService) CheckSource(ctx context.Context, req *connect.Request[cerebrov1.CheckSourceRequest]) (*connect.Response[cerebrov1.CheckSourceResponse], error) {
	response, err := sourceops.New(s.sources).Check(ctx, req.Msg)
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) DiscoverSource(ctx context.Context, req *connect.Request[cerebrov1.DiscoverSourceRequest]) (*connect.Response[cerebrov1.DiscoverSourceResponse], error) {
	response, err := sourceops.New(s.sources).Discover(ctx, req.Msg)
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) ReadSource(ctx context.Context, req *connect.Request[cerebrov1.ReadSourceRequest]) (*connect.Response[cerebrov1.ReadSourceResponse], error) {
	response, err := sourceops.New(s.sources).Read(ctx, req.Msg)
	if err != nil {
		return nil, sourceConnectError(err)
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
		return nil, sourceRuntimeConnectError(err)
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
		return nil, sourceRuntimeConnectError(err)
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
		return nil, sourceRuntimeConnectError(err)
	}
	return connect.NewResponse(response), nil
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

func (a *App) runtimeService() *sourceruntime.Service {
	return sourceruntime.New(
		a.sources,
		sourceRuntimeStore(a.deps.StateStore),
		a.deps.AppendLog,
		sourceProjector(a.deps.StateStore, a.deps.GraphStore),
	)
}

func sourceConfigFromRequest(r *http.Request) (map[string]string, error) {
	values := make(map[string]string)
	for key, rawValues := range r.URL.Query() {
		if reservedSourceConfigKey(key) || len(rawValues) == 0 {
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
			if trimmedKey != "" && !reservedSourceConfigKey(trimmedKey) {
				values[trimmedKey] = value
			}
		}
	}
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		values["token"] = token
	}
	return values, nil
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("Bearer "):])
}

func reservedSourceConfigKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	return normalized == "cursor" || normalized == "base_url"
}

func sensitiveSourceConfigKey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(value, "token") || strings.Contains(value, "secret") || strings.Contains(value, "password")
}

func sourceRuntimeConnectError(err error) error {
	switch {
	case errors.Is(err, ports.ErrSourceRuntimeNotFound), errors.Is(err, sourceops.ErrSourceNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	case errors.Is(err, sourceruntime.ErrInvalidRequest):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func writeSourceError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	if errors.Is(err, sourceops.ErrSourceNotFound) {
		statusCode = http.StatusNotFound
	}
	http.Error(w, err.Error(), statusCode)
}

func sourceConnectError(err error) error {
	switch {
	case errors.Is(err, sourceops.ErrInvalidSourceID),
		errors.Is(err, sourceops.ErrInvalidSourceConfig):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, sourceops.ErrSourceNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
}

func writeSourceRuntimeError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, sourceruntime.ErrInvalidRequest):
		statusCode = http.StatusBadRequest
	case errors.Is(err, ports.ErrSourceRuntimeNotFound), errors.Is(err, sourceops.ErrSourceNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
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
