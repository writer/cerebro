package bootstrap

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
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
	config, err := sourceConfigFromQuery(r)
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
	config, err := sourceConfigFromQuery(r)
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
	config, err := sourceConfigFromQuery(r)
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
	config, err := sanitizePreviewSourceConfig(req.Msg.Config)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	response, err := sourceops.New(s.sources).Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: req.Msg.SourceId,
		Config:   config,
	})
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) DiscoverSource(ctx context.Context, req *connect.Request[cerebrov1.DiscoverSourceRequest]) (*connect.Response[cerebrov1.DiscoverSourceResponse], error) {
	config, err := sanitizePreviewSourceConfig(req.Msg.Config)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	response, err := sourceops.New(s.sources).Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: req.Msg.SourceId,
		Config:   config,
	})
	if err != nil {
		return nil, sourceConnectError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *bootstrapService) ReadSource(ctx context.Context, req *connect.Request[cerebrov1.ReadSourceRequest]) (*connect.Response[cerebrov1.ReadSourceResponse], error) {
	config, err := sanitizePreviewSourceConfig(req.Msg.Config)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	response, err := sourceops.New(s.sources).Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: req.Msg.SourceId,
		Config:   config,
		Cursor:   req.Msg.Cursor,
	})
	if err != nil {
		return nil, sourceConnectError(err)
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

func sourceConfigFromQuery(r *http.Request) (map[string]string, error) {
	values := make(map[string]string)
	for key, rawValues := range r.URL.Query() {
		if key == "cursor" || key == "base_url" || len(rawValues) == 0 {
			continue
		}
		if sensitiveSourceConfigKey(key) {
			return nil, fmt.Errorf("source config key %q must not be passed as a query parameter", key)
		}
		values[key] = rawValues[len(rawValues)-1]
	}
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		values["token"] = token
	}
	return values, nil
}

func sanitizePreviewSourceConfig(values map[string]string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	sanitized := make(map[string]string, len(values))
	for key, value := range values {
		if blockedPreviewSourceConfigKey(key) {
			return nil, fmt.Errorf("source config key %q is not allowed for preview requests", key)
		}
		sanitized[key] = value
	}
	return sanitized, nil
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("Bearer "):])
}

func sensitiveSourceConfigKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	if strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "password") || strings.Contains(normalized, "session") {
		return true
	}
	return normalized == "key" || strings.HasSuffix(normalized, "_key")
}

func blockedPreviewSourceConfigKey(key string) bool {
	return strings.EqualFold(strings.TrimSpace(key), "base_url")
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

func writeSourceError(w http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	if errors.Is(err, sourceops.ErrSourceNotFound) {
		statusCode = http.StatusNotFound
	}
	http.Error(w, err.Error(), statusCode)
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
