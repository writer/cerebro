package grcuploadhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcupload"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

const maxUploadBytes int64 = 32 << 20

type Scope struct {
	TenantID  string
	SourceID  string
	RuntimeID string
}

type Options struct {
	Target          grcupload.Target
	ParserFactory   func() (grcupload.Parser, error)
	AppendLog       ports.AppendLog
	Projector       ports.SourceProjector
	ResolveScope    func(*http.Request) (Scope, error)
	AuthorizeTenant func(context.Context, string) error
	ActorUserID     func(context.Context) string
	BumpCache       func(context.Context, string)
	WriteError      func(http.ResponseWriter, error)
	WriteJSON       func(http.ResponseWriter, int, any)
	Now             func() time.Time
}

type Handler struct {
	options Options
}

func NewHandler(options Options) Handler {
	return Handler{options: options}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		h.writeError(w, fmt.Errorf("%w: parse upload form: %w", grcupload.ErrInvalidRequest, err))
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		h.writeError(w, fmt.Errorf("%w: file is required", grcupload.ErrInvalidRequest))
		return
	}
	defer func() { _ = file.Close() }()

	fields := formFields(r.MultipartForm)
	scope, err := h.scope(scopeRequestWithTenant(r, fields["tenant_id"]))
	if err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := resolvedTenantID(fields["tenant_id"], scope.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if h.options.AuthorizeTenant != nil {
		if err := h.options.AuthorizeTenant(r.Context(), tenantID); err != nil {
			h.writeError(w, err)
			return
		}
	}
	parser, err := h.parser()
	if err != nil {
		h.writeError(w, err)
		return
	}
	if h.options.AppendLog == nil || h.options.Projector == nil {
		h.writeError(w, grcupload.ErrRuntimeUnavailable)
		return
	}

	contentType := fileContentType(header)
	parsed, err := parser.Parse(r.Context(), header.Filename, contentType, file)
	if err != nil {
		h.writeError(w, err)
		return
	}
	sourceID := firstNonEmpty(fields["source_id"], scope.SourceID)
	runtimeID := firstNonEmpty(fields["runtime_id"], scope.RuntimeID)
	events, response, err := grcupload.BuildEvents(grcupload.UploadRequest{
		Target:      h.options.Target,
		TenantID:    tenantID,
		SourceID:    sourceID,
		RuntimeID:   runtimeID,
		ActorUserID: h.actorUserID(r.Context()),
		FileName:    header.Filename,
		ContentType: contentType,
		FileSize:    header.Size,
		Fields:      fields,
	}, parsed, h.now())
	if err != nil {
		h.writeError(w, err)
		return
	}
	appended, err := h.appendEvents(r.Context(), events)
	if err != nil {
		wrapped := fmt.Errorf("%w: append upload event: %w", grcupload.ErrRuntimeUnavailable, err)
		emitUploadTelemetry(r.Context(), uploadTelemetry{
			target:         h.options.Target,
			tenantID:       tenantID,
			sourceID:       sourceID,
			runtimeID:      runtimeID,
			status:         "append_failed",
			eventsBuilt:    len(events),
			eventsAppended: appended,
			err:            wrapped,
		})
		h.writeError(w, wrapped)
		return
	}
	projection := h.projectEvents(r.Context(), events)
	status := "accepted"
	response.ProjectionStatus = "projected"
	if projection.err != nil {
		status = "accepted_with_projection_errors"
		response.ProjectionStatus = status
		response.ProjectionFailures = projection.failures
	}
	emitUploadTelemetry(r.Context(), uploadTelemetry{
		target:             h.options.Target,
		tenantID:           tenantID,
		sourceID:           sourceID,
		runtimeID:          runtimeID,
		status:             status,
		eventsBuilt:        len(events),
		eventsAppended:     appended,
		eventsProjected:    projection.eventsProjected,
		entitiesProjected:  projection.entitiesProjected,
		linksProjected:     projection.linksProjected,
		projectionFailures: projection.failures,
		err:                projection.err,
	})
	if h.options.BumpCache != nil && projection.eventsProjected > 0 {
		h.options.BumpCache(r.Context(), tenantID)
	}
	h.writeJSON(w, http.StatusAccepted, response)
}

func (h Handler) appendEvents(ctx context.Context, events []*cerebrov1.EventEnvelope) (int, error) {
	appended := 0
	for _, event := range events {
		if err := h.options.AppendLog.Append(ctx, event); err != nil {
			return appended, err
		}
		appended++
	}
	return appended, nil
}

type projectionSummary struct {
	eventsProjected   int
	entitiesProjected uint32
	linksProjected    uint32
	failures          int
	err               error
}

func (h Handler) projectEvents(ctx context.Context, events []*cerebrov1.EventEnvelope) projectionSummary {
	var summary projectionSummary
	for _, event := range events {
		result, err := h.options.Projector.Project(ctx, event)
		if err != nil {
			summary.failures++
			if summary.err == nil {
				summary.err = err
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				break
			}
			continue
		}
		summary.eventsProjected++
		summary.entitiesProjected += result.EntitiesProjected
		summary.linksProjected += result.LinksProjected
	}
	return summary
}

type uploadTelemetry struct {
	target             grcupload.Target
	tenantID           string
	sourceID           string
	runtimeID          string
	status             string
	eventsBuilt        int
	eventsAppended     int
	eventsProjected    int
	entitiesProjected  uint32
	linksProjected     uint32
	projectionFailures int
	err                error
}

func emitUploadTelemetry(ctx context.Context, summary uploadTelemetry) {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "target", Value: string(summary.target)},
		telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(summary.tenantID)},
		telemetry.Field{Key: "source_id", Value: strings.TrimSpace(summary.sourceID)},
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(summary.runtimeID)},
		telemetry.Field{Key: "status", Value: strings.TrimSpace(summary.status)},
		telemetry.Field{Key: "events_built", Value: summary.eventsBuilt},
		telemetry.Field{Key: "events_appended", Value: summary.eventsAppended},
		telemetry.Field{Key: "events_projected", Value: summary.eventsProjected},
		telemetry.Field{Key: "entities_projected", Value: summary.entitiesProjected},
		telemetry.Field{Key: "links_projected", Value: summary.linksProjected},
		telemetry.Field{Key: "projection_failures", Value: summary.projectionFailures},
	)
	if summary.err != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(summary.err)})
	}
	telemetry.Event(ctx, "cerebro.grc.upload", attrs)
	if summary.err != nil {
		telemetry.CaptureError(ctx, "cerebro.grc.upload.error", summary.err, attrs.WithField(telemetry.Field{Key: "operation", Value: strings.TrimSpace(summary.status)}))
	}
}

func (h Handler) scope(r *http.Request) (Scope, error) {
	if h.options.ResolveScope == nil {
		return Scope{}, nil
	}
	return h.options.ResolveScope(r)
}

func (h Handler) parser() (grcupload.Parser, error) {
	if h.options.ParserFactory == nil {
		return nil, grcupload.ErrRuntimeUnavailable
	}
	return h.options.ParserFactory()
}

func (h Handler) actorUserID(ctx context.Context) string {
	if h.options.ActorUserID == nil {
		return ""
	}
	return h.options.ActorUserID(ctx)
}

func (h Handler) now() time.Time {
	if h.options.Now == nil {
		return time.Now().UTC()
	}
	return h.options.Now().UTC()
}

func (h Handler) writeError(w http.ResponseWriter, err error) {
	if h.options.WriteError != nil {
		h.options.WriteError(w, err)
		return
	}
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, grcupload.ErrInvalidRequest):
		statusCode = http.StatusBadRequest
	case errors.Is(err, grcupload.ErrRemote):
		statusCode = http.StatusBadGateway
	case errors.Is(err, grcupload.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

func (h Handler) writeJSON(w http.ResponseWriter, statusCode int, value any) {
	if h.options.WriteJSON != nil {
		h.options.WriteJSON(w, statusCode, value)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func scopeRequestWithTenant(r *http.Request, tenantID string) *http.Request {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(r.URL.Query().Get("tenant_id")) != "" {
		return r
	}
	clone := new(http.Request)
	*clone = *r
	clonedURL := *r.URL
	query := clonedURL.Query()
	query.Set("tenant_id", tenantID)
	clonedURL.RawQuery = query.Encode()
	clone.URL = &clonedURL
	return clone
}

func resolvedTenantID(formTenantID string, scopeTenantID string) (string, error) {
	formTenantID = strings.TrimSpace(formTenantID)
	scopeTenantID = strings.TrimSpace(scopeTenantID)
	if formTenantID != "" && scopeTenantID != "" && formTenantID != scopeTenantID {
		return "", fmt.Errorf("%w: tenant_id must match the resolved upload scope", grcupload.ErrInvalidRequest)
	}
	return firstNonEmpty(scopeTenantID, formTenantID), nil
}

func formFields(form *multipart.Form) map[string]string {
	fields := map[string]string{}
	if form == nil {
		return fields
	}
	for key, values := range form.Value {
		key = strings.TrimSpace(strings.ToLower(key))
		if key == "" || len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(values[0])
		if value != "" {
			fields[key] = value
		}
	}
	return fields
}

func fileContentType(header *multipart.FileHeader) string {
	if header == nil {
		return ""
	}
	return strings.TrimSpace(header.Header.Get("Content-Type"))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
