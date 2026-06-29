package grcuploadhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcupload"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

const maxUploadBytes int64 = 32 << 20

type Scope struct {
	TenantID   string
	RuntimeID  string
	RuntimeIDs []string
	SourceID   string
	Limit      uint32
}

type Options struct {
	Target          grcupload.Target
	ParserFactory   func() (grcupload.Parser, error)
	AppendLog       ports.AppendLog
	Projector       ports.SourceProjector
	JobStore        ports.JobStore
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
	sourceID := firstNonEmpty(fields["source_id"], scope.SourceID)
	runtimeID := firstNonEmpty(fields["runtime_id"], scope.RuntimeID)
	request := grcupload.UploadRequest{
		Target:      h.options.Target,
		TenantID:    tenantID,
		SourceID:    sourceID,
		RuntimeID:   runtimeID,
		ActorUserID: h.actorUserID(r.Context()),
		FileName:    header.Filename,
		ContentType: contentType,
		FileSize:    header.Size,
		Fields:      fields,
	}
	uploadID := grcupload.NewUploadID(request)
	job, err := h.startUploadJob(r.Context(), uploadID, request)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.recordUploadJobEvent(r.Context(), job, "parsing", ports.JobStatusRunning, "Parsing file with Reducto", nil)
	hasher := sha256.New()
	parsed, err := parser.Parse(r.Context(), header.Filename, contentType, io.TeeReader(file, hasher))
	request.FileSHA256 = hex.EncodeToString(hasher.Sum(nil))
	if err != nil {
		h.failUploadJob(r.Context(), job, "parse_failed", err, map[string]any{"upload_id": uploadID})
		h.writeError(w, err)
		return
	}
	h.recordUploadJobEvent(r.Context(), job, "parsed", ports.JobStatusRunning, "Reducto parse completed", map[string]any{
		"upload_id":   uploadID,
		"parse_id":    parsed.ParseID,
		"chunk_count": parsed.ChunkCount,
		"page_count":  parsed.PageCount,
	})
	events, response, err := grcupload.BuildEvents(request, parsed, h.now())
	if err != nil {
		h.failUploadJob(r.Context(), job, "events_failed", err, map[string]any{"upload_id": uploadID})
		h.writeError(w, err)
		return
	}
	response.Job = uploadJobRef(job)
	appended, err := h.appendEvents(r.Context(), events)
	if err != nil {
		wrapped := fmt.Errorf("%w: append upload event: %w", grcupload.ErrRuntimeUnavailable, err)
		h.failUploadJob(r.Context(), job, "append_failed", wrapped, map[string]any{
			"upload_id":       uploadID,
			"events_built":    len(events),
			"events_appended": appended,
		})
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
	h.recordUploadJobEvent(r.Context(), job, "events_appended", ports.JobStatusRunning, "Upload events appended", map[string]any{
		"upload_id":         uploadID,
		"events_built":      len(events),
		"events_appended":   appended,
		"review_state":      response.ReviewState,
		"quality_status":    response.QualityStatus,
		"review_item_count": len(response.ReviewItems),
	})
	projection := h.projectEvents(r.Context(), events)
	status := "accepted"
	response.Status = "projected"
	response.ProjectionStatus = "projected"
	if projection.err != nil {
		status = "accepted_with_projection_errors"
		response.Status = "projection_partial"
		response.ProjectionStatus = "projection_partial"
		response.ProjectionFailures = projection.failures
	}
	if response.ReviewState == "needs_review" && response.Status == "projected" {
		response.Status = "needs_review"
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
	job = h.completeUploadJob(r.Context(), job, response, projection, len(events), appended)
	response.Job = uploadJobRef(job)
	h.writeJSON(w, http.StatusAccepted, response)
}

func (h Handler) appendEvents(ctx context.Context, events []*cerebrov1.EventEnvelope) (int, error) {
	if batcher, ok := h.options.AppendLog.(ports.AppendLogBatcher); ok {
		if err := batcher.AppendBatch(ctx, events); err != nil {
			return 0, err
		}
		return len(events), nil
	}
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

func (h Handler) startUploadJob(ctx context.Context, uploadID string, request grcupload.UploadRequest) (*ports.Job, error) {
	if h.options.JobStore == nil {
		return nil, nil
	}
	job, _, err := h.options.JobStore.CreateJob(ctx, ports.CreateJobRequest{
		Kind:           platformjobs.KindGRCUpload,
		TenantID:       request.TenantID,
		SubjectType:    "grc_upload",
		SubjectID:      uploadID,
		IdempotencyKey: "grc_upload:" + uploadID,
		Payload: map[string]any{
			"upload_id":    uploadID,
			"target":       string(request.Target),
			"source_id":    request.SourceID,
			"runtime_id":   request.RuntimeID,
			"file_name":    request.FileName,
			"content_type": request.ContentType,
			"file_size":    request.FileSize,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: create upload job: %w", grcupload.ErrRuntimeUnavailable, err)
	}
	now := h.now()
	progress := uint32(10)
	updated, err := h.options.JobStore.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status:    ports.JobStatusRunning,
		Progress:  &progress,
		Message:   "Upload received",
		StartedAt: &now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: start upload job: %w", grcupload.ErrRuntimeUnavailable, err)
	}
	h.recordUploadJobEvent(ctx, updated, "received", ports.JobStatusRunning, "Upload received", map[string]any{
		"upload_id":  uploadID,
		"target":     string(request.Target),
		"file_name":  request.FileName,
		"file_size":  request.FileSize,
		"runtime_id": request.RuntimeID,
	})
	return updated, nil
}

func (h Handler) recordUploadJobEvent(ctx context.Context, job *ports.Job, eventType string, status string, message string, payload map[string]any) {
	if h.options.JobStore == nil || job == nil {
		return
	}
	if payload == nil {
		payload = map[string]any{}
	}
	if _, err := h.options.JobStore.AppendJobEvent(ctx, ports.JobEvent{
		JobID:   job.ID,
		Type:    strings.TrimSpace(eventType),
		Status:  strings.TrimSpace(status),
		Message: strings.TrimSpace(message),
		Payload: payload,
	}); err != nil {
		telemetry.CaptureError(ctx, "cerebro.grc.upload.job_event_error", err, telemetry.Attrs(
			telemetry.Field{Key: "job_id", Value: job.ID},
			telemetry.Field{Key: "event_type", Value: strings.TrimSpace(eventType)},
		))
	}
}

func (h Handler) failUploadJob(ctx context.Context, job *ports.Job, eventType string, err error, payload map[string]any) {
	if h.options.JobStore == nil || job == nil {
		return
	}
	finished := h.now()
	updated, updateErr := h.options.JobStore.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status:     ports.JobStatusFailed,
		Message:    "Upload failed",
		Error:      err.Error(),
		FinishedAt: &finished,
	})
	if updateErr != nil {
		telemetry.CaptureError(ctx, "cerebro.grc.upload.job_update_error", updateErr, telemetry.Attrs(telemetry.Field{Key: "job_id", Value: job.ID}))
		updated = job
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["error_kind"] = telemetry.ErrorKind(err)
	h.recordUploadJobEvent(ctx, updated, eventType, ports.JobStatusFailed, "Upload failed", payload)
}

func (h Handler) completeUploadJob(ctx context.Context, job *ports.Job, response grcupload.Response, projection projectionSummary, eventsBuilt int, eventsAppended int) *ports.Job {
	if h.options.JobStore == nil || job == nil {
		return job
	}
	eventType := "projected"
	message := "Upload projected"
	if response.Status == "projection_partial" {
		eventType = "projection_partial"
		message = "Upload accepted with projection errors"
	}
	if response.Status == "needs_review" {
		eventType = "needs_review"
		message = "Upload needs field review"
	}
	result := map[string]any{
		"upload_id":           response.UploadID,
		"status":              response.Status,
		"target":              response.Target,
		"projection_status":   response.ProjectionStatus,
		"projection_failures": response.ProjectionFailures,
		"events_built":        eventsBuilt,
		"events_appended":     eventsAppended,
		"events_projected":    projection.eventsProjected,
		"entities_projected":  projection.entitiesProjected,
		"links_projected":     projection.linksProjected,
		"review_state":        response.ReviewState,
		"review_item_count":   len(response.ReviewItems),
		"quality_status":      response.QualityStatus,
		"quality_check_count": len(response.QualityChecks),
		"reducto_parse_id":    response.ReductoParseID,
		"reducto_file_id":     response.ReductoFileID,
		"entity_match_hints":  response.EntityMatchHints,
	}
	refs := map[string]string{
		"upload_id": response.UploadID,
	}
	if response.ReductoParseID != "" {
		refs["reducto_parse_id"] = response.ReductoParseID
	}
	if len(response.Events) > 0 {
		refs["first_event_id"] = response.Events[0].EventID
	}
	finished := h.now()
	progress := uint32(100)
	updated, err := h.options.JobStore.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status:     ports.JobStatusCompleted,
		Progress:   &progress,
		Message:    message,
		Result:     result,
		ResultRefs: refs,
		FinishedAt: &finished,
	})
	if err != nil {
		telemetry.CaptureError(ctx, "cerebro.grc.upload.job_update_error", err, telemetry.Attrs(telemetry.Field{Key: "job_id", Value: job.ID}))
		updated = job
	}
	h.recordUploadJobEvent(ctx, updated, eventType, ports.JobStatusCompleted, message, result)
	return updated
}

func uploadJobRef(job *ports.Job) *grcupload.UploadJobRef {
	if job == nil {
		return nil
	}
	return &grcupload.UploadJobRef{ID: job.ID, Status: job.Status}
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
