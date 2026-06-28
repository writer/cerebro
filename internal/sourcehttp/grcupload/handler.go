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

	"github.com/writer/cerebro/internal/grcupload"
	"github.com/writer/cerebro/internal/ports"
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
	tenantID := firstNonEmpty(fields["tenant_id"], scope.TenantID)
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
	events, response, err := grcupload.BuildEvents(grcupload.UploadRequest{
		Target:      h.options.Target,
		TenantID:    tenantID,
		SourceID:    firstNonEmpty(fields["source_id"], scope.SourceID),
		RuntimeID:   firstNonEmpty(fields["runtime_id"], scope.RuntimeID),
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
	for _, event := range events {
		if err := h.options.AppendLog.Append(r.Context(), event); err != nil {
			h.writeError(w, fmt.Errorf("%w: append upload event: %w", grcupload.ErrRuntimeUnavailable, err))
			return
		}
		if _, err := h.options.Projector.Project(r.Context(), event); err != nil {
			h.writeError(w, fmt.Errorf("%w: project upload event: %w", grcupload.ErrRuntimeUnavailable, err))
			return
		}
	}
	if h.options.BumpCache != nil {
		h.options.BumpCache(r.Context(), tenantID)
	}
	h.writeJSON(w, http.StatusAccepted, response)
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
