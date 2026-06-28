package bootstrap

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grcupload"
)

const maxGRCUploadBytes int64 = 32 << 20

func (a *App) handleGRCPolicyUpload(w http.ResponseWriter, r *http.Request) {
	a.handleGRCUpload(w, r, grcupload.TargetPolicy)
}

func (a *App) handleGRCVendorUpload(w http.ResponseWriter, r *http.Request) {
	a.handleGRCUpload(w, r, grcupload.TargetVendor)
}

func (a *App) handleGRCUpload(w http.ResponseWriter, r *http.Request, target grcupload.Target) {
	r.Body = http.MaxBytesReader(w, r.Body, maxGRCUploadBytes)
	if err := r.ParseMultipartForm(maxGRCUploadBytes); err != nil {
		writeGRCError(w, fmt.Errorf("%w: parse upload form: %w", errInvalidHTTPRequest, err))
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeGRCError(w, fmt.Errorf("%w: file is required", errInvalidHTTPRequest))
		return
	}
	defer func() { _ = file.Close() }()

	fields := grcUploadFormFields(r.MultipartForm)
	scopeRequest := r
	if fields["tenant_id"] != "" && strings.TrimSpace(r.URL.Query().Get("tenant_id")) == "" {
		clone := new(http.Request)
		*clone = *r
		clonedURL := *r.URL
		query := clonedURL.Query()
		query.Set("tenant_id", fields["tenant_id"])
		clonedURL.RawQuery = query.Encode()
		clone.URL = &clonedURL
		scopeRequest = clone
	}
	scope, err := grcScopeFromRequest(scopeRequest)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	tenantID := firstNonEmptyString(fields["tenant_id"], scope.TenantID)
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	sourceID := firstNonEmptyString(fields["source_id"], scope.SourceID)
	runtimeID := firstNonEmptyString(fields["runtime_id"], scope.RuntimeID)
	parser, err := a.grcUploadParser()
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if a.deps.AppendLog == nil {
		writeGRCError(w, grcupload.ErrRuntimeUnavailable)
		return
	}
	projector := sourceProjector(a.deps.StateStore, a.deps.GraphStore)
	if projector == nil {
		writeGRCError(w, grcupload.ErrRuntimeUnavailable)
		return
	}
	parsed, err := parser.Parse(r.Context(), header.Filename, grcUploadContentType(header), file)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	events, response, err := grcupload.BuildEvents(grcupload.UploadRequest{
		Target:      target,
		TenantID:    tenantID,
		SourceID:    sourceID,
		RuntimeID:   runtimeID,
		ActorUserID: customDashboardActorID(r.Context()),
		FileName:    header.Filename,
		ContentType: grcUploadContentType(header),
		FileSize:    header.Size,
		Fields:      fields,
	}, parsed, time.Now().UTC())
	if err != nil {
		writeGRCError(w, err)
		return
	}
	for _, event := range events {
		if err := a.deps.AppendLog.Append(r.Context(), event); err != nil {
			writeGRCError(w, fmt.Errorf("%w: append upload event: %w", grcupload.ErrRuntimeUnavailable, err))
			return
		}
		if _, err := projector.Project(r.Context(), event); err != nil {
			writeGRCError(w, fmt.Errorf("%w: project upload event: %w", grcupload.ErrRuntimeUnavailable, err))
			return
		}
	}
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeGraph)
	writeJSON(w, http.StatusAccepted, response)
}

func (a *App) grcUploadParser() (grcupload.Parser, error) {
	return grcupload.NewReductoClient(grcupload.ReductoConfig{
		APIKey:  a.cfg.DocumentParsing.Reducto.APIKey,
		BaseURL: a.cfg.DocumentParsing.Reducto.BaseURL,
		Timeout: a.cfg.DocumentParsing.Reducto.Timeout,
	})
}

func grcUploadFormFields(form *multipart.Form) map[string]string {
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

func grcUploadContentType(header *multipart.FileHeader) string {
	if header == nil {
		return ""
	}
	return strings.TrimSpace(header.Header.Get("Content-Type"))
}
