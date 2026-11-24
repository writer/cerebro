// Package vulnerabilities serves the vulnerability pipeline HTTP API: the
// normalized observation views, source profiles, and the push ingest
// transport.
package vulnerabilities

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

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/vulnpipeline"
)

const maxJSONBodyBytes = 1 << 20

// TenantResolver resolves and authorizes the effective tenant for a request.
type TenantResolver func(context.Context, string) (string, error)

// ActorResolver names the authenticated caller.
type ActorResolver func(context.Context) string

// ForbiddenChecker reports authorization errors from the tenant resolver.
type ForbiddenChecker func(error) bool

// Handler serves /vulnerabilities routes.
type Handler struct {
	service   *vulnpipeline.Service
	tenant    TenantResolver
	actor     ActorResolver
	forbidden ForbiddenChecker
}

// NewHandler builds a Handler.
func NewHandler(service *vulnpipeline.Service, tenant TenantResolver, actor ActorResolver, forbidden ForbiddenChecker) *Handler {
	return &Handler{service: service, tenant: tenant, actor: actor, forbidden: forbidden}
}

func (h *Handler) resolveTenant(r *http.Request) (string, error) {
	tenantID, err := h.tenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(tenantID) == "" {
		return "", fmt.Errorf("%w: tenant_id is required", vulnpipeline.ErrInvalidRequest)
	}
	return tenantID, nil
}

// ListObservations serves GET /vulnerabilities.
func (h *Handler) ListObservations(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	query := r.URL.Query()
	limit, err := optionalInt(query.Get("limit"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	page, err := h.service.ListObservations(r.Context(), ports.VulnerabilityObservationFilter{
		TenantID:        tenantID,
		SourceIDs:       query["source_id"],
		ProfileID:       query.Get("profile_id"),
		Severities:      query["severity"],
		Statuses:        query["status"],
		Classes:         query["class"],
		VulnerabilityID: query.Get("vulnerability_id"),
		AssetIdentifier: query.Get("asset"),
		CorrelationKey:  query.Get("correlation_key"),
		Search:          query.Get("q"),
		Limit:           limit,
		Cursor:          query.Get("cursor"),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// Summary serves GET /vulnerabilities/summary.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	summary, err := h.service.Summary(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// GetObservation serves GET /vulnerabilities/observations/{observationID}.
func (h *Handler) GetObservation(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	observation, err := h.service.GetObservation(r.Context(), tenantID, r.PathValue("observationID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"observation": observation})
}

type catalogResponse struct {
	Formats       []string `json:"formats"`
	PullKinds     []string `json:"pull_kinds"`
	MappingFields []string `json:"mapping_fields"`
	Severities    []string `json:"severities"`
	Statuses      []string `json:"statuses"`
	Classes       []string `json:"classes"`
	NativeSchema  string   `json:"native_schema"`
	MaxPayload    int      `json:"max_payload_bytes"`
}

// Catalog serves GET /vulnerabilities/catalog: the vocabularies, formats,
// and transports this runtime supports.
func (h *Handler) Catalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, catalogResponse{
		Formats: vulnpipeline.Formats(), PullKinds: h.service.PullKinds(), MappingFields: vulnpipeline.MappingFields(),
		Severities: vulnpipeline.Severities(), Statuses: vulnpipeline.Statuses(), Classes: vulnpipeline.Classes(),
		NativeSchema: vulnpipeline.NativeSchema, MaxPayload: vulnpipeline.MaxPayloadBytes,
	})
}

// ListProfiles serves GET /vulnerabilities/profiles.
func (h *Handler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	profiles, err := h.service.ListProfiles(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

// CreateProfile serves POST /vulnerabilities/profiles.
func (h *Handler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	var input vulnpipeline.ProfileInput
	if err := decodeJSON(w, r, &input); err != nil {
		h.writeError(w, err)
		return
	}
	profile, err := h.service.CreateProfile(r.Context(), tenantID, h.actor(r.Context()), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"profile": profile})
}

// GetProfile serves GET /vulnerabilities/profiles/{profileID}.
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	profile, err := h.service.GetProfile(r.Context(), tenantID, r.PathValue("profileID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": profile})
}

// UpdateProfile serves PATCH /vulnerabilities/profiles/{profileID}.
func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	var input vulnpipeline.ProfileInput
	if err := decodeJSON(w, r, &input); err != nil {
		h.writeError(w, err)
		return
	}
	profile, err := h.service.UpdateProfile(r.Context(), tenantID, r.PathValue("profileID"), h.actor(r.Context()), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": profile})
}

// DeleteProfile serves DELETE /vulnerabilities/profiles/{profileID}.
func (h *Handler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if err := h.service.DeleteProfile(r.Context(), tenantID, r.PathValue("profileID")); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Ingest serves POST /vulnerabilities/profiles/{profileID}/ingest. The body
// is the scanner's own document (JSON or NDJSON), not a wrapper.
func (h *Handler) Ingest(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	fullSnapshot, err := optionalBool(r.URL.Query().Get("full_snapshot"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	payload, err := readBody(w, r, vulnpipeline.MaxPayloadBytes)
	if err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.service.Ingest(r.Context(), vulnpipeline.IngestRequest{
		TenantID:       tenantID,
		ProfileID:      r.PathValue("profileID"),
		Transport:      vulnpipeline.TransportPushAPI,
		ContentType:    r.Header.Get("Content-Type"),
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		Actor:          h.actor(r.Context()),
		Format:         strings.TrimSpace(r.URL.Query().Get("format")),
		FullSnapshot:   fullSnapshot,
		Payload:        payload,
	})
	if err != nil && result == nil {
		h.writeError(w, err)
		return
	}
	status := http.StatusAccepted
	switch {
	case err != nil:
		status = statusFor(err, h.forbidden)
	case result.Replayed:
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"ingest": result})
}

// Sync serves POST /vulnerabilities/profiles/{profileID}/sync.
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.service.SyncProfile(r.Context(), tenantID, r.PathValue("profileID"), h.actor(r.Context()))
	if err != nil {
		h.writeError(w, err)
		return
	}
	// The scheduler runs the pull; the response only confirms it is queued.
	writeJSON(w, http.StatusAccepted, map[string]any{"sync": result})
}

type activateRequest struct {
	Mapping *vulnpipeline.Mapping `json:"mapping,omitempty"`
}

// ActivateMapping serves POST /vulnerabilities/profiles/{profileID}/mapping/activate.
func (h *Handler) ActivateMapping(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	var request activateRequest
	if err := decodeOptionalJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.service.ActivateMapping(r.Context(), tenantID, r.PathValue("profileID"), h.actor(r.Context()), request.Mapping)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ListBatches serves GET /vulnerabilities/profiles/{profileID}/batches.
func (h *Handler) ListBatches(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	limit, err := optionalInt(r.URL.Query().Get("limit"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	batches, err := h.service.ListBatches(r.Context(), tenantID, r.PathValue("profileID"), r.URL.Query().Get("status"), limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"batches": batches})
}

// ListQuarantine serves GET /vulnerabilities/profiles/{profileID}/quarantine.
func (h *Handler) ListQuarantine(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.resolveTenant(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	limit, err := optionalInt(r.URL.Query().Get("limit"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, err := h.service.ListQuarantine(r.Context(), tenantID, r.PathValue("profileID"), limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	views := make([]map[string]any, 0, len(records))
	for _, record := range records {
		views = append(views, map[string]any{
			"id": record.ID, "batch_id": record.BatchID, "reason": record.Reason,
			"record": json.RawMessage(validJSONOrString(record.RecordJSON)), "created_at": record.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": views})
}

type previewRequest struct {
	Sample      json.RawMessage       `json:"sample,omitempty"`
	SampleText  string                `json:"sample_text,omitempty"`
	ContentType string                `json:"content_type,omitempty"`
	Format      string                `json:"format,omitempty"`
	Mapping     *vulnpipeline.Mapping `json:"mapping,omitempty"`
}

// Preview serves POST /vulnerabilities/preview: detect the format, learn or
// apply a mapping, and normalize a sample without persisting it.
func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	if _, err := h.resolveTenant(r); err != nil {
		h.writeError(w, err)
		return
	}
	var request previewRequest
	if err := decodeJSONLimit(w, r, &request, vulnpipeline.MaxPayloadBytes); err != nil {
		h.writeError(w, err)
		return
	}
	payload := []byte(request.SampleText)
	if len(request.Sample) > 0 {
		payload = request.Sample
	}
	mappingJSON := ""
	if request.Mapping != nil {
		mappingJSON = request.Mapping.JSON()
	}
	result, err := h.service.Preview(vulnpipeline.PreviewRequest{Payload: payload, ContentType: request.ContentType, Format: request.Format, MappingJSON: mappingJSON})
	if err != nil {
		h.writeError(w, err)
		return
	}
	observations := make([]vulnpipeline.ObservationView, 0, len(result.Observations))
	for _, observation := range result.Observations {
		observations = append(observations, vulnpipeline.ViewObservation(observation))
	}
	writeJSON(w, http.StatusOK, map[string]any{"preview": result, "observations": observations})
}

func validJSONOrString(raw string) []byte {
	if json.Valid([]byte(raw)) {
		return []byte(raw)
	}
	encoded, _ := json.Marshal(raw)
	return encoded
}

func optionalInt(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%w: limit must be a non-negative integer", vulnpipeline.ErrInvalidRequest)
	}
	return value, nil
}

func optionalBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	default:
		return false, fmt.Errorf("%w: full_snapshot must be true or false", vulnpipeline.ErrInvalidRequest)
	}
}

var errBodyTooLarge = errors.New("request body is too large")

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, limit), limit+1))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, errBodyTooLarge
		}
		return nil, fmt.Errorf("%w: read body: %w", vulnpipeline.ErrInvalidRequest, err)
	}
	return body, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	return decodeJSONLimit(w, r, target, maxJSONBodyBytes)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) error {
	body, err := readBody(w, r, limit)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid JSON body: %w", vulnpipeline.ErrInvalidRequest, err)
	}
	return nil
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, target any) error {
	body, err := readBody(w, r, maxJSONBodyBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid JSON body: %w", vulnpipeline.ErrInvalidRequest, err)
	}
	return nil
}

// IsClientError reports errors caused by the caller's request rather than
// the runtime, so transports other than HTTP can classify them the same way.
func IsClientError(err error) bool {
	switch statusFor(err, nil) {
	case http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge:
		return true
	default:
		return false
	}
}

func statusFor(err error, forbidden ForbiddenChecker) int {
	switch {
	case forbidden != nil && forbidden(err):
		return http.StatusForbidden
	case errors.Is(err, errBodyTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, vulnpipeline.ErrInvalidRequest), errors.Is(err, vulnpipeline.ErrInvalidPayload), errors.Is(err, vulnpipeline.ErrInvalidMapping):
		return http.StatusBadRequest
	case errors.Is(err, vulnpipeline.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, vulnpipeline.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, vulnpipeline.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	status := statusFor(err, h.forbidden)
	message := err.Error()
	switch status {
	case http.StatusInternalServerError:
		message = "vulnerability pipeline request failed"
	case http.StatusForbidden:
		message = "forbidden"
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
