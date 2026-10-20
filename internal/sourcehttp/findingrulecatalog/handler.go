// Package findingrulecatalog serves the classified detection rule catalog and
// the authoring endpoints for tenant custom rules.
package findingrulecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/rulecatalog"
)

// maxBodyBytes leaves room for a full document plus a sample resource and
// JSON escaping overhead.
const maxBodyBytes = 4 * rulecatalog.MaxDocumentBytes

var (
	errInvalidRequest   = errors.New("invalid rule request")
	errStoreUnavailable = errors.New("custom finding rule store is not configured")
	errTenantForbidden  = errors.New("tenant access denied")
)

// TenantResolver returns the authorized tenant for a requested tenant ID.
// Any error it returns is treated as an authorization failure.
type TenantResolver func(context.Context, string) (string, error)

// ActorResolver returns the authenticated actor for attribution.
type ActorResolver func(context.Context) string

// Handler serves the rule catalog routes.
type Handler struct {
	store   ports.CustomFindingRuleStore
	resolve TenantResolver
	actor   ActorResolver
}

// NewHandler builds a handler from the optional StateStore capability.
// Catalog reads work without a store; custom rule writes return 503.
func NewHandler(store ports.StateStore, resolve TenantResolver, actor ActorResolver) Handler {
	ruleStore, _ := store.(ports.CustomFindingRuleStore)
	return Handler{store: ruleStore, resolve: resolve, actor: actor}
}

// CatalogResponse lists every rule visible to the tenant.
type CatalogResponse struct {
	Rules            []rulecatalog.Entry `json:"rules"`
	Total            int                 `json:"total"`
	CustomRulesReady bool                `json:"custom_rules_ready"`
}

// DocumentRequest carries one authored rule document.
type DocumentRequest struct {
	TenantID string                     `json:"tenant_id"`
	Format   string                     `json:"format"`
	Content  string                     `json:"content"`
	Resource rulecatalog.SampleResource `json:"resource,omitempty"`
}

// List returns built-in rules followed by the tenant's custom rules.
func (h Handler) List(w http.ResponseWriter, r *http.Request) {
	builtin := rulecatalog.Builtin()
	entries := make([]rulecatalog.Entry, 0, len(builtin))
	for _, detail := range builtin {
		entries = append(entries, detail.Entry)
	}
	tenantID, err := h.optionalTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	ready := h.store != nil && tenantID != ""
	if ready {
		custom, err := h.customDetails(r.Context(), tenantID)
		if err != nil {
			writeError(w, err)
			return
		}
		for _, detail := range custom {
			entries = append(entries, detail.Entry)
		}
	}
	writeJSON(w, http.StatusOK, CatalogResponse{Rules: entries, Total: len(entries), CustomRulesReady: ready})
}

// Get returns one built-in or custom rule detail.
func (h Handler) Get(w http.ResponseWriter, r *http.Request) {
	ruleID := strings.TrimSpace(r.PathValue("ruleID"))
	if ruleID == "" {
		writeError(w, fmt.Errorf("%w: rule id is required", errInvalidRequest))
		return
	}
	if detail, ok := rulecatalog.BuiltinRule(ruleID); ok {
		writeJSON(w, http.StatusOK, detail)
		return
	}
	tenantID, err := h.optionalTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if h.store == nil || tenantID == "" {
		writeError(w, fmt.Errorf("%w: %s", ports.ErrCustomFindingRuleNotFound, ruleID))
		return
	}
	record, err := h.store.GetCustomFindingRule(r.Context(), tenantID, ruleID)
	if err != nil {
		writeError(w, err)
		return
	}
	detail, err := rulecatalog.StoredCustomDetail(*record)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// Validate checks a document without saving it.
func (h Handler) Validate(w http.ResponseWriter, r *http.Request) {
	body, err := decodeDocumentRequest(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rulecatalog.Validate(body.Format, body.Content))
}

// Test evaluates a document against a sample resource without saving it.
func (h Handler) Test(w http.ResponseWriter, r *http.Request) {
	body, err := decodeDocumentRequest(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rulecatalog.Test(body.Format, body.Content, body.Resource))
}

// Put validates and saves a custom rule as canonical YAML.
func (h Handler) Put(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, errStoreUnavailable)
		return
	}
	ruleID := strings.TrimSpace(r.PathValue("ruleID"))
	body, err := decodeDocumentRequest(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	tenantID, err := h.requiredTenant(r.Context(), body.TenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	result := rulecatalog.Validate(body.Format, body.Content)
	if !result.Valid || result.Preview == nil {
		writeJSON(w, http.StatusUnprocessableEntity, result)
		return
	}
	if result.Preview.ID != ruleID {
		writeError(w, fmt.Errorf("%w: metadata.id %q must match the rule id in the path %q", errInvalidRequest, result.Preview.ID, ruleID))
		return
	}
	actor := ""
	if h.actor != nil {
		actor = h.actor(r.Context())
	}
	record := &ports.CustomFindingRule{TenantID: tenantID, ID: ruleID, Document: result.YAML, CreatedBy: actor, UpdatedBy: actor}
	if err := h.store.PutCustomFindingRule(r.Context(), record); err != nil {
		writeError(w, err)
		return
	}
	stored, err := h.store.GetCustomFindingRule(r.Context(), tenantID, ruleID)
	if err != nil {
		writeError(w, err)
		return
	}
	detail, err := rulecatalog.StoredCustomDetail(*stored)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// Delete removes a custom rule.
func (h Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, errStoreUnavailable)
		return
	}
	ruleID := strings.TrimSpace(r.PathValue("ruleID"))
	tenantID, err := h.requiredTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.DeleteCustomFindingRule(r.Context(), tenantID, ruleID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ruleID, "deleted": true})
}

func (h Handler) customDetails(ctx context.Context, tenantID string) ([]rulecatalog.Detail, error) {
	records, err := h.store.ListCustomFindingRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	details := make([]rulecatalog.Detail, 0, len(records))
	for _, record := range records {
		detail, err := rulecatalog.StoredCustomDetail(record)
		if err != nil {
			// Keep unreadable rules visible so operators can fix or delete them.
			detail = rulecatalog.Detail{Entry: rulecatalog.Entry{
				ID: record.ID, Name: record.ID, Summary: "The saved document could not be parsed. Open it to fix or delete it.",
				Severity: "info", Origin: rulecatalog.OriginCustom, Domain: rulecatalog.DomainSaaS, Posture: rulecatalog.PostureSSPM,
				Provider: "custom", Evaluation: rulecatalog.EvaluationCEL, Detection: rulecatalog.DetectionPosture, Maturity: "custom",
			}, Document: record.Document, Editable: true}
		}
		details = append(details, detail)
	}
	return details, nil
}

func (h Handler) optionalTenant(ctx context.Context, requested string) (string, error) {
	tenantID := strings.TrimSpace(requested)
	if h.resolve != nil {
		resolved, err := h.resolve(ctx, requested)
		if err != nil {
			return "", fmt.Errorf("%w: %w", errTenantForbidden, err)
		}
		tenantID = strings.TrimSpace(resolved)
	}
	return tenantID, nil
}

func (h Handler) requiredTenant(ctx context.Context, requested string) (string, error) {
	tenantID, err := h.optionalTenant(ctx, requested)
	if err != nil {
		return "", err
	}
	if tenantID == "" {
		return "", fmt.Errorf("%w: tenant_id is required", errInvalidRequest)
	}
	return tenantID, nil
}

func decodeDocumentRequest(w http.ResponseWriter, r *http.Request) (DocumentRequest, error) {
	var body DocumentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return DocumentRequest{}, fmt.Errorf("%w: decode rule document request: %w", errInvalidRequest, err)
	}
	return body, nil
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "internal server error"
	switch {
	case errors.Is(err, errInvalidRequest):
		status = http.StatusBadRequest
		message = err.Error()
	case errors.Is(err, ports.ErrCustomFindingRuleNotFound):
		status = http.StatusNotFound
		message = "rule not found"
	case errors.Is(err, errTenantForbidden):
		status = http.StatusForbidden
		message = "tenant access denied"
	case errors.Is(err, errStoreUnavailable):
		status = http.StatusServiceUnavailable
		message = err.Error()
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
