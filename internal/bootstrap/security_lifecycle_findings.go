package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"
	"github.com/writer/cerebro/internal/securitylifecyclefindings"
)

const maxSecurityLifecycleReconcileBodyBytes = 4 << 10

type securityLifecycleReconcileRequest struct {
	TenantID string `json:"tenant_id"`
}

type securityLifecycleReconcileResponse struct {
	FindingID       string `json:"finding_id"`
	Status          string `json:"status"`
	Verification    string `json:"verification"`
	Reason          string `json:"reason,omitempty"`
	AuditPreviewURL string `json:"audit_preview_url"`
}

func (a *App) handleReconcileSecurityLifecycleFinding(w http.ResponseWriter, r *http.Request) {
	var request securityLifecycleReconcileRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecurityLifecycleReconcileBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode security lifecycle reconcile request: %w", errInvalidHTTPRequest, err))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findingID := strings.TrimSpace(r.PathValue("findingID"))
	if findingID == "" {
		writeGRCError(w, fmt.Errorf("%w: finding id is required", errInvalidHTTPRequest))
		return
	}
	result, err := securitylifecyclefindings.New(
		a.findingService(),
		a.deps.SecurityLifecycleQueries,
		a.deps.SourceCollectionReceipts,
	).Reconcile(r.Context(), tenantID, findingID)
	if err != nil {
		switch {
		case errors.Is(err, securitylifecyclefindings.ErrTenantForbidden):
			writeGRCError(w, errTenantForbidden)
		case errors.Is(err, securitylifecyclefindings.ErrDependency):
			status := http.StatusBadGateway
			if connect.CodeOf(err) == connect.CodeUnavailable {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "Security lifecycle verification dependency failed.", status)
		default:
			writeGRCError(w, err)
		}
		return
	}
	if result.Changed {
		a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeFindings, grcCacheScopeEvidence)
	}
	status := http.StatusOK
	if result.Pending {
		status = http.StatusAccepted
	}
	writeJSON(w, status, securityLifecycleReconcileResponse{
		FindingID:       result.FindingID,
		Status:          result.Status,
		Verification:    result.Verification,
		Reason:          result.Reason,
		AuditPreviewURL: lifecycleAuditPreviewURL(result.FindingID),
	})
}

func lifecycleAuditPreviewURL(findingID string) string {
	return "/grc/findings/" + url.PathEscape(strings.TrimSpace(findingID)) + "/audit-preview"
}
