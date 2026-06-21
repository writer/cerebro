package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
)

const maxGRCFindingTriageBodyBytes = 32 << 10

type grcFindingTriageRequest struct {
	TenantID    string   `json:"tenant_id"`
	FindingIDs  []string `json:"finding_ids"`
	Disposition string   `json:"disposition"`
}

type grcFindingDispositionItem struct {
	FindingID   string    `json:"finding_id"`
	Disposition string    `json:"disposition"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type grcFindingTriageResponse struct {
	Updated     []grcFindingDispositionItem `json:"updated"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

func (a *App) handleUpdateGRCFindingDispositions(w http.ResponseWriter, r *http.Request) {
	var request grcFindingTriageRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCFindingTriageBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode finding triage request: %w", errInvalidHTTPRequest, err))
		return
	}
	disposition := strings.TrimSpace(request.Disposition)
	if !ports.IsGRCFindingDisposition(disposition) {
		writeGRCError(w, fmt.Errorf("%w: disposition is invalid", errInvalidHTTPRequest))
		return
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		writeGRCError(w, fmt.Errorf("%w: tenant_id is required", errInvalidHTTPRequest))
		return
	}
	if len(grcNonEmptyFindingIDs(request.FindingIDs)) == 0 {
		writeGRCError(w, fmt.Errorf("%w: at least one finding_id is required", errInvalidHTTPRequest))
		return
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	store := grcFindingDispositionStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	records, err := store.UpsertGRCFindingDispositions(r.Context(), ports.GRCFindingDispositionBulkUpdate{
		TenantID:    tenantID,
		FindingIDs:  request.FindingIDs,
		Disposition: disposition,
		UpdatedBy:   grcInventoryUpdatedBy(r),
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeFindings)
	writeJSON(w, http.StatusOK, grcFindingTriageResponse{
		Updated:     grcFindingDispositionItems(records),
		GeneratedAt: time.Now().UTC(),
	})
}

func grcFindingDispositionItems(records []*ports.GRCFindingDispositionRecord) []grcFindingDispositionItem {
	items := make([]grcFindingDispositionItem, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		items = append(items, grcFindingDispositionItem{
			FindingID:   record.FindingID,
			Disposition: record.Disposition,
			UpdatedBy:   record.UpdatedBy,
			UpdatedAt:   record.UpdatedAt,
		})
	}
	return items
}

func grcApplyFindingDispositions(items []grcFindingItem, dispositions map[string]string) {
	if len(dispositions) == 0 {
		return
	}
	for i := range items {
		if disposition, ok := dispositions[items[i].ID]; ok {
			items[i].Disposition = disposition
		}
	}
}

func (a *App) grcFindingDispositions(r *http.Request, findings []*ports.FindingRecord) map[string]string {
	store := grcFindingDispositionStore(a.deps.StateStore)
	if store == nil {
		return nil
	}
	idsByTenant := map[string][]string{}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		tenantID := strings.TrimSpace(finding.TenantID)
		findingID := strings.TrimSpace(finding.ID)
		if tenantID == "" || findingID == "" {
			continue
		}
		idsByTenant[tenantID] = append(idsByTenant[tenantID], findingID)
	}
	dispositions := map[string]string{}
	for tenantID, ids := range idsByTenant {
		records, err := store.ListGRCFindingDispositions(r.Context(), tenantID, ids)
		if err != nil {
			return dispositions
		}
		for _, record := range records {
			if record != nil {
				dispositions[record.FindingID] = record.Disposition
			}
		}
	}
	return dispositions
}
