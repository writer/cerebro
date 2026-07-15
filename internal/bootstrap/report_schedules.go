package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/reportschedule"
)

const (
	reportSchedulePollInterval       = 30 * time.Second
	reportScheduleMinIntervalSeconds = int64(60)
	reportScheduleMaxIntervalSeconds = int64(31 * 24 * 60 * 60)
)

type reportScheduleView struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	ReportID        string            `json:"report_id"`
	Parameters      map[string]string `json:"parameters"`
	IntervalSeconds int64             `json:"interval_seconds"`
	Enabled         bool              `json:"enabled"`
	NextRunAt       string            `json:"next_run_at"`
	LastRunAt       string            `json:"last_run_at,omitempty"`
	CreatedAt       string            `json:"created_at"`
	UpdatedAt       string            `json:"updated_at"`
}

type reportScheduleResponse struct {
	Schedule reportScheduleView `json:"schedule"`
}

type reportScheduleListResponse struct {
	Schedules []reportScheduleView `json:"schedules"`
}

type createReportScheduleRequest struct {
	TenantID        string            `json:"tenant_id"`
	ReportID        string            `json:"report_id"`
	Parameters      map[string]string `json:"parameters"`
	IntervalSeconds int64             `json:"interval_seconds"`
	Enabled         *bool             `json:"enabled"`
}

type updateReportScheduleRequest struct {
	IntervalSeconds *int64            `json:"interval_seconds"`
	Enabled         *bool             `json:"enabled"`
	Parameters      map[string]string `json:"parameters"`
}

func (a *App) handleCreateReportSchedule(w http.ResponseWriter, r *http.Request) {
	store := reportScheduleStore(a.deps.StateStore)
	if store == nil {
		writeReportError(w, fmt.Errorf("%w: report schedules are not configured", reports.ErrRuntimeUnavailable))
		return
	}
	var request createReportScheduleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeReportError(w, fmt.Errorf("%w: decode report schedule: %w", reports.ErrInvalidRequest, err))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeReportError(w, err)
		return
	}
	if tenantID == "" {
		writeReportError(w, fmt.Errorf("%w: tenant_id is required", reports.ErrInvalidRequest))
		return
	}
	definition, err := a.lookupReportDefinition(request.ReportID)
	if err != nil {
		writeReportError(w, err)
		return
	}
	interval, err := normalizeReportScheduleInterval(request.IntervalSeconds)
	if err != nil {
		writeReportError(w, err)
		return
	}
	parameters := sanitizeReportScheduleParameters(request.Parameters)
	parameters["tenant_id"] = tenantID
	if err := validateReportScheduleParameters(definition, parameters); err != nil {
		writeReportError(w, err)
		return
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	now := time.Now().UTC()
	schedule := &ports.ReportSchedule{
		ID:              newReportScheduleID(),
		TenantID:        tenantID,
		ReportID:        definition.GetId(),
		Parameters:      parameters,
		IntervalSeconds: interval,
		Enabled:         enabled,
		NextRunAt:       now.Add(time.Duration(interval) * time.Second),
	}
	if err := store.PutReportSchedule(r.Context(), schedule); err != nil {
		writeReportError(w, err)
		return
	}
	stored, err := store.GetReportSchedule(r.Context(), schedule.ID)
	if err != nil {
		writeReportError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, reportScheduleResponse{Schedule: newReportScheduleView(stored)})
}

func (a *App) handleListReportSchedules(w http.ResponseWriter, r *http.Request) {
	store := reportScheduleStore(a.deps.StateStore)
	if store == nil {
		writeReportError(w, fmt.Errorf("%w: report schedules are not configured", reports.ErrRuntimeUnavailable))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeReportError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeReportError(w, fmt.Errorf("%w: %w", reports.ErrInvalidRequest, err))
		return
	}
	schedules, err := store.ListReportSchedules(r.Context(), ports.ReportScheduleFilter{TenantID: tenantID, Limit: limit})
	if err != nil {
		writeReportError(w, err)
		return
	}
	views := make([]reportScheduleView, 0, len(schedules))
	for _, schedule := range schedules {
		views = append(views, newReportScheduleView(schedule))
	}
	writeJSON(w, http.StatusOK, reportScheduleListResponse{Schedules: views})
}

func (a *App) handleUpdateReportSchedule(w http.ResponseWriter, r *http.Request) {
	store := reportScheduleStore(a.deps.StateStore)
	if store == nil {
		writeReportError(w, fmt.Errorf("%w: report schedules are not configured", reports.ErrRuntimeUnavailable))
		return
	}
	existing, err := store.GetReportSchedule(r.Context(), r.PathValue("scheduleID"))
	if err != nil {
		writeReportError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), existing.TenantID); err != nil {
		writeReportError(w, normalizeIDLookupError(err, ports.ErrReportScheduleNotFound))
		return
	}
	var request updateReportScheduleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeReportError(w, fmt.Errorf("%w: decode report schedule: %w", reports.ErrInvalidRequest, err))
		return
	}
	now := time.Now().UTC()
	if request.Parameters != nil {
		definition, err := a.lookupReportDefinition(existing.ReportID)
		if err != nil {
			writeReportError(w, err)
			return
		}
		parameters := sanitizeReportScheduleParameters(request.Parameters)
		parameters["tenant_id"] = existing.TenantID
		if err := validateReportScheduleParameters(definition, parameters); err != nil {
			writeReportError(w, err)
			return
		}
		existing.Parameters = parameters
	}
	if request.IntervalSeconds != nil {
		interval, err := normalizeReportScheduleInterval(*request.IntervalSeconds)
		if err != nil {
			writeReportError(w, err)
			return
		}
		existing.IntervalSeconds = interval
		existing.NextRunAt = now.Add(time.Duration(interval) * time.Second)
	}
	if request.Enabled != nil {
		existing.Enabled = *request.Enabled
		if existing.Enabled && (existing.NextRunAt.IsZero() || existing.NextRunAt.Before(now)) {
			existing.NextRunAt = now.Add(time.Duration(existing.IntervalSeconds) * time.Second)
		}
	}
	if err := store.PutReportSchedule(r.Context(), existing); err != nil {
		writeReportError(w, err)
		return
	}
	stored, err := store.GetReportSchedule(r.Context(), existing.ID)
	if err != nil {
		writeReportError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, reportScheduleResponse{Schedule: newReportScheduleView(stored)})
}

func (a *App) handleDeleteReportSchedule(w http.ResponseWriter, r *http.Request) {
	store := reportScheduleStore(a.deps.StateStore)
	if store == nil {
		writeReportError(w, fmt.Errorf("%w: report schedules are not configured", reports.ErrRuntimeUnavailable))
		return
	}
	existing, err := store.GetReportSchedule(r.Context(), r.PathValue("scheduleID"))
	if err != nil {
		writeReportError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), existing.TenantID); err != nil {
		writeReportError(w, normalizeIDLookupError(err, ports.ErrReportScheduleNotFound))
		return
	}
	if err := store.DeleteReportSchedule(r.Context(), existing.ID); err != nil {
		writeReportError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleListReportRuns(w http.ResponseWriter, r *http.Request) {
	lister := reportRunLister(a.deps.StateStore)
	if lister == nil {
		writeReportError(w, fmt.Errorf("%w: report runs are not listable", reports.ErrRuntimeUnavailable))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeReportError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeReportError(w, fmt.Errorf("%w: %w", reports.ErrInvalidRequest, err))
		return
	}
	runs, err := lister.ListReportRuns(r.Context(), ports.ReportRunFilter{
		TenantID: tenantID,
		ReportID: strings.TrimSpace(r.URL.Query().Get("report_id")),
		Limit:    limit,
	})
	if err != nil {
		writeReportError(w, err)
		return
	}
	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	items := make([]json.RawMessage, 0, len(runs))
	for _, run := range runs {
		payload, err := marshaler.Marshal(run)
		if err != nil {
			writeReportError(w, fmt.Errorf("%w: marshal report run: %w", reports.ErrRuntimeUnavailable, err))
			return
		}
		items = append(items, json.RawMessage(payload))
	}
	writeJSON(w, http.StatusOK, map[string][]json.RawMessage{"runs": items})
}

// RunDueReportSchedules claims every schedule whose next run is due and enqueues
// a report-run job for each. It returns the number of schedules enqueued.
func (a *App) RunDueReportSchedules(ctx context.Context) (int, error) {
	store := reportScheduleStore(a.deps.StateStore)
	if store == nil {
		return 0, nil
	}
	return reportschedule.RunDue(ctx, store, a.jobService(), time.Now().UTC())
}

// StartReportScheduler launches the background loop that periodically enqueues
// due report-run jobs. The returned channel closes when the loop stops, which it
// does when the context is cancelled.
func (a *App) StartReportScheduler(ctx context.Context, logf func(string, ...any)) <-chan struct{} {
	done := make(chan struct{})
	if reportScheduleStore(a.deps.StateStore) == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(reportSchedulePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := a.RunDueReportSchedules(ctx); err != nil && ctx.Err() == nil {
					logf("run due report schedules: %v", err)
				}
			}
		}
	}()
	return done
}

func (a *App) lookupReportDefinition(reportID string) (*cerebrov1.ReportDefinition, error) {
	reportID = strings.TrimSpace(reportID)
	if reportID == "" {
		return nil, fmt.Errorf("%w: report_id is required", reports.ErrInvalidRequest)
	}
	for _, definition := range a.reportService().List().GetReports() {
		if definition.GetId() == reportID {
			return definition, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", reports.ErrReportNotFound, reportID)
}

func validateReportScheduleParameters(definition *cerebrov1.ReportDefinition, parameters map[string]string) error {
	for _, parameter := range definition.GetParameters() {
		if !parameter.GetRequired() || parameter.GetId() == "tenant_id" {
			continue
		}
		if strings.TrimSpace(parameters[parameter.GetId()]) == "" {
			return fmt.Errorf("%w: report parameter %q is required", reports.ErrInvalidRequest, parameter.GetId())
		}
	}
	return nil
}

func normalizeReportScheduleInterval(seconds int64) (int64, error) {
	switch {
	case seconds <= 0:
		return 0, fmt.Errorf("%w: interval_seconds is required", reports.ErrInvalidRequest)
	case seconds < reportScheduleMinIntervalSeconds:
		return 0, fmt.Errorf("%w: interval_seconds must be at least %d", reports.ErrInvalidRequest, reportScheduleMinIntervalSeconds)
	case seconds > reportScheduleMaxIntervalSeconds:
		return 0, fmt.Errorf("%w: interval_seconds must be at most %d", reports.ErrInvalidRequest, reportScheduleMaxIntervalSeconds)
	default:
		return seconds, nil
	}
}

func sanitizeReportScheduleParameters(parameters map[string]string) map[string]string {
	sanitized := make(map[string]string, len(parameters))
	for key, value := range parameters {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		sanitized[key] = strings.TrimSpace(value)
	}
	return sanitized
}

func newReportScheduleView(schedule *ports.ReportSchedule) reportScheduleView {
	view := reportScheduleView{
		ID:              schedule.ID,
		TenantID:        schedule.TenantID,
		ReportID:        schedule.ReportID,
		Parameters:      schedule.Parameters,
		IntervalSeconds: schedule.IntervalSeconds,
		Enabled:         schedule.Enabled,
		NextRunAt:       schedule.NextRunAt.UTC().Format(time.RFC3339),
		CreatedAt:       schedule.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:       schedule.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if view.Parameters == nil {
		view.Parameters = map[string]string{}
	}
	if !schedule.LastRunAt.IsZero() {
		view.LastRunAt = schedule.LastRunAt.UTC().Format(time.RFC3339)
	}
	return view
}

func newReportScheduleID() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Sprintf("report-schedule-%d", time.Now().UnixNano())
	}
	return "report-schedule-" + hex.EncodeToString(random[:])
}

func reportScheduleStore(store ports.StateStore) ports.ReportScheduleStore {
	scheduleStore, ok := store.(ports.ReportScheduleStore)
	if !ok || isNilInterface(scheduleStore) {
		return nil
	}
	return scheduleStore
}

func reportRunLister(store ports.StateStore) ports.ReportRunLister {
	lister, ok := store.(ports.ReportRunLister)
	if !ok || isNilInterface(lister) {
		return nil
	}
	return lister
}
