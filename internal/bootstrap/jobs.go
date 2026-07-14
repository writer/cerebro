package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/appendlogindex"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type createJobHTTPRequest struct {
	Kind           string         `json:"kind"`
	TenantID       string         `json:"tenant_id"`
	SubjectType    string         `json:"subject_type"`
	SubjectID      string         `json:"subject_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	Payload        map[string]any `json:"payload"`
}

type jobResponse struct {
	Job *ports.Job `json:"job"`
}

type jobListResponse struct {
	Jobs []*ports.Job `json:"jobs"`
}

type jobEventListResponse struct {
	Events []*ports.JobEvent `json:"events"`
}

func (a *App) jobService() *platformjobs.Service {
	if a != nil && a.services.jobs != nil {
		return a.services.jobs
	}
	return a.newJobService()
}

func (a *App) newJobService() *platformjobs.Service {
	service := newJobFeatureService(newJobFeatureDeps(a.deps))
	service.WithRunner(platformjobs.KindSourceRuntimeSync, a.runSourceRuntimeSyncJob)
	service.WithRunner(platformjobs.KindSourceRuntimeOrchestrate, a.runSourceRuntimeOrchestrateJob)
	service.WithRunner(platformjobs.KindGraphIngestRuntime, a.runGraphIngestRuntimeJob)
	service.WithRunner(platformjobs.KindFindingRulesEvaluate, a.runFindingRulesEvaluateJob)
	service.WithRunner(platformjobs.KindFindingsEvaluate, a.runFindingsEvaluateJob)
	service.WithRunner(platformjobs.KindReportRun, a.runReportJob)
	if a.cfg.AppendLog.JetStreamRuntimeIndexEnabled {
		service.WithRunner(platformjobs.KindAppendLogRuntimeIndex, a.runAppendLogRuntimeIndexJob)
	}
	return service
}

// RecoverPlatformJobs resumes queued work and jobs whose worker lease expired.
// Claiming is owner-checked, so every server replica may call this at startup.
func (a *App) RecoverPlatformJobs(ctx context.Context) (int, error) {
	if _, ok := a.deps.StateStore.(ports.JobLeaseStore); !ok {
		return 0, nil
	}
	return a.jobService().Recover(ctx, 0)
}

// StartPlatformJobRecovery continuously makes expired leases runnable. The
// returned channel closes after cancellation and is included in shutdown waits.
func (a *App) StartPlatformJobRecovery(ctx context.Context, logf func(string, ...any)) <-chan struct{} {
	return a.jobService().StartRecovery(ctx, logf)
}

func (a *App) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var request createJobHTTPRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		writeJobError(w, fmt.Errorf("%w: decode job request: %w", platformjobs.ErrInvalidRequest, err))
		return
	}
	if request.IdempotencyKey == "" {
		request.IdempotencyKey = r.Header.Get("Idempotency-Key")
	}
	if request.Payload == nil {
		request.Payload = map[string]any{}
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeJobError(w, err)
		return
	}
	request.TenantID = tenantID
	tenantID, err = authorizeJobCreate(r.Context(), a.deps.StateStore, request)
	if err != nil {
		writeJobError(w, err)
		return
	}
	request.TenantID = tenantID
	job, created, err := a.jobService().Create(r.Context(), ports.CreateJobRequest{
		Kind:           request.Kind,
		TenantID:       request.TenantID,
		SubjectType:    request.SubjectType,
		SubjectID:      request.SubjectID,
		IdempotencyKey: request.IdempotencyKey,
		Payload:        request.Payload,
	})
	if err != nil {
		writeJobError(w, err)
		return
	}
	if created {
		a.jobService().StartAsync(r.Context(), job)
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, jobResponse{Job: job})
}

func (a *App) handleListJobs(w http.ResponseWriter, r *http.Request) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeJobError(w, err)
		return
	}
	filter := ports.JobFilter{
		Kind:   strings.TrimSpace(r.URL.Query().Get("kind")),
		Status: strings.TrimSpace(r.URL.Query().Get("status")),
		Limit:  limit,
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeJobError(w, err)
		return
	}
	filter.TenantID = tenantID
	jobs, err := a.jobService().List(r.Context(), filter)
	if err != nil {
		writeJobError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobListResponse{Jobs: jobs})
}

func (a *App) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.jobService().Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		writeJobError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), job.TenantID); err != nil {
		writeJobError(w, normalizeIDLookupError(err, ports.ErrJobNotFound))
		return
	}
	writeJSON(w, http.StatusOK, jobResponse{Job: job})
}

func (a *App) handleListJobEvents(w http.ResponseWriter, r *http.Request) {
	job, err := a.jobService().Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		writeJobError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), job.TenantID); err != nil {
		writeJobError(w, normalizeIDLookupError(err, ports.ErrJobNotFound))
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeJobError(w, err)
		return
	}
	events, err := a.jobService().Events(r.Context(), job.ID, limit)
	if err != nil {
		writeJobError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobEventListResponse{Events: events})
}

func (a *App) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	existing, err := a.jobService().Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		writeJobError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), existing.TenantID); err != nil {
		writeJobError(w, normalizeIDLookupError(err, ports.ErrJobNotFound))
		return
	}
	job, err := a.jobService().Cancel(r.Context(), existing.ID)
	if err != nil {
		writeJobError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobResponse{Job: job})
}

func (a *App) runSourceRuntimeSyncJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := stringPayload(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	response, err := a.runtimeService().SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{
		Id:        runtimeID,
		PageLimit: uint32Payload(job.Payload, "page_limit"),
	}, sourceruntime.SyncWithLeaseOptions{LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore)})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeRuntime, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeGraph, grcCacheScopeInventory)
	return protoToMap(response), nil, nil
}

func (a *App) runSourceRuntimeOrchestrateJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := stringPayload(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	syncResponse, err := a.runtimeService().SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{
		Id:        runtimeID,
		PageLimit: uint32Payload(job.Payload, "page_limit"),
	}, sourceruntime.SyncWithLeaseOptions{LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore)})
	if err != nil {
		return nil, nil, err
	}
	graphResult, err := a.graphIngestService().RunRuntime(ctx, graphingest.RuntimeRequest{
		RuntimeID: runtimeID,
		PageLimit: uint32Payload(job.Payload, "graph_page_limit"),
		Trigger:   "platform_orchestration_job",
	})
	if err != nil {
		return nil, nil, err
	}
	ruleResult, ruleErr := a.findingService().EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID:  runtimeID,
		RuleIDs:    stringSlicePayload(job.Payload, "rule_ids"),
		EventLimit: uint32Payload(job.Payload, "event_limit"),
	})
	graphPayload, err := json.Marshal(graphResult)
	if err != nil {
		return nil, nil, err
	}
	graphOut := map[string]any{}
	_ = json.Unmarshal(graphPayload, &graphOut)
	rulePayload, err := json.Marshal(ruleResult)
	if err != nil {
		return nil, nil, err
	}
	ruleOut := map[string]any{}
	_ = json.Unmarshal(rulePayload, &ruleOut)
	result := map[string]any{
		"sync":          protoToMap(syncResponse),
		"graph_ingest":  graphOut,
		"finding_rules": ruleOut,
	}
	refs := map[string]string{}
	if graphResult.Run.ID != "" {
		refs["graph_ingest_run_id"] = graphResult.Run.ID
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeRuntime, grcCacheScopeGraph, grcCacheScopeInventory)
	if ruleResult != nil {
		bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	}
	if ruleErr != nil {
		return result, refs, ruleErr
	}
	return result, refs, nil
}

func (a *App) runGraphIngestRuntimeJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := stringPayload(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := a.graphIngestService().RunRuntime(ctx, graphingest.RuntimeRequest{
		RuntimeID: runtimeID,
		PageLimit: uint32Payload(job.Payload, "page_limit"),
		Trigger:   "platform_job",
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeGraph, grcCacheScopeRuntime, grcCacheScopeInventory)
	refs := map[string]string{}
	if result.Run.ID != "" {
		refs["graph_ingest_run_id"] = result.Run.ID
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{}
	_ = json.Unmarshal(payload, &out)
	return out, refs, nil
}

func (a *App) runFindingRulesEvaluateJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := stringPayload(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, evaluationErr := a.findingService().EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID:  runtimeID,
		RuleIDs:    stringSlicePayload(job.Payload, "rule_ids"),
		EventLimit: uint32Payload(job.Payload, "event_limit"),
	})
	if result != nil {
		bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{}
	_ = json.Unmarshal(payload, &out)
	if evaluationErr != nil {
		return out, nil, evaluationErr
	}
	return out, nil, nil
}

func (a *App) runFindingsEvaluateJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := stringPayload(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := a.findingService().EvaluateSourceRuntime(ctx, findings.EvaluateRequest{
		RuntimeID:  runtimeID,
		RuleID:     stringPayload(job.Payload, "rule_id", ""),
		EventLimit: uint32Payload(job.Payload, "event_limit"),
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	return protoToMap(findingResponse(result)), nil, nil
}

// runAppendLogRuntimeIndexJob is the global (no runtime scope) maintenance job
// that advances the per-runtime append-log replay index. Bootstrap only adapts
// dependencies and payload; the population logic lives in appendlogindex.
func (a *App) runAppendLogRuntimeIndexJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	if !a.cfg.AppendLog.JetStreamRuntimeIndexEnabled {
		return nil, nil, fmt.Errorf("%w: append log runtime index is disabled", platformjobs.ErrInvalidRequest)
	}
	source, ok := a.deps.AppendLog.(ports.RuntimeIndexSource)
	if !ok || isNilInterface(source) {
		return nil, nil, fmt.Errorf("%w: append log does not support runtime indexing", platformjobs.ErrRuntimeUnavailable)
	}
	writer, ok := a.deps.StateStore.(ports.RuntimeIndexWriter)
	if !ok || isNilInterface(writer) {
		return nil, nil, fmt.Errorf("%w: state store does not support runtime indexing", platformjobs.ErrRuntimeUnavailable)
	}
	result, err := appendlogindex.Populate(ctx, source, writer, uint32Payload(job.Payload, "batch"), uint32Payload(job.Payload, "max_batches"))
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{
		"indexed_entries": result.IndexedEntries,
		"batches":         result.Batches,
		"watermark":       result.Watermark,
		"caught_up":       result.CaughtUp,
	}, nil, nil
}

func (a *App) runReportJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	reportID := stringPayload(job.Payload, "report_id", job.SubjectID)
	if reportID == "" {
		return nil, nil, fmt.Errorf("%w: report_id is required", platformjobs.ErrInvalidRequest)
	}
	parameters := stringMapPayload(job.Payload, "parameters")
	if job.TenantID != "" && parameters["tenant_id"] == "" {
		parameters["tenant_id"] = job.TenantID
	}
	response, err := a.reportService().Run(ctx, &cerebrov1.RunReportRequest{ReportId: reportID, Parameters: parameters})
	if err != nil {
		return nil, nil, err
	}
	refs := map[string]string{}
	if response.GetRun() != nil {
		refs["report_run_id"] = response.GetRun().GetId()
	}
	return protoToMap(response), refs, nil
}

func authorizeJobCreate(ctx context.Context, store ports.StateStore, request createJobHTTPRequest) (string, error) {
	if err := authorizeTenantID(ctx, request.TenantID); err != nil {
		return "", err
	}
	switch strings.TrimSpace(request.Kind) {
	case platformjobs.KindSourceRuntimeSync, platformjobs.KindSourceRuntimeOrchestrate, platformjobs.KindGraphIngestRuntime, platformjobs.KindFindingRulesEvaluate, platformjobs.KindFindingsEvaluate:
		runtimeID := stringPayload(request.Payload, "runtime_id", request.SubjectID)
		runtimeTenantID, err := sourceRuntimeTenantID(ctx, sourceRuntimeStore(store), runtimeID, false)
		if err != nil {
			return "", err
		}
		if err := requireMatchingJobTenant(request.TenantID, runtimeTenantID); err != nil {
			return "", err
		}
		return firstNonEmpty(request.TenantID, runtimeTenantID), nil
	case platformjobs.KindReportRun:
		parameters := stringMapPayload(request.Payload, "parameters")
		if request.TenantID != "" && parameters["tenant_id"] == "" {
			parameters["tenant_id"] = request.TenantID
		}
		reportTenantID := parameters["tenant_id"]
		if err := authorizeTenantID(ctx, reportTenantID); err != nil {
			return "", err
		}
		if err := requireMatchingJobTenant(request.TenantID, reportTenantID); err != nil {
			return "", err
		}
		return firstNonEmpty(request.TenantID, reportTenantID), nil
	case platformjobs.KindAppendLogRuntimeIndex:
		if err := authorizeJobAdmin(ctx); err != nil {
			return "", err
		}
		return "", nil
	default:
		return "", fmt.Errorf("%w: unsupported job kind %q", platformjobs.ErrInvalidRequest, strings.TrimSpace(request.Kind))
	}
}

func requireMatchingJobTenant(jobTenantID string, targetTenantID string) error {
	jobTenantID = strings.TrimSpace(jobTenantID)
	targetTenantID = strings.TrimSpace(targetTenantID)
	if jobTenantID == "" || targetTenantID == "" || jobTenantID == targetTenantID {
		return nil
	}
	return errTenantForbidden
}

func writeJobError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, platformjobs.ErrInvalidRequest), errors.Is(err, errInvalidHTTPRequest):
		status = http.StatusBadRequest
	case errors.Is(err, ports.ErrJobNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ports.ErrJobIdempotencyConflict), errors.Is(err, ports.ErrJobUpdateConflict), errors.Is(err, ports.ErrJobLeaseConflict):
		status = http.StatusConflict
	case errors.Is(err, platformjobs.ErrRuntimeUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, errTenantForbidden):
		status = http.StatusForbidden
	}
	writeJSON(w, status, map[string]string{"error": safeHTTPErrorMessage(status, err)})
}

func protoToMap(message proto.Message) map[string]any {
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := map[string]any{}
	_ = json.Unmarshal(payload, &out)
	return out
}

func stringPayload(payload map[string]any, key string, fallback string) string {
	if value, ok := payload[key]; ok {
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		}
	}
	return strings.TrimSpace(fallback)
}

func uint32Payload(payload map[string]any, key string) uint32 {
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		if typed > 0 {
			return uint32(typed)
		}
	case json.Number:
		parsed, _ := strconv.ParseUint(string(typed), 10, 32)
		return uint32(parsed)
	case string:
		parsed, _ := strconv.ParseUint(strings.TrimSpace(typed), 10, 32)
		return uint32(parsed)
	}
	return 0
}

func stringSlicePayload(payload map[string]any, key string) []string {
	value, ok := payload[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				values = append(values, strings.TrimSpace(text))
			}
		}
		return values
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	default:
		return nil
	}
}

func stringMapPayload(payload map[string]any, key string) map[string]string {
	result := map[string]string{}
	value, ok := payload[key]
	if !ok {
		return result
	}
	switch typed := value.(type) {
	case map[string]string:
		for k, v := range typed {
			result[k] = v
		}
	case map[string]any:
		for k, v := range typed {
			if text, ok := v.(string); ok {
				result[k] = text
			}
		}
	}
	return result
}
