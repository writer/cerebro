package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/jobobservability"
	"github.com/writer/cerebro/internal/jobpayload"
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
	service.WithRunner(platformjobs.KindGraphRulesEvaluate, a.runGraphRulesEvaluateJob)
	service.WithRunner(platformjobs.KindFindingRulesEvaluate, a.runFindingRulesEvaluateJob)
	service.WithRunner(platformjobs.KindFindingCandidatesEvaluate, a.runFindingCandidatesEvaluateJob)
	service.WithRunner(platformjobs.KindFindingsEvaluate, a.runFindingsEvaluateJob)
	service.WithRunner(platformjobs.KindReportRun, a.runReportJob)
	return service
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

func (a *App) runSourceRuntimeSyncJob(ctx context.Context, job *ports.Job, service *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	response, err := jobobservability.RunPhase(ctx, service, job, "source_runtime.sync", "source runtime sync", jobobservability.SourceRuntimeSyncPayload, func() (*cerebrov1.SyncSourceRuntimeResponse, error) {
		return a.runtimeService().SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{
			Id:        runtimeID,
			PageLimit: jobpayload.Uint32(job.Payload, "page_limit"),
		}, sourceruntime.SyncWithLeaseOptions{LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore)})
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeRuntime, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeGraph, grcCacheScopeInventory)
	return protoToMap(response), nil, nil
}

func (a *App) runSourceRuntimeOrchestrateJob(ctx context.Context, job *ports.Job, service *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	syncResponse, err := jobobservability.RunPhase(ctx, service, job, "source_runtime.sync", "source runtime sync", jobobservability.SourceRuntimeSyncPayload, func() (*cerebrov1.SyncSourceRuntimeResponse, error) {
		return a.runtimeService().SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{
			Id:        runtimeID,
			PageLimit: jobpayload.Uint32(job.Payload, "page_limit"),
		}, sourceruntime.SyncWithLeaseOptions{LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore)})
	})
	if err != nil {
		return nil, nil, err
	}
	graphResult, err := jobobservability.RunPhase(ctx, service, job, "orchestrator.graph_ingest", "graph ingest", jobobservability.GraphIngestPayload, func() (*graphingest.RunResult, error) {
		return a.graphIngestService().RunRuntime(ctx, graphingest.RuntimeRequest{
			RuntimeID: runtimeID,
			PageLimit: jobpayload.Uint32(job.Payload, "graph_page_limit"),
			Trigger:   "platform_orchestration_job",
		})
	})
	if err != nil {
		return nil, nil, err
	}
	ruleResult, err := jobobservability.RunPhase(ctx, service, job, "orchestrator.finding_rules", "finding rules", jobobservability.FindingRulesPayload, func() (*findings.EvaluateRulesResult, error) {
		return a.findingService().EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
			RuntimeID:  runtimeID,
			RuleIDs:    jobpayload.StringSlice(job.Payload, "rule_ids"),
			EventLimit: jobpayload.Uint32(job.Payload, "event_limit"),
		})
	})
	if err != nil {
		return nil, nil, err
	}
	graphRulesResult, err := jobobservability.RunPhase(ctx, service, job, "orchestrator.graph_rules", "graph rules", jobobservability.GraphRulesPayload, func() (*findings.EvaluateGraphRulesResult, error) {
		return a.findingService().EvaluateSourceRuntimeGraphRules(ctx, findings.EvaluateGraphRulesRequest{
			RuntimeID: runtimeID,
			RuleIDs:   jobpayload.StringSlice(job.Payload, "graph_rule_ids"),
		})
	})
	if err != nil {
		return nil, nil, err
	}
	graphOut, err := jsonResultMap(graphResult)
	if err != nil {
		return nil, nil, err
	}
	ruleOut, err := jsonResultMap(ruleResult)
	if err != nil {
		return nil, nil, err
	}
	graphRulesOut, err := jsonResultMap(graphRulesResult)
	if err != nil {
		return nil, nil, err
	}
	result := map[string]any{
		"sync":          protoToMap(syncResponse),
		"graph_ingest":  graphOut,
		"finding_rules": ruleOut,
		"graph_rules":   graphRulesOut,
	}
	refs := map[string]string{}
	if graphResult.Run.ID != "" {
		refs["graph_ingest_run_id"] = graphResult.Run.ID
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeRuntime, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeGraph, grcCacheScopeInventory)
	return result, refs, nil
}

func (a *App) runGraphIngestRuntimeJob(ctx context.Context, job *ports.Job, service *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := jobobservability.RunPhase(ctx, service, job, "graph_ingest_runtime", "graph ingest", jobobservability.GraphIngestPayload, func() (*graphingest.RunResult, error) {
		return a.graphIngestService().RunRuntime(ctx, graphingest.RuntimeRequest{
			RuntimeID: runtimeID,
			PageLimit: jobpayload.Uint32(job.Payload, "page_limit"),
			Trigger:   "platform_job",
		})
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeGraph, grcCacheScopeRuntime, grcCacheScopeInventory)
	refs := map[string]string{}
	if result.Run.ID != "" {
		refs["graph_ingest_run_id"] = result.Run.ID
	}
	out, err := jsonResultMap(result)
	return out, refs, err
}

func (a *App) runGraphRulesEvaluateJob(ctx context.Context, job *ports.Job, service *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := jobobservability.RunPhase(ctx, service, job, "graph_rules_evaluate", "graph rules", jobobservability.GraphRulesPayload, func() (*findings.EvaluateGraphRulesResult, error) {
		return a.findingService().EvaluateSourceRuntimeGraphRules(ctx, findings.EvaluateGraphRulesRequest{
			RuntimeID: runtimeID,
			RuleIDs:   jobpayload.StringSlice(job.Payload, "rule_ids"),
		})
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeGraph, grcCacheScopeInventory)
	out, err := jsonResultMap(result)
	return out, nil, err
}

func (a *App) runFindingRulesEvaluateJob(ctx context.Context, job *ports.Job, service *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := jobobservability.RunPhase(ctx, service, job, "finding_rules_evaluate", "finding rules", jobobservability.FindingRulesPayload, func() (*findings.EvaluateRulesResult, error) {
		return a.findingService().EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
			RuntimeID:  runtimeID,
			RuleIDs:    jobpayload.StringSlice(job.Payload, "rule_ids"),
			EventLimit: jobpayload.Uint32(job.Payload, "event_limit"),
		})
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	out, err := jsonResultMap(result)
	return out, nil, err
}

func (a *App) runFindingCandidatesEvaluateJob(ctx context.Context, job *ports.Job, service *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := jobobservability.RunPhase(ctx, service, job, "finding_candidates_evaluate", "candidate rules", jobobservability.CandidateRulesPayload, func() (*findings.EvaluateCandidateRulesResult, error) {
		return a.findingService().EvaluateSourceRuntimeCandidateRules(ctx, findings.EvaluateCandidateRulesRequest{
			RuntimeID:  runtimeID,
			RuleIDs:    jobpayload.StringSlice(job.Payload, "rule_ids"),
			EventLimit: jobpayload.Uint32(job.Payload, "event_limit"),
		})
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	out, err := jsonResultMap(result)
	return out, nil, err
}

func (a *App) runFindingsEvaluateJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	runtimeID := jobpayload.String(job.Payload, "runtime_id", job.SubjectID)
	if runtimeID == "" {
		return nil, nil, fmt.Errorf("%w: runtime_id is required", platformjobs.ErrInvalidRequest)
	}
	result, err := a.findingService().EvaluateSourceRuntime(ctx, findings.EvaluateRequest{
		RuntimeID:  runtimeID,
		RuleID:     jobpayload.String(job.Payload, "rule_id", ""),
		EventLimit: jobpayload.Uint32(job.Payload, "event_limit"),
	})
	if err != nil {
		return nil, nil, err
	}
	bumpGRCCacheForRuntime(ctx, a.deps, runtimeID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	return protoToMap(findingResponse(result)), nil, nil
}

func (a *App) runReportJob(ctx context.Context, job *ports.Job, _ *platformjobs.Service) (map[string]any, map[string]string, error) {
	reportID := jobpayload.String(job.Payload, "report_id", job.SubjectID)
	if reportID == "" {
		return nil, nil, fmt.Errorf("%w: report_id is required", platformjobs.ErrInvalidRequest)
	}
	parameters := jobpayload.StringMap(job.Payload, "parameters")
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
	case platformjobs.KindSourceRuntimeSync, platformjobs.KindSourceRuntimeOrchestrate, platformjobs.KindGraphIngestRuntime, platformjobs.KindGraphRulesEvaluate, platformjobs.KindFindingRulesEvaluate, platformjobs.KindFindingCandidatesEvaluate, platformjobs.KindFindingsEvaluate:
		runtimeID := jobpayload.String(request.Payload, "runtime_id", request.SubjectID)
		runtimeTenantID, err := sourceRuntimeTenantID(ctx, sourceRuntimeStore(store), runtimeID, false)
		if err != nil {
			return "", err
		}
		if err := requireMatchingJobTenant(request.TenantID, runtimeTenantID); err != nil {
			return "", err
		}
		return firstNonEmpty(request.TenantID, runtimeTenantID), nil
	case platformjobs.KindReportRun:
		parameters := jobpayload.StringMap(request.Payload, "parameters")
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

func jsonResultMap(value any) (map[string]any, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	_ = json.Unmarshal(payload, &out)
	return out, nil
}
