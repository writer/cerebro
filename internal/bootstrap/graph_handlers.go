package bootstrap

import (
	"fmt"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionops"
	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/graphstore"
	knowledgetransport "github.com/writer/cerebro/internal/knowledge/transport"
	"github.com/writer/cerebro/internal/workflowprojection"
)

func (a *App) handleWriteDecision(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteDecisionRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	metadata := map[string]any{}
	if request.GetMetadata() != nil {
		metadata = request.GetMetadata().AsMap()
	}
	if strings.TrimSpace(request.GetPacketId()) != "" {
		tenant, actor, err := decisionPacketIdentity(r.Context(), tenantIDFromMetadata(metadata), r.Header.Get("X-Cerebro-Actor"))
		if err != nil {
			writeKnowledgeError(w, err)
			return
		}
		result, err := newDecisionOutcomeService(a.deps).RecordDecision(r.Context(), decisionops.RecordDecisionRequest{
			TenantID: tenant.ID, ActorID: actor.ID, PacketID: request.GetPacketId(),
			Disposition: decisionworkflow.Disposition(request.GetDecisionDisposition()),
			Reason:      decisionworkflow.DismissalReason(request.GetDispositionReason()),
		})
		if err != nil {
			writeKnowledgeError(w, err)
			return
		}
		writeProtoJSON(w, http.StatusCreated, knowledgetransport.DecisionResponse(&result.Write))
		return
	}
	if err := authorizeKnowledgeTenant(r.Context(), metadata, append(append([]string{}, request.GetTargetIds()...), append(request.GetEvidenceIds(), request.GetActionIds()...)...)...); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	result, err := a.knowledgeService().WriteDecision(r.Context(), knowledgetransport.DecisionRequest(request, metadata))
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusCreated, knowledgetransport.DecisionResponse(result))
}

func (a *App) handleWriteAction(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteActionRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	metadata := map[string]any{}
	if request.GetMetadata() != nil {
		metadata = request.GetMetadata().AsMap()
	}
	if err := authorizeKnowledgeTenant(r.Context(), metadata, append(append([]string{request.GetDecisionId()}, request.GetTargetIds()...), request.GetRecommendationId())...); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	result, err := a.knowledgeService().WriteAction(r.Context(), knowledgetransport.ActionRequest(request, metadata))
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	knowledgetransport.RecordDecisionAction(r.Context(), request, metadata, result)
	writeProtoJSON(w, http.StatusCreated, knowledgetransport.ActionResponse(result))
}

func (a *App) handleWriteOutcome(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.WriteOutcomeRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	metadata := map[string]any{}
	if request.GetMetadata() != nil {
		metadata = request.GetMetadata().AsMap()
	}
	tenant, actor, err := decisionPacketIdentity(r.Context(), tenantIDFromMetadata(metadata), r.Header.Get("X-Cerebro-Actor"))
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	result, recorded, err := newDecisionOutcomeService(a.deps).RecordPacketOutcome(r.Context(), decisionops.RecordPacketOutcomeRequest{
		TenantID: tenant.ID, ActorID: actor.ID, DecisionID: request.GetDecisionId(), OutcomeType: request.GetOutcomeType(),
		AuditPacketExportReceiptID: request.GetAuditPacketExportReceiptId(),
	})
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	if recorded {
		writeProtoJSON(w, http.StatusCreated, knowledgetransport.OutcomeResponse(&result.Write))
		return
	}
	if err := authorizeKnowledgeTenant(r.Context(), metadata, append([]string{request.GetDecisionId()}, request.GetTargetIds()...)...); err != nil {
		writeKnowledgeError(w, err)
		return
	}
	legacyResult, err := a.knowledgeService().WriteOutcome(r.Context(), knowledgetransport.OutcomeRequest(request, metadata))
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusCreated, knowledgetransport.OutcomeResponse(legacyResult))
}

func (a *App) handleReplayWorkflowEvents(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ReplayWorkflowEventsRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeWorkflowReplayError(w, err)
		return
	}
	if err := authorizeTenantScopeRequired(r.Context(), request.GetTenantId()); err != nil {
		writeWorkflowReplayError(w, err)
		return
	}
	result, err := a.workflowReplayService().Replay(r.Context(), workflowprojection.ReplayRequest{
		KindPrefix:      request.GetKindPrefix(),
		TenantID:        request.GetTenantId(),
		AttributeEquals: request.GetAttributeEquals(),
		Limit:           request.GetLimit(),
	})
	if err != nil {
		writeWorkflowReplayError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, workflowReplayResponse(result))
}

func (a *App) handleGetEntityNeighborhood(w http.ResponseWriter, r *http.Request) {
	ctx, err := withParityCorrelation(r)
	if err != nil {
		writeGraphQueryError(w, fmt.Errorf("%w: %w", graphquery.ErrInvalidRequest, err))
		return
	}
	r = r.WithContext(ctx) //nolint:contextcheck // ctx is derived from the inbound request context after validating parity headers.
	request := &cerebrov1.GetEntityNeighborhoodRequest{}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeGraphQueryError(w, err)
			return
		}
	}
	request.RootUrn = r.URL.Query().Get("root_urn")
	tenantID, applicationWorkspaceID, err := requestTenantWorkspaceSelector(r)
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	if tenantID == "" {
		tenantID = tenantIDFromCerebroURN(request.GetRootUrn())
	}
	if err := authorizeApplicationWorkspaceID(r.Context(), tenantID, applicationWorkspaceID); err != nil { //nolint:contextcheck // r carries the validated parity context above.
		writeGraphQueryError(w, err)
		return
	}
	response, err := a.graphQueryService().GetEntityNeighborhood(r.Context(), graphquery.NeighborhoodRequest{ //nolint:contextcheck // r carries the validated parity context above.
		RootURN:                request.GetRootUrn(),
		TenantID:               tenantID,
		ApplicationWorkspaceID: applicationWorkspaceID,
		Limit:                  request.GetLimit(),
	})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, graphNeighborhoodResponse(response))
}

func (a *App) handleGetVulnerabilityImpact(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	a.handleGetGraphImpact(w, r, graphquery.ImpactRequest{
		Kind:       graphquery.ImpactKindVulnerability,
		TenantID:   tenantID,
		Identifier: r.PathValue("id"),
	})
}

func (a *App) handleGetPackageImpact(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	a.handleGetGraphImpact(w, r, graphquery.ImpactRequest{
		Kind:       graphquery.ImpactKindPackage,
		TenantID:   tenantID,
		Identifier: r.URL.Query().Get("package"),
	})
}

func (a *App) handleGetAssetImpact(w http.ResponseWriter, r *http.Request) {
	rootURN := r.URL.Query().Get("urn")
	if err := authorizeCerebroURNTenant(r.Context(), rootURN); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	a.handleGetGraphImpact(w, r, graphquery.ImpactRequest{
		Kind:    graphquery.ImpactKindAsset,
		RootURN: rootURN,
	})
}

func (a *App) handleGetGraphImpact(w http.ResponseWriter, r *http.Request, request graphquery.ImpactRequest) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	depth, err := uint32QueryParam(r, "depth")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	request.Limit = limit
	request.Depth = depth
	result, err := a.graphQueryService().GetImpact(r.Context(), request)
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleGetAWSPublicEndpointInsights(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	result, err := a.graphQueryService().GetAWSPublicEndpointInsights(r.Context(), graphquery.AWSPublicEndpointInsightsRequest{
		TenantID:  tenantID,
		AccountID: r.URL.Query().Get("account_id"),
		Region:    r.URL.Query().Get("region"),
		Search:    r.URL.Query().Get("search"),
		Limit:     limit,
	})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleGetAttackPaths(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	result, err := a.graphQueryService().GetAttackPaths(r.Context(), graphquery.AttackPathRequest{
		TenantID:  tenantID,
		AccountID: r.URL.Query().Get("account_id"),
		Limit:     limit,
	})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleGetPersonAccessPaths(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	personURN := r.URL.Query().Get("person_urn")
	if strings.TrimSpace(personURN) != "" {
		if err := authorizeCerebroURNTenant(r.Context(), personURN); err != nil {
			writeGraphQueryError(w, err)
			return
		}
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	depth, err := uint32QueryParam(r, "depth")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	result, err := a.graphQueryService().GetPersonAccessPaths(r.Context(), graphquery.PersonAccessPathRequest{
		TenantID:    tenantID,
		PersonURN:   personURN,
		PersonQuery: firstNonEmpty(r.URL.Query().Get("person_query"), r.URL.Query().Get("q")),
		Limit:       limit,
		Depth:       depth,
	})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleGetEffectiveAccessPaths(w http.ResponseWriter, r *http.Request) {
	request, err := graphquery.EffectiveAccessPathRequestFromQuery(r.URL.Query())
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	result, err := a.graphQueryService().GetEffectiveAccessPaths(r.Context(), request)
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleGetCrownJewelRankings(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	depth, err := uint32QueryParam(r, "depth")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	seedLimit, err := uint32QueryParam(r, "seed_limit")
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	result, err := a.graphQueryService().GetCrownJewelRanks(r.Context(), graphquery.CrownJewelRankRequest{
		TenantID:   tenantID,
		AccountID:  r.URL.Query().Get("account_id"),
		EntityType: r.URL.Query().Get("entity_type"),
		Limit:      limit,
		Depth:      depth,
		SeedLimit:  seedLimit,
	})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleRunGraphIngestRuntime(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.RunGraphIngestRuntimeRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeGraphIngestError(w, fmt.Errorf("%w: %w", graphingest.ErrInvalidRequest, err))
		return
	}
	if pageLimit := r.URL.Query().Get("page_limit"); pageLimit != "" {
		overrides := &cerebrov1.RunGraphIngestRuntimeRequest{}
		body := []byte(`{"page_limit":` + pageLimit + `}`)
		if err := unmarshalHTTPProtoJSON(body, overrides); err != nil {
			writeGraphIngestError(w, err)
			return
		}
		request.PageLimit = overrides.GetPageLimit()
	}
	if resetCheckpoint := r.URL.Query().Get("reset_checkpoint"); resetCheckpoint != "" {
		overrides := &cerebrov1.RunGraphIngestRuntimeRequest{}
		body := []byte(`{"reset_checkpoint":` + resetCheckpoint + `}`)
		if err := unmarshalHTTPProtoJSON(body, overrides); err != nil {
			writeGraphIngestError(w, err)
			return
		}
		request.ResetCheckpoint = overrides.GetResetCheckpoint()
	}
	if checkpointID := r.URL.Query().Get("checkpoint_id"); checkpointID != "" {
		request.CheckpointId = checkpointID
	}
	request.RuntimeId = r.PathValue("runtimeID")
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeGraphIngestError(w, err)
		return
	}
	result, err := a.graphIngestService().RunRuntime(r.Context(), graphingest.RuntimeRequest{
		RuntimeID:       request.GetRuntimeId(),
		PageLimit:       request.GetPageLimit(),
		CheckpointID:    request.GetCheckpointId(),
		ResetCheckpoint: request.GetResetCheckpoint(),
		Trigger:         "api",
	})
	if err != nil {
		writeGraphIngestError(w, err)
		return
	}
	bumpGRCCacheForRuntime(r.Context(), a.deps, request.GetRuntimeId(), grcCacheScopeGraph, grcCacheScopeRuntime, grcCacheScopeInventory)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.RunGraphIngestRuntimeResponse{
		Result: graphIngestRunResultMessage(result),
	})
}

func (a *App) handleGetGraphIngestRun(w http.ResponseWriter, r *http.Request) {
	run, err := a.graphIngestService().GetRun(r.Context(), r.PathValue("runID"))
	if err != nil {
		writeGraphIngestError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), run.TenantID); err != nil {
		writeGraphIngestError(w, normalizeIDLookupError(err, graphingest.ErrRunNotFound))
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetGraphIngestRunResponse{
		Run: graphingest.RunMessage(run),
	})
}

func (a *App) handleListGraphIngestRuns(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListGraphIngestRunsRequest{
		RuntimeId: r.URL.Query().Get("runtime_id"),
		Status:    r.URL.Query().Get("status"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeGraphIngestError(w, err)
			return
		}
		request.RuntimeId = r.URL.Query().Get("runtime_id")
		request.Status = r.URL.Query().Get("status")
	}
	if err := authorizeGraphIngestRunListScope(r.Context(), request.GetRuntimeId()); err != nil {
		writeGraphIngestError(w, err)
		return
	}
	if request.GetRuntimeId() != "" {
		if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
			writeGraphIngestError(w, err)
			return
		}
	}
	result, err := a.graphIngestService().ListRuns(r.Context(), graphstore.IngestRunFilter{
		RuntimeID: request.GetRuntimeId(),
		Status:    request.GetStatus(),
		Limit:     int(request.GetLimit()),
	})
	if err != nil {
		writeGraphIngestError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, graphIngestListResponse(result))
}

func (a *App) handleCheckGraphIngestHealth(w http.ResponseWriter, r *http.Request) {
	if err := authorizeGlobalGraphHealthScope(r.Context()); err != nil {
		writeGraphIngestError(w, err)
		return
	}
	request := &cerebrov1.CheckGraphIngestHealthRequest{}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeGraphIngestError(w, err)
			return
		}
	}
	result, err := a.graphIngestService().Health(r.Context(), request.GetLimit())
	if err != nil {
		writeGraphIngestError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, graphIngestHealthResponse(result))
}
