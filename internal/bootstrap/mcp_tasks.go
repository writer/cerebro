package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/mcpoperations"
)

type mcpTaskPacketBuilder interface {
	Build(context.Context, agentplatform.EvidencePacketRequest) (agentplatform.AgentEvidencePacket, *agentplatform.AgentCoverageContext, error)
}

type mcpTaskPacketContext interface {
	agentCoverageContext(context.Context, string) (*agentplatform.AgentCoverageContext, error)
}

type currentAgentEvidencePacketBuilder struct{ context mcpTaskPacketContext }

func (builder currentAgentEvidencePacketBuilder) Build(ctx context.Context, request agentplatform.EvidencePacketRequest) (agentplatform.AgentEvidencePacket, *agentplatform.AgentCoverageContext, error) {
	resolved, err := resolveAgentPlatformRequestContext(ctx, "", "", request.RequestedScopes)
	if err != nil {
		return agentplatform.AgentEvidencePacket{}, nil, err
	}
	request.TenantID, request.ActorID = resolved.TenantID, resolved.ActorID
	request.RequestedScopes, request.ScopeUnrestricted = resolved.RequestedScopes, resolved.ScopeUnrestricted
	request.CoverageContext, err = builder.context.agentCoverageContext(ctx, request.TenantID)
	if err != nil {
		return agentplatform.AgentEvidencePacket{}, nil, err
	}
	if err := authorizeAgentPlatformPacketURNs(ctx, request); err != nil {
		return agentplatform.AgentEvidencePacket{}, nil, err
	}
	return agentplatform.BuildEvidencePacket(request), request.CoverageContext, nil
}

func (app *App) mcpTaskRiskExplain(r *http.Request, args map[string]any) (any, error) {
	data, err := app.mcpInvestigationContext(r, args)
	if err != nil {
		return nil, err
	}
	context, _ := data.(map[string]any)
	return mcpoperations.RiskExplanation(mcpoperations.StructuredContent(context), mcpBoolArg(args, "skip_graph"))
}

func (app *App) mcpTaskEvidencePacket(r *http.Request, args map[string]any) (any, error) {
	return app.mcpTaskEvidencePacketWithBuilder(r, args, currentAgentEvidencePacketBuilder{context: app})
}

func (app *App) mcpTaskEvidencePacketWithBuilder(r *http.Request, args map[string]any, builder mcpTaskPacketBuilder) (any, error) {
	request, err := mcpoperations.EvidencePacketRequest(mcpoperations.StructuredContent(args))
	if err != nil {
		return nil, errors.Join(errInvalidHTTPRequest, err)
	}
	packet, coverage, err := builder.Build(r.Context(), request)
	if err != nil {
		return nil, err
	}
	return mcpoperations.EvidencePacket(packet, coverage)
}

func (app *App) mcpTaskSourcesHealth(r *http.Request, _ map[string]any) (any, error) {
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), "", "", nil)
	if err != nil {
		return nil, err
	}
	coverage, err := app.agentCoverageContext(r.Context(), resolved.TenantID)
	if err != nil {
		return nil, err
	}
	return mcpoperations.SourcesHealth(coverage, sourceRuntimeStore(app.deps.StateStore) != nil, app.sources != nil)
}

func (app *App) mcpTaskActionPlan(r *http.Request, args map[string]any) (any, error) {
	value, err := app.mcpRiskActionsList(r, args)
	if err != nil {
		return nil, err
	}
	plan, _ := value.(map[string]any)
	return mcpoperations.ActionPlan(mcpoperations.StructuredContent(plan), strings.TrimSpace(mcpAnyString(plan["graph_evidence_status"])) == mcpGraphEvidenceIncluded)
}
