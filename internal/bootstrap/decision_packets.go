package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionpacket"
	"github.com/writer/cerebro/internal/decisionpacket/prototransport"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"google.golang.org/protobuf/encoding/protojson"
)

type decisionCoverageReader struct {
	store   ports.SourceRuntimeListStore
	sources *sourcecdk.Registry
	now     func() time.Time
}

func (r decisionCoverageReader) ReadCoverage(ctx context.Context, tenantID string, requiredSources []string) ([]sourcecoverage.Record, error) {
	if r.store == nil {
		return nil, decisionpacket.ErrResolverUnavailable
	}
	runtimes, err := r.store.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{TenantID: tenantID, Limit: 5000})
	if err != nil {
		return nil, err
	}
	if r.sources == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
	}
	contracts := sourcecoverage.ContractsFromRegistry(r.sources)
	observations := sourcecoverage.ObservationsFromRuntimes(runtimes, func(runtime *cerebrov1.SourceRuntime) string {
		return runtimeHealthStatus(runtime, now)
	})
	records := sourcecoverage.Evaluate(contracts, observations, sourcecoverage.Options{TenantID: strings.TrimSpace(tenantID)})
	result := make([]sourcecoverage.Record, 0, len(records))
	for _, record := range records {
		if containsAuthValue(requiredSources, record.SourceID) {
			result = append(result, record)
		}
	}
	return result, nil
}

func (a *App) newDecisionPacketService() *decisionpacket.Service {
	receipts := decisionPacketReceiptStore(a.deps.StateStore)
	if receipts == nil {
		return nil
	}
	coverageStore, _ := a.deps.StateStore.(ports.SourceRuntimeListStore)
	resolver := decisionpacket.PortsResolver{
		Findings: findingStore(a.deps.StateStore), FindingEvidence: findingEvidenceStore(a.deps.StateStore),
		Claims: claimStore(a.deps.StateStore), Evidence: evidenceLedgerStore(a.deps.StateStore),
		AuditPackets: grcAuditPacketStore(a.deps.StateStore), Graph: graphQueryStore(a.deps.GraphStore),
		Coverage: decisionCoverageReader{store: coverageStore, sources: a.sources}, Actions: graphactions.DefaultRegistry(),
	}
	return decisionpacket.NewPersistentService(resolver, decisionpacket.SystemClock{}, receipts, a.cfg.StateStore.DecisionPacketRetention)
}

func (a *App) handleBuildDecisionPacket(w http.ResponseWriter, r *http.Request) {
	if a.services.decisionPackets == nil {
		writeDecisionPacketHTTPError(w, decisionpacket.ErrResolverUnavailable)
		return
	}
	request := &cerebrov1.BuildDecisionPacketRequest{}
	if err := decodeDecisionPacketRequest(r, request); err != nil {
		writeDecisionPacketHTTPError(w, err)
		return
	}
	tenant, actor, err := decisionPacketIdentity(r.Context(), requestTenantHint(r), r.Header.Get("X-Cerebro-Actor"))
	if err != nil {
		writeDecisionPacketHTTPError(w, err)
		return
	}
	packet, err := a.services.decisionPackets.Build(r.Context(), tenant, actor, decisionPacketDomainRequest(request))
	if err != nil {
		writeDecisionPacketHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, packet)
}

func decodeDecisionPacketRequest(r *http.Request, request *cerebrov1.BuildDecisionPacketRequest) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProtoJSONBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read request body", errInvalidHTTPRequest)
	}
	if len(body) > maxProtoJSONBodyBytes {
		return fmt.Errorf("%w: request body exceeds %d bytes", errInvalidHTTPRequest, maxProtoJSONBodyBytes)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, request); err != nil {
		return fmt.Errorf("%w: decode request body", errInvalidHTTPRequest)
	}
	return nil
}

func (a *App) handleGetDecisionPacket(w http.ResponseWriter, r *http.Request) {
	if a.services.decisionPackets == nil {
		writeDecisionPacketHTTPError(w, decisionpacket.ErrResolverUnavailable)
		return
	}
	tenant, _, err := decisionPacketIdentity(r.Context(), requestTenantHint(r), r.Header.Get("X-Cerebro-Actor"))
	if err != nil {
		writeDecisionPacketHTTPError(w, err)
		return
	}
	packet, err := a.services.decisionPackets.GetReceipt(r.Context(), tenant, r.PathValue("packetID"))
	if err != nil {
		writeDecisionPacketHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, packet)
}

func (s *bootstrapService) BuildDecisionPacket(ctx context.Context, request *connect.Request[cerebrov1.BuildDecisionPacketRequest]) (*connect.Response[cerebrov1.BuildDecisionPacketResponse], error) {
	if s.decisionPackets == nil {
		return nil, decisionPacketConnectError(decisionpacket.ErrResolverUnavailable)
	}
	tenant, actor, err := decisionPacketIdentity(ctx, request.Header().Get("X-Cerebro-Tenant"), request.Header().Get("X-Cerebro-Actor"))
	if err != nil {
		return nil, decisionPacketConnectError(err)
	}
	packet, err := s.decisionPackets.Build(ctx, tenant, actor, decisionPacketDomainRequest(request.Msg))
	if err != nil {
		return nil, decisionPacketConnectError(err)
	}
	message, err := prototransport.Packet(packet)
	if err != nil {
		return nil, decisionPacketConnectError(err)
	}
	return connect.NewResponse(&cerebrov1.BuildDecisionPacketResponse{Packet: message}), nil
}

func decisionPacketIdentity(ctx context.Context, tenantHint, actorHint string) (decisionpacket.AuthorizedTenant, decisionpacket.AuthorizedActor, error) {
	tenantID, err := effectiveTenantFilter(ctx, tenantHint)
	if err != nil {
		return decisionpacket.AuthorizedTenant{}, decisionpacket.AuthorizedActor{}, err
	}
	actorID := strings.TrimSpace(actorHint)
	scopes := []string{scopeCosmoSecurityRead}
	if auth, ok := ctx.Value(authContextKey{}).(authContext); ok {
		actorID = strings.TrimSpace(auth.principal.Name)
		if actorID == "" {
			actorID = strings.TrimSpace(auth.principal.CredentialID)
		}
		scopes = expandedPrincipalScopes(auth.principal)
	}
	if actorID == "" {
		actorID = "api"
	}
	return decisionpacket.AuthorizedTenant{ID: tenantID}, decisionpacket.AuthorizedActor{ID: actorID, Scopes: scopes}, nil
}

func decisionPacketDomainRequest(request *cerebrov1.BuildDecisionPacketRequest) decisionpacket.Request {
	if request == nil {
		return decisionpacket.Request{}
	}
	result := decisionpacket.Request{
		Workflow: request.GetWorkflow(), Question: request.GetQuestion(), ScopeURN: request.GetScopeUrn(),
		FindingIDs: request.GetFindingIds(), ClaimIDs: request.GetClaimIds(), EvidenceURNs: request.GetEvidenceUrns(),
		AuditPacketIDs: request.GetAuditPacketIds(), RequiredSources: request.GetRequiredSources(), RequestedAction: request.GetRequestedAction(),
	}
	if budgets := request.GetBudgets(); budgets != nil {
		result.Budgets = decisionpacket.Budgets{
			Evidence: int(budgets.GetEvidence()), Contradictions: int(budgets.GetContradictions()),
			CoverageGaps: int(budgets.GetCoverageGaps()), Affected: int(budgets.GetAffected()),
			Controls: int(budgets.GetControls()), AuditPackets: int(budgets.GetAuditPackets()),
			Actions: int(budgets.GetActions()), GraphRows: int(budgets.GetGraphRows()), GraphDepth: int(budgets.GetGraphDepth()),
		}
	}
	return result
}

func decisionPacketReceiptStore(store ports.StateStore) ports.DecisionPacketReceiptStore {
	result, ok := store.(ports.DecisionPacketReceiptStore)
	if !ok || isNilInterface(result) {
		return nil
	}
	return result
}

func evidenceLedgerStore(store ports.StateStore) ports.EvidenceLedgerStore {
	result, ok := store.(ports.EvidenceLedgerStore)
	if !ok || isNilInterface(result) {
		return nil
	}
	return result
}

func grcAuditPacketStore(store ports.StateStore) ports.GRCAuditPacketStore {
	result, ok := store.(ports.GRCAuditPacketStore)
	if !ok || isNilInterface(result) {
		return nil
	}
	return result
}

func writeDecisionPacketHTTPError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		status = http.StatusForbidden
	case errors.Is(err, decisionpacket.ErrInvalidRequest), errors.Is(err, decisionpacket.ErrInvalidBudget), errors.Is(err, errInvalidHTTPRequest):
		status = http.StatusBadRequest
	case errors.Is(err, decisionpacket.ErrProtectedReference), errors.Is(err, ports.ErrDecisionPacketNotFound):
		status = http.StatusNotFound
	case errors.Is(err, decisionpacket.ErrResolverUnavailable):
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"error": http.StatusText(status)})
}

func decisionPacketConnectError(err error) error {
	code := connect.CodeInternal
	switch {
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		code = connect.CodePermissionDenied
	case errors.Is(err, decisionpacket.ErrInvalidRequest), errors.Is(err, decisionpacket.ErrInvalidBudget), errors.Is(err, errInvalidHTTPRequest):
		code = connect.CodeInvalidArgument
	case errors.Is(err, decisionpacket.ErrProtectedReference), errors.Is(err, ports.ErrDecisionPacketNotFound):
		code = connect.CodeNotFound
	case errors.Is(err, decisionpacket.ErrResolverUnavailable):
		code = connect.CodeUnavailable
	}
	return connect.NewError(code, fmt.Errorf("decision packet request failed: %w", err))
}
