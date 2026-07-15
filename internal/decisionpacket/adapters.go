package decisionpacket

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

var (
	ErrProtectedReference  = errors.New("decision packet reference is unavailable")
	ErrResolverUnavailable = errors.New("decision packet resolver is unavailable")
)

type CoverageReader interface {
	ReadCoverage(context.Context, string, []string) ([]sourcecoverage.Record, error)
}

type FindingReader interface {
	GetFinding(context.Context, string) (*ports.FindingRecord, error)
}

type FindingEvidenceReader interface {
	ListFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error)
}

type ClaimReader interface {
	ListClaims(context.Context, ports.ListClaimsRequest) ([]*ports.ClaimRecord, error)
}

type AuditPacketReader interface {
	GetGRCAuditPacket(context.Context, string) (*ports.GRCAuditPacketReceipt, error)
}

type GraphReader interface {
	GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error)
}

// PortsResolver adapts current state-store and graph boundaries into bounded,
// redacted decision facts. It never executes an action.
type PortsResolver struct {
	Findings        FindingReader
	FindingEvidence FindingEvidenceReader
	Claims          ClaimReader
	AuditPackets    AuditPacketReader
	Graph           GraphReader
	Coverage        CoverageReader
	Actions         graphactions.Registry
}

func (r PortsResolver) Resolve(ctx context.Context, tenant AuthorizedTenant, request Request) (ResolvedFacts, error) {
	result := ResolvedFacts{ResolverIDs: []string{"ports"}}
	findings, err := r.resolveFindings(ctx, tenant.ID, request.FindingIDs)
	if err != nil {
		return ResolvedFacts{}, err
	}
	r.addFindingFacts(&result, findings)
	if err := r.addFindingEvidence(ctx, &result, request.FindingIDs); err != nil {
		return ResolvedFacts{}, err
	}
	if err := r.addClaims(ctx, &result, tenant.ID, request.ClaimIDs); err != nil {
		return ResolvedFacts{}, err
	}
	if err := r.addAuditPackets(ctx, &result, tenant.ID, request.AuditPacketIDs); err != nil {
		return ResolvedFacts{}, err
	}
	r.addCoverage(ctx, &result, tenant.ID, request.RequiredSources)
	r.addGraphContext(ctx, &result, request.ScopeURN, request.Budgets.GraphDepth)
	if err := r.addActionPreview(&result, request.RequestedAction, findings); err != nil {
		return ResolvedFacts{}, err
	}
	return result, nil
}

func (r PortsResolver) resolveFindings(ctx context.Context, tenantID string, ids []string) ([]*ports.FindingRecord, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if r.Findings == nil {
		return nil, fmt.Errorf("%w: finding store", ErrResolverUnavailable)
	}
	result := make([]*ports.FindingRecord, 0, len(ids))
	for _, id := range ids {
		finding, err := r.Findings.GetFinding(ctx, id)
		if err != nil || finding == nil || strings.TrimSpace(finding.TenantID) != tenantID {
			return nil, ErrProtectedReference
		}
		result = append(result, finding)
	}
	return result, nil
}

func (r PortsResolver) addFindingFacts(result *ResolvedFacts, findings []*ports.FindingRecord) {
	for _, finding := range findings {
		result.Evidence = append(result.Evidence, EvidenceReference{
			ID: finding.ID, Kind: "finding", SourceID: finding.RuntimeID,
			ObservedAt: finding.LastObservedAt,
		})
		result.SourceIDs = append(result.SourceIDs, finding.RuntimeID)
		for _, urn := range finding.ResourceURNs {
			result.Affected = append(result.Affected, SubjectReference{URN: urn, Kind: "resource"})
		}
		for _, ref := range finding.ControlRefs {
			result.Controls = append(result.Controls, ControlReference{ID: ref.ControlID, Framework: ref.FrameworkName, Applicability: "applicable"})
		}
	}
}

func (r PortsResolver) addFindingEvidence(ctx context.Context, result *ResolvedFacts, findingIDs []string) error {
	if len(findingIDs) == 0 {
		return nil
	}
	if r.FindingEvidence == nil {
		return fmt.Errorf("%w: finding evidence store", ErrResolverUnavailable)
	}
	items, err := r.FindingEvidence.ListFindingEvidence(ctx, ports.ListFindingEvidenceRequest{FindingIDs: findingIDs, Limit: 100})
	if err != nil {
		return fmt.Errorf("resolve finding evidence: %w", err)
	}
	for _, item := range items {
		if item == nil || !containsString(findingIDs, item.GetFindingId()) {
			continue
		}
		observedAt := protobufTime(item.GetLastObservedAt())
		if observedAt.IsZero() {
			observedAt = protobufTime(item.GetCreatedAt())
		}
		result.Evidence = append(result.Evidence, EvidenceReference{ID: item.GetId(), Kind: "finding_evidence", SourceID: item.GetRuntimeId(), ObservedAt: observedAt})
		for _, eventID := range item.GetEventIds() {
			result.Evidence = append(result.Evidence, EvidenceReference{ID: eventID, Kind: "source_event", SourceID: item.GetRuntimeId(), ObservedAt: observedAt})
		}
		result.SourceIDs = append(result.SourceIDs, item.GetRuntimeId())
	}
	return nil
}

func (r PortsResolver) addClaims(ctx context.Context, result *ResolvedFacts, tenantID string, claimIDs []string) error {
	if len(claimIDs) == 0 {
		return nil
	}
	if r.Claims == nil {
		return fmt.Errorf("%w: claim store", ErrResolverUnavailable)
	}
	for _, claimID := range claimIDs {
		claims, err := r.Claims.ListClaims(ctx, ports.ListClaimsRequest{TenantID: tenantID, ClaimID: claimID, Limit: 2})
		if err != nil || len(claims) != 1 || claims[0] == nil || claims[0].TenantID != tenantID {
			return ErrProtectedReference
		}
		claim := claims[0]
		evidence := EvidenceReference{
			ID: claim.ID, Kind: "claim", SourceID: claim.RuntimeID, SubjectURN: claim.SubjectURN,
			Predicate: claim.Predicate, Value: claimValue(claim), ObservedAt: claim.ObservedAt,
			ValidFrom: claim.ValidFrom, ValidTo: claim.ValidTo,
		}
		result.Evidence = append(result.Evidence, evidence)
		result.Observations = append(result.Observations, ClaimObservation{
			TenantID: tenantID, SubjectURN: claim.SubjectURN, Predicate: claim.Predicate,
			Value: claimValue(claim), ValidFrom: claim.ValidFrom, ValidTo: claim.ValidTo,
			ObservedAt: claim.ObservedAt, SourceID: claim.RuntimeID, Evidence: evidence,
		})
		result.SourceIDs = append(result.SourceIDs, claim.RuntimeID)
	}
	return nil
}

func (r PortsResolver) addAuditPackets(ctx context.Context, result *ResolvedFacts, tenantID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if r.AuditPackets == nil {
		return fmt.Errorf("%w: audit packet store", ErrResolverUnavailable)
	}
	for _, id := range ids {
		receipt, err := r.AuditPackets.GetGRCAuditPacket(ctx, id)
		if err != nil || receipt == nil || receipt.TenantID != tenantID {
			return ErrProtectedReference
		}
		result.AuditPackets = append(result.AuditPackets, AuditPacketReference{ID: receipt.ID, Digest: receipt.Digest, GeneratedAt: receipt.CreatedAt, Freshness: "unknown"})
	}
	return nil
}

func (r PortsResolver) addCoverage(ctx context.Context, result *ResolvedFacts, tenantID string, requiredSources []string) {
	if len(requiredSources) == 0 {
		return
	}
	if r.Coverage == nil {
		for _, sourceID := range requiredSources {
			result.CoverageGaps = append(result.CoverageGaps, coverageGap(sourceID, "", CoverageUnconfigured, true, "coverage resolver is not configured"))
		}
		return
	}
	records, err := r.Coverage.ReadCoverage(ctx, tenantID, requiredSources)
	if err != nil {
		for _, sourceID := range requiredSources {
			result.CoverageGaps = append(result.CoverageGaps, coverageGap(sourceID, "", CoverageFailed, true, "coverage resolution failed"))
		}
		return
	}
	seen := map[string]bool{}
	for _, record := range records {
		if !containsString(requiredSources, record.SourceID) {
			continue
		}
		seen[record.SourceID] = true
		state := decisionCoverageState(record.State, record.CertificationTier)
		if state != CoverageComplete {
			result.CoverageGaps = append(result.CoverageGaps, coverageGap(record.SourceID, record.DimensionID, state, true, record.Warning))
		}
	}
	for _, sourceID := range requiredSources {
		if !seen[sourceID] {
			result.CoverageGaps = append(result.CoverageGaps, coverageGap(sourceID, "", CoverageUnconfigured, true, "required source has no coverage record"))
		}
	}
}

func (r PortsResolver) addGraphContext(ctx context.Context, result *ResolvedFacts, scopeURN string, depth int) {
	if scopeURN == "" {
		return
	}
	if r.Graph == nil {
		result.CoverageGaps = append(result.CoverageGaps, coverageGap("graph", "context", CoverageUnconfigured, false, "graph context is not configured"))
		return
	}
	neighborhood, err := r.Graph.GetEntityNeighborhood(ctx, scopeURN, depth)
	if err != nil {
		result.CoverageGaps = append(result.CoverageGaps, coverageGap("graph", "context", CoverageFailed, false, "graph context resolution failed"))
		return
	}
	if neighborhood == nil {
		return
	}
	if neighborhood.Root != nil {
		if tenantScopedURN(tenantFromURN(scopeURN), neighborhood.Root.URN) {
			result.Affected = append(result.Affected, SubjectReference{URN: neighborhood.Root.URN, Kind: neighborhood.Root.EntityType, Name: neighborhood.Root.Label})
		}
	}
	for _, node := range neighborhood.Neighbors {
		if node != nil && tenantScopedURN(tenantFromURN(scopeURN), node.URN) {
			result.Affected = append(result.Affected, SubjectReference{URN: node.URN, Kind: node.EntityType, Name: node.Label})
		}
	}
}

func (r PortsResolver) addActionPreview(result *ResolvedFacts, actionID string, findings []*ports.FindingRecord) error {
	if actionID == "" {
		return nil
	}
	if len(findings) != 1 {
		return fmt.Errorf("%w: action preview requires one resolved finding", ErrProtectedReference)
	}
	spec, err := r.Actions.Lookup(actionID)
	if err != nil {
		return fmt.Errorf("resolve action metadata: %w", err)
	}
	if spec.CheckEligibility != nil {
		if err := spec.CheckEligibility(spec.ID, findings[0]); err != nil {
			return fmt.Errorf("action is not eligible: %w", err)
		}
	}
	target, err := graphactions.TargetForActionSpec(spec, findings[0], "")
	if err != nil {
		return fmt.Errorf("resolve action target: %w", err)
	}
	state := ActionStateProposal
	requirements := []string{}
	if spec.Destructive {
		state = ActionApprovalRequired
		requirements = append(requirements, "human_approval")
	}
	result.Actions = append(result.Actions, ActionProposal{
		ID: "preview:" + spec.ID, ActionID: spec.ID, State: state, TargetURNs: []string{target},
		Rationale:            "The resolved finding is eligible for this action preview.",
		ApprovalRequirements: requirements, CatalogVersion: "generated",
	})
	return nil
}

func coverageGap(sourceID, dimension, state string, required bool, reason string) CoverageGap {
	if strings.TrimSpace(reason) == "" {
		reason = "required coverage is not complete"
	}
	id := strings.Join([]string{"coverage", sourceID, dimension, state}, ":")
	return CoverageGap{ID: id, SourceID: sourceID, Dimension: dimension, State: state, Required: required, CouldChangeConclusion: true, Reason: reason}
}

func decisionCoverageState(state string, tier sourcecoverage.CertificationTier) string {
	if sourcecoverage.BoundedCertificationTier(tier) == sourcecoverage.CertificationUnknown {
		return CoverageUnverified
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case sourcecoverage.StateHealthy:
		return CoverageComplete
	case sourcecoverage.StatePartial:
		return CoveragePartial
	case sourcecoverage.StateStale:
		return CoverageStale
	case sourcecoverage.StateFailed:
		return CoverageFailed
	case sourcecoverage.StateUnsupported:
		return CoverageUnsupported
	case sourcecoverage.StateUnconfigured:
		return CoverageUnconfigured
	default:
		return CoverageUnverified
	}
}

func claimValue(claim *ports.ClaimRecord) string {
	if strings.TrimSpace(claim.ObjectURN) != "" {
		return claim.ObjectURN
	}
	return claim.ObjectValue
}

func tenantFromURN(urn string) string {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 5)
	if len(parts) < 4 || parts[0] != "urn" || parts[1] != "cerebro" {
		return ""
	}
	return parts[2]
}

func protobufTime(value interface {
	AsTime() time.Time
	IsValid() bool
}) time.Time {
	if value == nil || !value.IsValid() {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}
