package decisionpacket

import "context"

type Resolver interface {
	Resolve(context.Context, AuthorizedTenant, Request) (ResolvedFacts, error)
}

type ResolvedFacts struct {
	Evidence     []EvidenceReference
	Observations []ClaimObservation
	CoverageGaps []CoverageGap
	Affected     []SubjectReference
	Controls     []ControlReference
	AuditPackets []AuditPacketReference
	Actions      []ActionProposal
	ResolverIDs  []string
	SourceIDs    []string
	Applicable   *bool
	Rationale    string
}

type CompositeResolver struct {
	Resolvers []Resolver
}

func (r CompositeResolver) Resolve(ctx context.Context, tenant AuthorizedTenant, request Request) (ResolvedFacts, error) {
	result := ResolvedFacts{}
	for _, resolver := range r.Resolvers {
		if resolver == nil {
			continue
		}
		facts, err := resolver.Resolve(ctx, tenant, request)
		if err != nil {
			return ResolvedFacts{}, err
		}
		mergeResolvedFacts(&result, facts)
	}
	return result, nil
}

func mergeResolvedFacts(target *ResolvedFacts, source ResolvedFacts) {
	target.Evidence = append(target.Evidence, source.Evidence...)
	target.Observations = append(target.Observations, source.Observations...)
	target.CoverageGaps = append(target.CoverageGaps, source.CoverageGaps...)
	target.Affected = append(target.Affected, source.Affected...)
	target.Controls = append(target.Controls, source.Controls...)
	target.AuditPackets = append(target.AuditPackets, source.AuditPackets...)
	target.Actions = append(target.Actions, source.Actions...)
	target.ResolverIDs = append(target.ResolverIDs, source.ResolverIDs...)
	target.SourceIDs = append(target.SourceIDs, source.SourceIDs...)
	if source.Applicable != nil {
		value := *source.Applicable
		target.Applicable = &value
	}
	if source.Rationale != "" {
		target.Rationale = source.Rationale
	}
}
