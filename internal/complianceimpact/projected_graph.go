package complianceimpact

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
)

const (
	impactProjectionSourceID   = "compliance"
	impactProjectionEntityType = "compliance.impact_revision"
	impactDependencyRelation   = "compliance_depends_on"
)

// GraphProjector writes exact immutable compliance facts into the shared graph
// projection. It stores identifiers and revision metadata only; lifecycle data
// remains in its owning service and append log.
type GraphProjector struct {
	graph ports.ProjectionGraphStore
}

func NewGraphProjector(graph ports.ProjectionGraphStore) (*GraphProjector, error) {
	if graph == nil {
		return nil, ErrImpactProjectionUnavailable
	}
	return &GraphProjector{graph: graph}, nil
}

func (p *GraphProjector) ProjectFact(ctx context.Context, fact complianceintegration.DomainFact) error {
	if p == nil || p.graph == nil {
		return ErrImpactProjectionUnavailable
	}
	root, err := projectedImpactEntity(fact.Revision())
	if err != nil {
		return err
	}
	entities := []*ports.ProjectedEntity{root}
	links := make([]*ports.ProjectedLink, 0, len(fact.Dependencies()))
	seen := map[string]struct{}{root.URN: {}}
	for _, dependency := range fact.Dependencies() {
		entity, entityErr := projectedImpactEntity(dependency.Revision())
		if entityErr != nil {
			return entityErr
		}
		if _, ok := seen[entity.URN]; !ok {
			seen[entity.URN] = struct{}{}
			entities = append(entities, entity)
		}
		links = append(links, &ports.ProjectedLink{
			TenantID: root.TenantID, SourceID: impactProjectionSourceID,
			FromURN: root.URN, ToURN: entity.URN, Relation: impactDependencyRelation,
			Attributes: map[string]string{"dependency_relation": dependency.Relation()},
		})
	}
	if err := ports.ValidateProjectedTenantScopes(entities, links); err != nil {
		return err
	}
	if batch, ok := p.graph.(ports.ProjectionGraphBatchStore); ok {
		if err := batch.UpsertProjectedEntities(ctx, entities); err != nil {
			return fmt.Errorf("project compliance impact entities: %w", err)
		}
		if len(links) != 0 {
			if err := batch.UpsertProjectedLinks(ctx, links); err != nil {
				return fmt.Errorf("project compliance impact dependencies: %w", err)
			}
			return nil
		}
		return nil
	}
	for _, entity := range entities {
		if err := p.graph.UpsertProjectedEntity(ctx, entity); err != nil {
			return fmt.Errorf("project compliance impact entity: %w", err)
		}
	}
	for _, link := range links {
		if err := p.graph.UpsertProjectedLink(ctx, link); err != nil {
			return fmt.Errorf("project compliance impact dependency: %w", err)
		}
	}
	return nil
}

func projectedImpactEntity(revision complianceintegration.RevisionRef) (*ports.ProjectedEntity, error) {
	urn, err := impactRevisionURN(revision)
	if err != nil {
		return nil, err
	}
	return &ports.ProjectedEntity{
		URN: urn, TenantID: revision.TenantID(), SourceID: impactProjectionSourceID,
		EntityType: impactProjectionEntityType,
		Label:      revision.Domain() + "/" + string(revision.Kind()) + "/" + revision.ID() + "@" + revision.RevisionID(),
		Attributes: map[string]string{
			"tenant_id": revision.TenantID(), "domain": revision.Domain(), "fact_kind": string(revision.Kind()),
			"stable_id": revision.ID(), "revision_id": revision.RevisionID(), "revision_version": strconv.FormatUint(revision.Version(), 10),
			"content_digest": string(revision.Canonical().ContentDigest), "last_modified": revision.Canonical().LastModified.Format(time.RFC3339Nano),
		},
	}, nil
}

func impactRevisionURN(revision complianceintegration.RevisionRef) (string, error) {
	urn, err := revision.ImpactRevisionURN()
	if err != nil {
		return "", ErrInvalidGraph
	}
	return urn, nil
}
