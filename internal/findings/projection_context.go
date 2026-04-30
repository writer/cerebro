package findings

import (
	"context"
	"errors"
	"slices"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

type findingProjectionContext struct {
	PrimaryActorURN    string
	PrimaryResourceURN string
	ActorLabel         string
	ResourceLabel      string
	ResourceURNs       []string
}

type findingProjectionContextOptions struct {
	PrimaryRelations   []string
	PrimaryEntityType  string
	CollectAllEntities bool
	CollectAllLinkURNs bool
	ActorFallbacks     []string
	ResourceFallbacks  []string
	SkipFallbackEntity func(*ports.ProjectedEntity) bool
}

func buildFindingProjectionContext(ctx context.Context, event *cerebrov1.EventEnvelope, options findingProjectionContextOptions) (findingProjectionContext, error) {
	if ctx == nil {
		return findingProjectionContext{}, errors.New("context is required")
	}
	entities, links, err := sourceprojection.ProjectEvent(event)
	if err != nil {
		return findingProjectionContext{}, err
	}
	context := findingProjectionContext{}
	entityByURN := make(map[string]*ports.ProjectedEntity, len(entities))
	seen := map[string]struct{}{}
	addURN := func(urn string) {
		trimmed := strings.TrimSpace(urn)
		if trimmed == "" {
			return
		}
		if _, ok := seen[trimmed]; ok {
			return
		}
		seen[trimmed] = struct{}{}
		context.ResourceURNs = append(context.ResourceURNs, trimmed)
	}
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		urn := strings.TrimSpace(entity.URN)
		if urn == "" {
			continue
		}
		entityByURN[urn] = entity
		if options.CollectAllEntities {
			addURN(urn)
		}
		if context.PrimaryResourceURN == "" && options.PrimaryEntityType != "" && strings.EqualFold(strings.TrimSpace(entity.EntityType), options.PrimaryEntityType) {
			context.PrimaryResourceURN = urn
		}
	}
	if options.CollectAllLinkURNs {
		for _, link := range links {
			if link == nil {
				continue
			}
			addURN(link.FromURN)
			addURN(link.ToURN)
		}
	}
	for _, relation := range options.PrimaryRelations {
		for _, link := range links {
			if link == nil || !strings.EqualFold(strings.TrimSpace(link.Relation), strings.TrimSpace(relation)) {
				continue
			}
			fromURN := strings.TrimSpace(link.FromURN)
			toURN := strings.TrimSpace(link.ToURN)
			if context.PrimaryActorURN == "" {
				context.PrimaryActorURN = fromURN
			}
			if context.PrimaryResourceURN == "" {
				context.PrimaryResourceURN = toURN
			}
			if !options.CollectAllLinkURNs && !options.CollectAllEntities {
				addURN(fromURN)
				addURN(toURN)
			}
			break
		}
		if context.PrimaryActorURN != "" || context.PrimaryResourceURN != "" {
			break
		}
	}
	if context.PrimaryResourceURN == "" {
		for _, entity := range entities {
			if entity == nil || options.SkipFallbackEntity != nil && options.SkipFallbackEntity(entity) {
				continue
			}
			if urn := strings.TrimSpace(entity.URN); urn != "" {
				context.PrimaryResourceURN = urn
				addURN(urn)
				break
			}
		}
	}
	slices.Sort(context.ResourceURNs)
	context.ActorLabel = entityLabel(entityByURN[context.PrimaryActorURN], options.ActorFallbacks...)
	context.ResourceLabel = entityLabel(entityByURN[context.PrimaryResourceURN], options.ResourceFallbacks...)
	return context, nil
}
