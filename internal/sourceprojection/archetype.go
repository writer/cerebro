package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func archetypeScanProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	scanID := firstNonEmpty(attrs["scan_id"], stringValue(payloadMap(event), "id"))
	if scanID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	scanURN := projectionURN(tenantID, "archetype_scan", scanID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        scanURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "archetype.scan",
		Label:      "Archetype scan " + scanID,
		Attributes: compactAttributes(map[string]string{
			"repository_id":  attrs["repository_id"],
			"scan_id":        scanID,
			"source_product": "archetype",
			"status":         attrs["status"],
			"at":             eventObservedAt(event),
		}),
	})
	if repoURN := archetypeRepoURN(tenantID, attrs); repoURN != "" {
		addArchetypeRepo(entities, tenantID, event.GetSourceId(), repoURN, attrs)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, scanURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), scanURN, repoURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func archetypeVulnerabilityProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	vulnID := firstNonEmpty(attrs["vulnerability_id"], stringValue(payloadMap(event), "id"))
	if vulnID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	findingURN := projectionURN(tenantID, "archetype_finding", vulnID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        findingURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "archetype.finding",
		Label:      archetypeFindingLabel(attrs),
		Attributes: compactAttributes(map[string]string{
			"category":         attrs["category"],
			"file_path":        attrs["file_path"],
			"line_number":      attrs["line_number"],
			"repository_id":    attrs["repository_id"],
			"scan_id":          attrs["scan_id"],
			"severity":         attrs["severity"],
			"source_product":   "archetype",
			"vulnerability_id": vulnID,
			"at":               eventObservedAt(event),
		}),
	})
	if scanURN := projectionURN(tenantID, "archetype_scan", attrs["scan_id"]); scanURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: scanURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "archetype.scan", Label: "Archetype scan " + attrs["scan_id"], Attributes: map[string]string{"scan_id": attrs["scan_id"]}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, scanURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	}
	if repoURN := archetypeRepoURN(tenantID, attrs); repoURN != "" {
		addArchetypeRepo(entities, tenantID, event.GetSourceId(), repoURN, attrs)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, findingURN, relationHasEvidence, map[string]string{"event_id": event.GetId(), "severity": attrs["severity"]}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, repoURN, relationAffects, map[string]string{"event_id": event.GetId()}))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func archetypeRepoURN(tenantID string, attrs map[string]string) string {
	repository := firstNonEmpty(attrs["repository"], joinRepo(attrs["owner"], attrs["repo"]))
	return projectionURN(tenantID, "github_code_repository", repository)
}

func addArchetypeRepo(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, repoURN string, attrs map[string]string) {
	addEntity(entities, &ports.ProjectedEntity{
		URN:        repoURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "github.code.repository",
		Label:      firstNonEmpty(attrs["repo"], attrs["repository"], repoURN),
		Attributes: compactAttributes(map[string]string{
			"owner_login":    attrs["owner"],
			"repository":     firstNonEmpty(attrs["repository"], joinRepo(attrs["owner"], attrs["repo"])),
			"resource_type":  "code_repository",
			"source_product": "archetype",
		}),
	})
}

func archetypeFindingLabel(attrs map[string]string) string {
	location := strings.TrimSpace(attrs["file_path"])
	if line := strings.TrimSpace(attrs["line_number"]); line != "" {
		location += ":" + line
	}
	return firstNonEmpty(attrs["category"]+" "+location, attrs["vulnerability_id"], "Archetype finding")
}

func joinRepo(owner string, repo string) string {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return ""
	}
	return strings.TrimSpace(owner) + "/" + strings.TrimSpace(repo)
}
