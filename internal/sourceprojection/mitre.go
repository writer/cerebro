package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/mitre"
	"github.com/writer/cerebro/internal/ports"
)

var mitreAttackTacticAttributeKeys = []string{
	"mitre_tactic",
	"mitre_tactics",
	"mitre_attack_tactic",
	"mitre_attack_tactics",
	"rule_mitre_attack_tactic",
	"rule_mitre_attack_tactics",
	"attack_tactic",
	"attack_tactics",
	"rule_attack_tactic",
	"rule_attack_tactics",
	"policy_mitre",
	"rule_mitre_attack",
}

var mitreAttackTechniqueAttributeKeys = []string{
	"mitre_technique",
	"mitre_techniques",
	"mitre_attack_technique",
	"mitre_attack_techniques",
	"rule_mitre_attack_technique",
	"rule_mitre_attack_techniques",
	"attack_technique",
	"attack_techniques",
	"rule_attack_technique",
	"rule_attack_techniques",
	"policy_mitre",
	"rule_mitre_attack",
}

var mitreAttackTagAttributeKeys = []string{
	"all_tags",
	"derived_tags",
	"metadata_tags",
	"rule_references",
	"rule_tags",
	"tags",
}

var mitreDefendTacticAttributeKeys = []string{
	"d3fend_tactic",
	"d3fend_tactics",
	"defend_tactic",
	"defend_tactics",
	"mitre_defend_tactic",
	"mitre_defend_tactics",
}

var mitreDefendTechniqueAttributeKeys = []string{
	"d3fend_technique",
	"d3fend_technique_id",
	"d3fend_techniques",
	"d3fend_technique_ids",
	"defend_technique",
	"defend_technique_id",
	"defend_techniques",
	"defend_technique_ids",
	"mitre_defend_technique",
	"mitre_defend_technique_id",
	"mitre_defend_techniques",
	"mitre_defend_technique_ids",
}

var mitreDefendArtifactAttributeKeys = []string{
	"d3fend_artifact",
	"d3fend_artifact_id",
	"d3fend_artifacts",
	"d3fend_artifact_ids",
	"defend_artifact",
	"defend_artifact_id",
	"defend_artifacts",
	"defend_artifact_ids",
	"mitre_defend_artifact",
	"mitre_defend_artifact_id",
	"mitre_defend_artifacts",
	"mitre_defend_artifact_ids",
}

func addMITREAttackContextLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, attrs map[string]string) {
	fromURN = strings.TrimSpace(fromURN)
	if fromURN == "" {
		return
	}
	addMITREAttackTacticLinks(entities, links, tenantID, event, fromURN, relationHasContext, mitre.ExtractAttackTactics(append(mitreAttributeValues(attrs, mitreAttackTacticAttributeKeys...), mitreAttributeValues(attrs, mitreAttackTagAttributeKeys...)...)...), nil)
	techniques := mitre.ExtractAttackTechniques(mitreAttributeValues(attrs, mitreAttackTechniqueAttributeKeys...)...)
	techniques = append(techniques, mitre.ExtractAttackTechniqueIDs(mitreAttributeValues(attrs, mitreAttackTagAttributeKeys...)...)...)
	addMITREAttackTechniqueLinks(entities, links, tenantID, event, fromURN, relationHasContext, techniques, nil)
}

func addMITREDefendContextLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, attrs map[string]string) {
	fromURN = strings.TrimSpace(fromURN)
	if fromURN == "" {
		return
	}
	addMITREDefendTacticLinks(entities, links, tenantID, event, fromURN, relationHasContext, mitre.ExtractDefendTactics(mitreAttributeValues(attrs, mitreDefendTacticAttributeKeys...)...), nil)
	addMITREDefendTechniqueLinks(entities, links, tenantID, event, fromURN, relationHasContext, mitre.ExtractDefendTechniques(mitreAttributeValues(attrs, mitreDefendTechniqueAttributeKeys...)...), nil)
	addMITREDefendArtifactLinks(entities, links, tenantID, event, fromURN, relationHasContext, mitre.ExtractDefendArtifacts(mitreAttributeValues(attrs, mitreDefendArtifactAttributeKeys...)...), nil)
}

func addMITREAttackTechniqueLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, techniques []mitre.AttackTechnique, extraAttrs map[string]string) []string {
	urns := make([]string, 0, len(techniques))
	for _, technique := range techniques {
		techniqueURN := mitre.AttackTechniqueURN(tenantID, technique)
		if techniqueURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        techniqueURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.AttackTechniqueEntityType,
			Label:      mitre.AttackTechniqueLabel(technique),
			Attributes: mitre.AttackTechniqueAttributes(technique),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, techniqueURN, relation, mitreLinkAttributes(event, "attack_technique", technique.SourceValue, extraAttrs)))
		addMITREAttackTechniqueKnowledgeLinks(entities, links, tenantID, event, fromURN, technique, techniqueURN, relation, extraAttrs)
		urns = append(urns, techniqueURN)
	}
	return urns
}

func addMITREAttackTacticLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, tactics []mitre.AttackTactic, extraAttrs map[string]string) {
	for _, tactic := range tactics {
		tacticURN := mitre.AttackTacticURN(tenantID, tactic)
		if tacticURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tacticURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.AttackTacticEntityType,
			Label:      mitre.AttackTacticLabel(tactic),
			Attributes: mitre.AttackTacticAttributes(tactic),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, tacticURN, relation, mitreLinkAttributes(event, "attack_tactic", tactic.SourceValue, extraAttrs)))
	}
}

func addMITREDefendTacticLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, tactics []mitre.DefendTactic, extraAttrs map[string]string) {
	for _, tactic := range tactics {
		tacticURN := mitre.DefendTacticURN(tenantID, tactic)
		if tacticURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tacticURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.DefendTacticEntityType,
			Label:      mitre.DefendTacticLabel(tactic),
			Attributes: mitre.DefendTacticAttributes(tactic),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, tacticURN, relation, mitreLinkAttributes(event, "defend_tactic", tactic.SourceValue, extraAttrs)))
	}
}

func addMITREDefendTechniqueLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, techniques []mitre.DefendTechnique, extraAttrs map[string]string) []string {
	urns := make([]string, 0, len(techniques))
	for _, technique := range techniques {
		techniqueURN := mitre.DefendTechniqueURN(tenantID, technique)
		if techniqueURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        techniqueURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.DefendTechniqueEntityType,
			Label:      mitre.DefendTechniqueLabel(technique),
			Attributes: mitre.DefendTechniqueAttributes(technique),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, techniqueURN, relation, mitreLinkAttributes(event, "defend_technique", technique.SourceValue, extraAttrs)))
		urns = append(urns, techniqueURN)
	}
	return urns
}

func addMITREDefendArtifactLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, relation string, artifacts []mitre.DefendArtifact, extraAttrs map[string]string) {
	for _, artifact := range artifacts {
		artifactURN := mitre.DefendArtifactURN(tenantID, artifact)
		if artifactURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        artifactURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.DefendArtifactEntityType,
			Label:      mitre.DefendArtifactLabel(artifact),
			Attributes: mitre.DefendArtifactAttributes(artifact),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, artifactURN, relation, mitreLinkAttributes(event, "defend_artifact", artifact.SourceValue, extraAttrs)))
	}
}

func addMITREAttackTechniqueKnowledgeLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, technique mitre.AttackTechnique, techniqueURN string, relation string, extraAttrs map[string]string) {
	knowledge, ok := mitre.AttackTechniqueKnowledgeFor(technique)
	if !ok {
		return
	}
	knowledgeTechnique := mitre.AttackTechnique{ID: knowledge.ID, Name: knowledge.Name, SourceValue: technique.SourceValue}
	if strings.TrimSpace(knowledgeTechnique.ID) == "" {
		knowledgeTechnique.ID = technique.ID
	}
	if strings.TrimSpace(knowledgeTechnique.Name) == "" {
		knowledgeTechnique.Name = technique.Name
	}
	for _, tactic := range mitre.AttackTacticsForTechnique(knowledgeTechnique) {
		tacticURN := mitre.AttackTacticURN(tenantID, tactic)
		if tacticURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tacticURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.AttackTacticEntityType,
			Label:      mitre.AttackTacticLabel(tactic),
			Attributes: mitre.AttackTacticAttributes(tactic),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), techniqueURN, tacticURN, relationBelongsTo, mitreKnowledgeLinkAttributes(event, "attack_technique_tactic", technique.SourceValue, extraAttrs)))
	}
	coverageURN := mitre.AttackCoverageURN(tenantID, fromURN, techniqueURN)
	if coverageURN != "" {
		coverageState := mitreCoverageState(relation, extraAttrs)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        coverageURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.AttackCoverageEntityType,
			Label:      mitre.AttackTechniqueLabel(knowledgeTechnique) + " coverage",
			Attributes: mitre.AttackCoverageAttributes(knowledgeTechnique, coverageState, fromURN, technique.SourceValue, mitreKnowledgeLinkAttributes(event, "attack_coverage", technique.SourceValue, extraAttrs)),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, coverageURN, relationHasContext, mitreKnowledgeLinkAttributes(event, "attack_coverage_anchor", technique.SourceValue, extraAttrs)))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), coverageURN, techniqueURN, relationSupports, mitreKnowledgeLinkAttributes(event, "attack_coverage_technique", technique.SourceValue, extraAttrs)))
	}
	for _, component := range knowledge.DataComponents {
		componentURN := mitre.AttackDataComponentURN(tenantID, component)
		if componentURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        componentURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.AttackDataComponentEntityType,
			Label:      firstNonEmpty(component.Name, component.ID),
			Attributes: mitre.AttackDataComponentAttributes(component),
		})
		if source, ok := mitre.AttackDataSourceForComponent(component); ok {
			sourceURN := mitre.AttackDataSourceURN(tenantID, source)
			if sourceURN != "" {
				addEntity(entities, &ports.ProjectedEntity{
					URN:        sourceURN,
					TenantID:   tenantID,
					SourceID:   event.GetSourceId(),
					EntityType: mitre.AttackDataSourceEntityType,
					Label:      firstNonEmpty(source.Name, source.ID),
					Attributes: mitre.AttackDataSourceAttributes(source),
				})
				addLink(links, projectedLink(tenantID, event.GetSourceId(), componentURN, sourceURN, relationBelongsTo, mitreKnowledgeLinkAttributes(event, "attack_data_component_source", technique.SourceValue, extraAttrs)))
			}
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), componentURN, techniqueURN, relationSupports, mitreKnowledgeLinkAttributes(event, "detects_attack_technique", technique.SourceValue, extraAttrs)))
		if coverageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), coverageURN, componentURN, relationHasEvidence, mitreKnowledgeLinkAttributes(event, "coverage_data_component", technique.SourceValue, extraAttrs)))
		}
	}
	for _, defendTechnique := range knowledge.DefendTechniques {
		defendTechniqueURN := mitre.DefendTechniqueURN(tenantID, defendTechnique)
		if defendTechniqueURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        defendTechniqueURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.DefendTechniqueEntityType,
			Label:      mitre.DefendTechniqueLabel(defendTechnique),
			Attributes: mitre.DefendTechniqueAttributes(defendTechnique),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), defendTechniqueURN, techniqueURN, relationSupports, mitreKnowledgeLinkAttributes(event, "defends_against", technique.SourceValue, extraAttrs)))
	}
	for _, artifact := range knowledge.DefendArtifacts {
		artifactURN := mitre.DefendArtifactURN(tenantID, artifact)
		if artifactURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        artifactURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: mitre.DefendArtifactEntityType,
			Label:      mitre.DefendArtifactLabel(artifact),
			Attributes: mitre.DefendArtifactAttributes(artifact),
		})
		for _, defendTechnique := range knowledge.DefendTechniques {
			defendTechniqueURN := mitre.DefendTechniqueURN(tenantID, defendTechnique)
			if defendTechniqueURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), defendTechniqueURN, artifactURN, relationHasContext, mitreKnowledgeLinkAttributes(event, "defense_artifact", technique.SourceValue, extraAttrs)))
			}
		}
	}
}

func mitreAttributeValues(attrs map[string]string, keys ...string) []string {
	values := []string{}
	if attrs == nil {
		return values
	}
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func mitreLinkAttributes(event *cerebrov1.EventEnvelope, contextType string, sourceValue string, extra map[string]string) map[string]string {
	attrs := map[string]string{
		"event_id":      event.GetId(),
		"context_type":  strings.TrimSpace(contextType),
		"source_value":  strings.TrimSpace(sourceValue),
		"source_system": strings.TrimSpace(event.GetSourceId()),
	}
	for key, value := range extra {
		if strings.TrimSpace(key) != "" {
			attrs[key] = strings.TrimSpace(value)
		}
	}
	return compactAttributes(attrs)
}

func mitreKnowledgeLinkAttributes(event *cerebrov1.EventEnvelope, relationship string, sourceValue string, extra map[string]string) map[string]string {
	attrs := mitreLinkAttributes(event, relationship, sourceValue, extra)
	attrs["relationship"] = strings.TrimSpace(relationship)
	attrs["knowledge_pack_id"] = mitre.KnowledgePackID
	return compactAttributes(attrs)
}

func mitreCoverageState(relation string, attrs map[string]string) mitre.CoverageState {
	status := ""
	evidenceSurface := ""
	if attrs != nil {
		status = firstNonEmpty(attrs["coverage_state"], attrs["coverage_status"], attrs["coverage"], attrs["status"])
		evidenceSurface = attrs["evidence_surface"]
	}
	state := mitre.NormalizeCoverageState(status)
	if relation == relationHasContext && state == "mapped" {
		state = "observed"
		status = firstNonEmpty(status, "observed")
	}
	return mitre.CoverageState{State: state, Status: status, EvidenceSurface: evidenceSurface}
}
