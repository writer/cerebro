package questionnaire

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	QuestionnaireAttributeQuestionnaireURN  = "questionnaire_urn"
	QuestionnaireAttributeSourceArtifactURN = "source_artifact_urn"
	QuestionnaireProjectionSourceID         = "cerebro-questionnaires"
)

type GraphProjection struct {
	Record       ports.QuestionnaireRunRecord
	Entities     []*ports.ProjectedEntity
	Links        []*ports.ProjectedLink
	RemovedLinks []*ports.ProjectedLink
}

func BuildGraphProjection(record ports.QuestionnaireRunRecord, previous *ports.QuestionnaireRunRecord, at time.Time) (GraphProjection, error) {
	record, err := EnsureGraphIdentity(record)
	if err != nil {
		return GraphProjection{}, err
	}
	current := graphProjectionForRecord(record, at)
	current.Record = record
	if previous == nil {
		return current, nil
	}
	previousRecord, err := EnsureGraphIdentity(*previous)
	if err != nil {
		return GraphProjection{}, err
	}
	previousProjection := graphProjectionForRecord(previousRecord, at)
	current.RemovedLinks = staleProjectionLinks(previousProjection.Links, current.Links)
	return current, nil
}

func EnsureGraphIdentity(record ports.QuestionnaireRunRecord) (ports.QuestionnaireRunRecord, error) {
	record.Attributes = copyStringMap(record.Attributes)
	if record.Attributes == nil {
		record.Attributes = map[string]string{}
	}
	if strings.TrimSpace(record.Attributes[QuestionnaireAttributeQuestionnaireURN]) != "" {
		return record, nil
	}
	questionnaireURN, err := cerebroQuestionnaireURN(record.TenantID, record.RunID)
	if err != nil {
		return ports.QuestionnaireRunRecord{}, err
	}
	record.Attributes[QuestionnaireAttributeQuestionnaireURN] = questionnaireURN
	return record, nil
}

func cerebroQuestionnaireURN(tenantID string, runID string) (string, error) {
	value, err := cerebrourn.Mint(tenantID, "security_questionnaire", "questionnaire_run", runID)
	if err != nil {
		return "", fmt.Errorf("mint questionnaire urn: %w", err)
	}
	return value, nil
}

func graphProjectionForRecord(record ports.QuestionnaireRunRecord, at time.Time) GraphProjection {
	sourceID := projectionSourceID(record)
	runtimeID := strings.TrimSpace(record.RuntimeID)
	questionnaireURN := strings.TrimSpace(record.Attributes[QuestionnaireAttributeQuestionnaireURN])
	entities := []*ports.ProjectedEntity{
		{
			URN:        questionnaireURN,
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			EntityType: "security.questionnaire",
			Label:      firstNonEmpty(record.Title, record.SourceFilename, record.RunID),
			Attributes: questionnaireEntityAttributes(record, at),
		},
	}
	links := []*ports.ProjectedLink{}
	addLink := func(toURN string, relation string, attrs map[string]string) {
		toURN = strings.TrimSpace(toURN)
		if questionnaireURN == "" || toURN == "" || relation == "" {
			return
		}
		links = append(links, &ports.ProjectedLink{
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			FromURN:    questionnaireURN,
			ToURN:      toURN,
			Relation:   relation,
			Attributes: compactProjectionAttributes(attrs),
		})
	}
	if vendorURN := strings.TrimSpace(record.VendorURN); vendorURN != "" {
		addLink(vendorURN, fabriccontract.RelationAssociatedWith, map[string]string{
			"match_type":           "questionnaire_vendor_link",
			"questionnaire_run_id": record.RunID,
			"questionnaire_urn":    questionnaireURN,
			"vendor_id":            record.VendorID,
			"direction":            record.Direction,
			"vendor_link_status":   record.Attributes["vendor_link_status"],
			"vendor_link_reason":   record.Attributes["vendor_link_reason"],
		})
	}
	if owner := strings.TrimSpace(record.OwnerID); owner != "" {
		ownerURN := ownerEntityURN(record.TenantID, owner)
		if ownerURN != "" {
			entities = append(entities, &ports.ProjectedEntity{
				URN:        ownerURN,
				TenantID:   record.TenantID,
				SourceID:   sourceID,
				RuntimeID:  runtimeID,
				EntityType: "grc.user",
				Label:      owner,
				Attributes: map[string]string{
					"owner_id":      owner,
					"source_system": QuestionnaireProjectionSourceID,
				},
			})
			addLink(ownerURN, fabriccontract.RelationOwnedBy, map[string]string{"owner_id": owner, "match_type": "questionnaire_owner"})
		}
	}
	for _, controlID := range questionnaireControlIDs(record) {
		controlURN := controlEntityURN(record.TenantID, controlID)
		if controlURN == "" {
			continue
		}
		if !strings.HasPrefix(controlID, "urn:cerebro:") {
			entities = append(entities, &ports.ProjectedEntity{
				URN:        controlURN,
				TenantID:   record.TenantID,
				SourceID:   sourceID,
				RuntimeID:  runtimeID,
				EntityType: "control",
				Label:      controlID,
				Attributes: map[string]string{
					"control_id":    controlID,
					"source_system": QuestionnaireProjectionSourceID,
				},
			})
		}
		addLink(controlURN, fabriccontract.RelationSupports, map[string]string{"control_id": controlID, "match_type": "questionnaire_control_mapping"})
	}
	for _, citation := range questionnaireCitations(record) {
		evidenceURN := citationResourceURN(record.TenantID, citation)
		if evidenceURN == "" {
			continue
		}
		entities = append(entities, &ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			EntityType: "runtime_evidence",
			Label:      firstNonEmpty(citation.Label, citation.EvidenceID, citation.EvidencePacketID, citation.ID),
			Attributes: compactProjectionAttributes(map[string]string{
				"evidence_id":        citation.EvidenceID,
				"evidence_packet_id": citation.EvidencePacketID,
				"evidence_type":      citation.EvidenceType,
				"freshness_status":   citation.FreshnessStatus,
				"observed_at":        citation.ObservedAt,
				"expires_at":         citation.ExpiresAt,
				"source_system":      QuestionnaireProjectionSourceID,
			}),
		})
		addLink(evidenceURN, fabriccontract.RelationHasEvidence, map[string]string{
			"citation_id":        citation.ID,
			"evidence_id":        citation.EvidenceID,
			"evidence_packet_id": citation.EvidencePacketID,
			"evidence_type":      citation.EvidenceType,
			"match_type":         "questionnaire_answer_citation",
		})
	}
	if sourceArtifactURN := strings.TrimSpace(record.Attributes[QuestionnaireAttributeSourceArtifactURN]); strings.HasPrefix(sourceArtifactURN, "urn:cerebro:") {
		addLink(sourceArtifactURN, fabriccontract.RelationAssociatedWith, map[string]string{"match_type": "questionnaire_source_artifact"})
	}
	return GraphProjection{
		Record:   record,
		Entities: dedupeProjectedEntities(entities),
		Links:    dedupeProjectedLinks(links),
	}
}

func questionnaireEntityAttributes(record ports.QuestionnaireRunRecord, at time.Time) map[string]string {
	attrs := map[string]string{
		"questionnaire_run_id":        record.RunID,
		"questionnaire_direction":     record.Direction,
		"status":                      record.Status,
		"decision":                    record.Decision,
		"requester":                   record.Requester,
		"customer_name":               record.CustomerName,
		"vendor_urn":                  record.VendorURN,
		"vendor_id":                   record.VendorID,
		"source_id":                   record.SourceID,
		"runtime_id":                  record.RuntimeID,
		"upload_id":                   record.UploadID,
		"source_filename":             record.SourceFilename,
		"source_format":               record.SourceFormat,
		"owner_id":                    record.OwnerID,
		"assigned_team":               record.AssignedTeam,
		"question_count":              strconv.Itoa(len(record.Questions)),
		"answer_count":                strconv.Itoa(len(record.Answers)),
		"ready_answer_count":          strconv.Itoa(record.ReadyAnswerCount),
		"blocked_answer_count":        strconv.Itoa(record.BlockedAnswerCount),
		"review_answer_count":         strconv.Itoa(record.ReviewAnswerCount),
		"missing_evidence_count":      strconv.Itoa(record.MissingEvidence),
		"stale_evidence_count":        strconv.Itoa(record.StaleEvidence),
		"unassigned_count":            strconv.Itoa(record.UnassignedCount),
		"questionnaire_projection_at": at.UTC().Format(time.RFC3339),
		"source_system":               QuestionnaireProjectionSourceID,
	}
	if record.DueAt != nil {
		attrs["due_at"] = record.DueAt.UTC().Format(time.RFC3339)
	}
	for key, value := range record.Attributes {
		if strings.HasPrefix(key, "portal_") || strings.HasPrefix(key, "intake_") || key == QuestionnaireAttributeQuestionnaireURN || key == QuestionnaireAttributeSourceArtifactURN {
			attrs[key] = value
		}
	}
	return compactProjectionAttributes(attrs)
}

func projectionSourceID(record ports.QuestionnaireRunRecord) string {
	return firstNonEmpty(record.SourceID, QuestionnaireProjectionSourceID)
}

func ownerEntityURN(tenantID string, owner string) string {
	value, err := cerebrourn.Mint(tenantID, "grc_user", cerebrourn.EncodeSegment(owner))
	if err != nil {
		return ""
	}
	return value
}

func controlEntityURN(tenantID string, controlID string) string {
	controlID = strings.TrimSpace(controlID)
	if strings.HasPrefix(controlID, "urn:cerebro:") {
		return controlID
	}
	value, err := cerebrourn.Mint(tenantID, "control", "questionnaire", cerebrourn.EncodeSegment(controlID))
	if err != nil {
		return ""
	}
	return value
}

func citationResourceURN(tenantID string, citation ports.QuestionnaireCitation) string {
	for _, value := range []string{citation.ResourceURN, citation.EvidenceID, citation.EvidencePacketID, citation.ID} {
		value = strings.TrimSpace(value)
		if isRuntimeEvidenceURN(tenantID, value) {
			return value
		}
	}
	evidenceID := firstNonCerebroURN(citation.EvidenceID, citation.EvidencePacketID, citation.ID)
	if evidenceID == "" {
		return ""
	}
	value, err := cerebrourn.Mint(tenantID, "runtime_evidence", cerebrourn.EncodeSegment(evidenceID))
	if err != nil {
		return ""
	}
	return value
}

func isRuntimeEvidenceURN(tenantID string, value string) bool {
	parsed, err := cerebrourn.Parse(value)
	if err != nil {
		return false
	}
	if parsed.TenantID != strings.TrimSpace(tenantID) {
		return false
	}
	switch parsed.Kind {
	case "runtime_evidence", "runtime.evidence":
		return true
	default:
		return false
	}
}

func firstNonCerebroURN(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !strings.HasPrefix(value, "urn:cerebro:") {
			return value
		}
	}
	return ""
}

func questionnaireControlIDs(record ports.QuestionnaireRunRecord) []string {
	controls := []string{}
	for _, question := range record.Questions {
		controls = append(controls, question.MappedControls...)
	}
	for _, answer := range record.Answers {
		controls = append(controls, answer.Controls...)
		for _, citation := range answer.Citations {
			if citation.ControlID != "" {
				controls = append(controls, citation.ControlID)
			}
		}
	}
	return uniqueSorted(controls)
}

func questionnaireCitations(record ports.QuestionnaireRunRecord) []ports.QuestionnaireCitation {
	seen := map[string]struct{}{}
	citations := []ports.QuestionnaireCitation{}
	for _, answer := range record.Answers {
		for _, citation := range answer.Citations {
			key := firstNonEmpty(citation.ResourceURN, citation.EvidenceID, citation.EvidencePacketID, citation.ID)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			citations = append(citations, citation)
		}
	}
	return citations
}

func staleProjectionLinks(previous []*ports.ProjectedLink, current []*ports.ProjectedLink) []*ports.ProjectedLink {
	currentKeys := map[string]struct{}{}
	for _, link := range current {
		currentKeys[projectionLinkKey(link)] = struct{}{}
	}
	removed := []*ports.ProjectedLink{}
	for _, link := range previous {
		if _, ok := currentKeys[projectionLinkKey(link)]; ok {
			continue
		}
		removed = append(removed, link)
	}
	return dedupeProjectedLinks(removed)
}

func dedupeProjectedEntities(entities []*ports.ProjectedEntity) []*ports.ProjectedEntity {
	seen := map[string]*ports.ProjectedEntity{}
	order := []string{}
	for _, entity := range entities {
		if entity == nil || strings.TrimSpace(entity.URN) == "" {
			continue
		}
		key := strings.TrimSpace(entity.URN)
		if existing, ok := seen[key]; ok {
			existing.Attributes = mergeProjectionAttributes(existing.Attributes, entity.Attributes)
			if strings.TrimSpace(existing.Label) == "" {
				existing.Label = entity.Label
			}
			continue
		}
		seen[key] = entity
		order = append(order, key)
	}
	result := make([]*ports.ProjectedEntity, 0, len(order))
	for _, key := range order {
		result = append(result, seen[key])
	}
	return result
}

func dedupeProjectedLinks(links []*ports.ProjectedLink) []*ports.ProjectedLink {
	seen := map[string]*ports.ProjectedLink{}
	order := []string{}
	for _, link := range links {
		key := projectionLinkKey(link)
		if key == "" {
			continue
		}
		if existing, ok := seen[key]; ok {
			existing.Attributes = mergeProjectionAttributes(existing.Attributes, link.Attributes)
			continue
		}
		seen[key] = link
		order = append(order, key)
	}
	result := make([]*ports.ProjectedLink, 0, len(order))
	for _, key := range order {
		result = append(result, seen[key])
	}
	return result
}

func projectionLinkKey(link *ports.ProjectedLink) string {
	if link == nil || strings.TrimSpace(link.FromURN) == "" || strings.TrimSpace(link.Relation) == "" || strings.TrimSpace(link.ToURN) == "" {
		return ""
	}
	return strings.TrimSpace(link.FromURN) + "\x00" + strings.TrimSpace(link.Relation) + "\x00" + strings.TrimSpace(link.ToURN)
}

func mergeProjectionAttributes(left map[string]string, right map[string]string) map[string]string {
	result := copyStringMap(left)
	if result == nil {
		result = map[string]string{}
	}
	for key, value := range right {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		result[key] = value
	}
	return result
}

func compactProjectionAttributes(values map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		result[key] = value
	}
	return result
}
