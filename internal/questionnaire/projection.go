package questionnaire

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	entities := []*ports.ProjectedEntity{}
	links := []*ports.ProjectedLink{}
	addEntity := func(entity *ports.ProjectedEntity) {
		if entity == nil || strings.TrimSpace(entity.URN) == "" {
			return
		}
		entities = append(entities, entity)
	}
	addEdge := func(fromURN string, toURN string, relation string, attrs map[string]string) {
		fromURN = strings.TrimSpace(fromURN)
		toURN = strings.TrimSpace(toURN)
		if fromURN == "" || toURN == "" || relation == "" {
			return
		}
		links = append(links, &ports.ProjectedLink{
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			FromURN:    fromURN,
			ToURN:      toURN,
			Relation:   relation,
			Attributes: compactProjectionAttributes(attrs),
		})
	}
	addLink := func(toURN string, relation string, attrs map[string]string) {
		addEdge(questionnaireURN, toURN, relation, attrs)
	}
	addOwnerEntity := func(owner string) string {
		owner = strings.TrimSpace(owner)
		if owner == "" {
			return ""
		}
		ownerURN := ownerEntityURN(record.TenantID, owner)
		if ownerURN == "" {
			return ""
		}
		addEntity(&ports.ProjectedEntity{
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
		return ownerURN
	}
	addControlEntity := func(controlID string) string {
		controlID = strings.TrimSpace(controlID)
		controlURN := controlEntityURN(record.TenantID, controlID)
		if controlURN == "" {
			return ""
		}
		if !strings.HasPrefix(controlID, "urn:cerebro:") {
			addEntity(&ports.ProjectedEntity{
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
		return controlURN
	}
	addEvidenceEntity := func(citation ports.QuestionnaireCitation) string {
		evidenceURN := citationResourceURN(record.TenantID, citation)
		if evidenceURN == "" {
			return ""
		}
		addEntity(&ports.ProjectedEntity{
			URN:        evidenceURN,
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			EntityType: "runtime_evidence",
			Label:      firstNonEmpty(citation.Label, citation.EvidenceID, citation.EvidencePacketID, citation.ID),
			Attributes: compactProjectionAttributes(map[string]string{
				"citation_id":        citation.ID,
				"evidence_id":        citation.EvidenceID,
				"evidence_packet_id": citation.EvidencePacketID,
				"evidence_type":      citation.EvidenceType,
				"control_id":         citation.ControlID,
				"freshness_status":   citation.FreshnessStatus,
				"observed_at":        citation.ObservedAt,
				"expires_at":         citation.ExpiresAt,
				"source_id":          citation.SourceID,
				"runtime_id":         citation.RuntimeID,
				"source_event_ids":   joinProjectionValues(citation.SourceEventIDs),
				"graph_root_urns":    joinProjectionValues(citation.GraphRootURNs),
				"graph_path_ids":     joinProjectionValues(citation.GraphPathIDs),
				"source_system":      QuestionnaireProjectionSourceID,
			}),
		})
		return evidenceURN
	}
	addEntity(&ports.ProjectedEntity{
		URN:        questionnaireURN,
		TenantID:   record.TenantID,
		SourceID:   sourceID,
		RuntimeID:  runtimeID,
		EntityType: "security.questionnaire",
		Label:      firstNonEmpty(record.Title, record.SourceFilename, record.RunID),
		Attributes: questionnaireEntityAttributes(record, at),
	})
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
		ownerURN := addOwnerEntity(owner)
		if ownerURN != "" {
			addLink(ownerURN, fabriccontract.RelationOwnedBy, map[string]string{"owner_id": owner, "match_type": "questionnaire_owner"})
		}
	}
	for _, controlID := range questionnaireControlIDs(record) {
		controlURN := addControlEntity(controlID)
		if controlURN == "" {
			continue
		}
		addLink(controlURN, fabriccontract.RelationSupports, map[string]string{"control_id": controlID, "match_type": "questionnaire_control_mapping"})
	}
	for _, citation := range questionnaireCitations(record) {
		evidenceURN := addEvidenceEntity(citation)
		if evidenceURN == "" {
			continue
		}
		addLink(evidenceURN, fabriccontract.RelationHasEvidence, citationLinkAttributes(citation, "questionnaire_answer_citation"))
	}
	if sourceArtifactURN := strings.TrimSpace(record.Attributes[QuestionnaireAttributeSourceArtifactURN]); isSourceArtifactURN(record.TenantID, sourceArtifactURN) {
		addLink(sourceArtifactURN, fabriccontract.RelationAssociatedWith, map[string]string{"match_type": "questionnaire_source_artifact"})
	}

	questionURNsByID := map[string]string{}
	questionURNsByRef := map[string]string{}
	for _, question := range record.Questions {
		questionRefID := questionnaireQuestionRefID(question)
		questionURN := questionnaireQuestionURN(record.TenantID, record.RunID, questionRefID)
		if questionURN == "" {
			continue
		}
		if strings.TrimSpace(question.ID) != "" {
			questionURNsByID[strings.TrimSpace(question.ID)] = questionURN
		}
		questionURNsByRef[questionRefID] = questionURN
		addEntity(&ports.ProjectedEntity{
			URN:        questionURN,
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			EntityType: "questionnaire.question",
			Label:      projectionLabel(firstNonEmpty(question.Question, question.ID)),
			Attributes: questionEntityAttributes(record, question),
		})
		addEdge(questionnaireURN, questionURN, fabriccontract.RelationContains, map[string]string{
			"match_type":           "questionnaire_question",
			"questionnaire_run_id": record.RunID,
			"question_id":          question.ID,
		})
		for _, controlID := range question.MappedControls {
			controlURN := addControlEntity(controlID)
			if controlURN == "" {
				continue
			}
			addEdge(questionURN, controlURN, fabriccontract.RelationSupports, map[string]string{
				"match_type":           "question_control_mapping",
				"questionnaire_run_id": record.RunID,
				"question_id":          question.ID,
				"control_id":           controlID,
			})
		}
		if ownerURN := addOwnerEntity(question.OwnerID); ownerURN != "" {
			addEdge(questionURN, ownerURN, fabriccontract.RelationOwnedBy, map[string]string{
				"match_type":           "question_owner",
				"questionnaire_run_id": record.RunID,
				"question_id":          question.ID,
				"owner_id":             question.OwnerID,
			})
		}
		if sourceArtifactURN := questionSourceArtifactURN(record, question); sourceArtifactURN != "" {
			addEdge(questionURN, sourceArtifactURN, fabriccontract.RelationHasContext, mergeProjectionAttributes(sourceLocatorAttributes(question.SourceLocator), map[string]string{
				"match_type":           "question_source_locator",
				"questionnaire_run_id": record.RunID,
				"question_id":          question.ID,
			}))
		}
	}

	slotURNsByKey := map[string]string{}
	slotURNsByID := map[string]string{}
	gapURNsByID := map[string]string{}
	for _, answer := range record.Answers {
		answerRefID := questionnaireAnswerRefID(answer)
		answerURN := questionnaireAnswerURN(record.TenantID, record.RunID, answer.QuestionID, answerRefID)
		if answerURN == "" {
			continue
		}
		questionURN := questionURNForAnswer(answer, questionURNsByID, questionURNsByRef)
		addEntity(&ports.ProjectedEntity{
			URN:        answerURN,
			TenantID:   record.TenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			EntityType: "questionnaire.answer",
			Label:      projectionLabel(firstNonEmpty(answer.Question, answer.ID)),
			Attributes: answerEntityAttributes(record, answer),
		})
		addEdge(questionnaireURN, answerURN, fabriccontract.RelationContains, map[string]string{
			"match_type":           "questionnaire_answer",
			"questionnaire_run_id": record.RunID,
			"question_id":          answer.QuestionID,
			"answer_id":            answer.ID,
		})
		if questionURN != "" {
			addEdge(answerURN, questionURN, fabriccontract.RelationAttachedTo, map[string]string{
				"match_type":           "answer_question",
				"questionnaire_run_id": record.RunID,
				"question_id":          answer.QuestionID,
				"answer_id":            answer.ID,
			})
		}
		for _, controlID := range answerControlIDs(answer) {
			controlURN := addControlEntity(controlID)
			if controlURN == "" {
				continue
			}
			addEdge(answerURN, controlURN, fabriccontract.RelationSupports, map[string]string{
				"match_type":           "answer_control_mapping",
				"questionnaire_run_id": record.RunID,
				"question_id":          answer.QuestionID,
				"answer_id":            answer.ID,
				"control_id":           controlID,
			})
		}

		citationURNs := map[string]string{}
		for _, citation := range answer.Citations {
			evidenceURN := addEvidenceEntity(citation)
			if evidenceURN == "" {
				continue
			}
			for _, citationKey := range citationLookupKeys(citation) {
				citationURNs[citationKey] = evidenceURN
			}
			addEdge(answerURN, evidenceURN, fabriccontract.RelationHasEvidence, citationLinkAttributes(citation, "answer_evidence"))
			for _, graphRootURN := range citation.GraphRootURNs {
				graphRootURN = strings.TrimSpace(graphRootURN)
				if !isSameTenantCerebroURN(record.TenantID, graphRootURN) {
					continue
				}
				addEdge(answerURN, graphRootURN, fabriccontract.RelationHasContext, compactProjectionAttributes(map[string]string{
					"match_type":           "answer_graph_root",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"answer_id":            answer.ID,
					"citation_id":          citation.ID,
					"source_event_ids":     joinProjectionValues(citation.SourceEventIDs),
					"graph_path_ids":       joinProjectionValues(citation.GraphPathIDs),
				}))
			}
		}

		for _, slot := range answer.EvidenceSlots {
			slotRefID := questionnaireSlotRefID(slot)
			slotURN := questionnaireSlotURN(record.TenantID, record.RunID, answer.QuestionID, slotRefID)
			if slotURN == "" {
				continue
			}
			slotURNsByKey[questionnaireSlotKey(answer.QuestionID, slot.ID)] = slotURN
			slotURNsByID[strings.TrimSpace(slot.ID)] = slotURN
			addEntity(&ports.ProjectedEntity{
				URN:        slotURN,
				TenantID:   record.TenantID,
				SourceID:   sourceID,
				RuntimeID:  runtimeID,
				EntityType: "questionnaire.evidence_slot",
				Label:      projectionLabel(firstNonEmpty(slot.Label, slot.ID)),
				Attributes: slotEntityAttributes(record, answer, slot),
			})
			addEdge(questionnaireURN, slotURN, fabriccontract.RelationContains, map[string]string{
				"match_type":           "questionnaire_evidence_slot",
				"questionnaire_run_id": record.RunID,
				"question_id":          answer.QuestionID,
				"answer_id":            answer.ID,
				"slot_id":              slot.ID,
			})
			addEdge(slotURN, answerURN, fabriccontract.RelationAttachedTo, map[string]string{
				"match_type":           "slot_answer",
				"questionnaire_run_id": record.RunID,
				"question_id":          answer.QuestionID,
				"answer_id":            answer.ID,
				"slot_id":              slot.ID,
			})
			if questionURN != "" {
				addEdge(slotURN, questionURN, fabriccontract.RelationAttachedTo, map[string]string{
					"match_type":           "slot_question",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"slot_id":              slot.ID,
				})
			}
			for _, citationID := range slot.CitationIDs {
				evidenceURN := citationURNs[strings.TrimSpace(citationID)]
				if evidenceURN == "" {
					continue
				}
				addEdge(slotURN, evidenceURN, fabriccontract.RelationHasEvidence, map[string]string{
					"match_type":           "slot_evidence",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"answer_id":            answer.ID,
					"slot_id":              slot.ID,
					"citation_id":          citationID,
				})
			}
		}

		for _, gap := range append(append([]ports.QuestionnaireEvidenceGap{}, answer.MissingEvidence...), answer.Conflicts...) {
			gapRefID := questionnaireGapRefID(gap)
			gapURN := questionnaireGapURN(record.TenantID, record.RunID, answer.QuestionID, gapRefID)
			if gapURN == "" {
				continue
			}
			if strings.TrimSpace(gap.ID) != "" {
				gapURNsByID[strings.TrimSpace(gap.ID)] = gapURN
			}
			addEntity(&ports.ProjectedEntity{
				URN:        gapURN,
				TenantID:   record.TenantID,
				SourceID:   sourceID,
				RuntimeID:  runtimeID,
				EntityType: "questionnaire.evidence_gap",
				Label:      projectionLabel(firstNonEmpty(gap.Code, gap.ID)),
				Attributes: gapEntityAttributes(record, answer, gap),
			})
			addEdge(questionnaireURN, gapURN, fabriccontract.RelationContains, map[string]string{
				"match_type":           "questionnaire_evidence_gap",
				"questionnaire_run_id": record.RunID,
				"question_id":          answer.QuestionID,
				"answer_id":            answer.ID,
				"gap_id":               gap.ID,
				"slot_id":              gap.SlotID,
			})
			if questionURN != "" {
				addEdge(gapURN, questionURN, fabriccontract.RelationAttachedTo, map[string]string{
					"match_type":           "gap_question",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"gap_id":               gap.ID,
				})
			}
			if slotURN := slotURNsByKey[questionnaireSlotKey(answer.QuestionID, gap.SlotID)]; slotURN != "" {
				addEdge(gapURN, slotURN, fabriccontract.RelationAttachedTo, map[string]string{
					"match_type":           "gap_slot",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"gap_id":               gap.ID,
					"slot_id":              gap.SlotID,
				})
			}
			if controlURN := addControlEntity(gap.ControlID); controlURN != "" {
				addEdge(gapURN, controlURN, fabriccontract.RelationSupports, map[string]string{
					"match_type":           "gap_control",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"gap_id":               gap.ID,
					"control_id":           gap.ControlID,
				})
			}
			if evidenceURN := gapEvidenceURN(record.TenantID, gap); evidenceURN != "" {
				addEntity(&ports.ProjectedEntity{
					URN:        evidenceURN,
					TenantID:   record.TenantID,
					SourceID:   sourceID,
					RuntimeID:  runtimeID,
					EntityType: "runtime_evidence",
					Label:      firstNonEmpty(gap.PacketID, gap.Code),
					Attributes: compactProjectionAttributes(map[string]string{
						"evidence_packet_id": gap.PacketID,
						"source_system":      QuestionnaireProjectionSourceID,
					}),
				})
				addEdge(gapURN, evidenceURN, fabriccontract.RelationAssociatedWith, map[string]string{
					"match_type":           "gap_evidence_packet",
					"questionnaire_run_id": record.RunID,
					"question_id":          answer.QuestionID,
					"gap_id":               gap.ID,
					"evidence_packet_id":   gap.PacketID,
				})
			}
		}
	}

	for _, assignment := range record.Assignments {
		ownerURN := addOwnerEntity(firstNonEmpty(assignment.OwnerID, assignment.Team))
		if ownerURN == "" {
			continue
		}
		targetURN := assignmentTargetURN(assignment, questionURNsByID, slotURNsByKey, slotURNsByID, gapURNsByID)
		if targetURN == "" {
			targetURN = questionnaireURN
		}
		addEdge(targetURN, ownerURN, fabriccontract.RelationAssignedTo, assignmentLinkAttributes(record, assignment))
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

func questionEntityAttributes(record ports.QuestionnaireRunRecord, question ports.QuestionnaireQuestion) map[string]string {
	attrs := map[string]string{
		"questionnaire_run_id":     record.RunID,
		"question_id":              question.ID,
		"question":                 projectionAttributeValue(question.Question),
		"normalized_question":      projectionAttributeValue(question.NormalizedQuestion),
		"section":                  question.Section,
		"required_answer_format":   question.RequiredAnswerFormat,
		"mapped_controls":          joinProjectionValues(question.MappedControls),
		"required_evidence_slots":  joinProjectionValues(question.RequiredSlots),
		"owner_id":                 question.OwnerID,
		"answer_state":             question.AnswerState,
		"review_state":             question.ReviewState,
		"questionnaire_direction":  record.Direction,
		"questionnaire_status":     record.Status,
		"questionnaire_source_id":  record.SourceID,
		"questionnaire_runtime_id": record.RuntimeID,
		"source_system":            QuestionnaireProjectionSourceID,
	}
	return mergeProjectionAttributes(attrs, sourceLocatorAttributes(question.SourceLocator))
}

func answerEntityAttributes(record ports.QuestionnaireRunRecord, answer ports.QuestionnaireRunAnswer) map[string]string {
	return compactProjectionAttributes(map[string]string{
		"questionnaire_run_id":     record.RunID,
		"answer_id":                answer.ID,
		"question_id":              answer.QuestionID,
		"question":                 projectionAttributeValue(answer.Question),
		"answer_state":             answer.AnswerState,
		"review_state":             answer.ReviewState,
		"confidence":               answer.Confidence,
		"confidence_score":         strconv.Itoa(answer.ConfidenceScore),
		"controls":                 joinProjectionValues(answer.Controls),
		"freshness_status":         answer.Freshness.Status,
		"freshness_observed_at":    answer.Freshness.ObservedAt,
		"freshness_expires_at":     answer.Freshness.ExpiresAt,
		"freshness_reason":         answer.Freshness.Reason,
		"source_answer_id":         answer.SourceAnswerID,
		"reviewer_decision":        answer.ReviewerDecision,
		"reviewer_reason":          projectionAttributeValue(answer.ReviewerReason),
		"questionnaire_direction":  record.Direction,
		"questionnaire_status":     record.Status,
		"questionnaire_source_id":  record.SourceID,
		"questionnaire_runtime_id": record.RuntimeID,
		"source_system":            QuestionnaireProjectionSourceID,
	})
}

func slotEntityAttributes(record ports.QuestionnaireRunRecord, answer ports.QuestionnaireRunAnswer, slot ports.QuestionnaireEvidenceSlot) map[string]string {
	return compactProjectionAttributes(map[string]string{
		"questionnaire_run_id":     record.RunID,
		"answer_id":                answer.ID,
		"question_id":              answer.QuestionID,
		"slot_id":                  slot.ID,
		"slot_label":               slot.Label,
		"slot_state":               slot.State,
		"required":                 strconv.FormatBool(slot.Required),
		"citation_ids":             joinProjectionValues(slot.CitationIDs),
		"missing_reasons":          joinProjectionValues(slot.MissingReasons),
		"questionnaire_direction":  record.Direction,
		"questionnaire_status":     record.Status,
		"questionnaire_source_id":  record.SourceID,
		"questionnaire_runtime_id": record.RuntimeID,
		"source_system":            QuestionnaireProjectionSourceID,
	})
}

func gapEntityAttributes(record ports.QuestionnaireRunRecord, answer ports.QuestionnaireRunAnswer, gap ports.QuestionnaireEvidenceGap) map[string]string {
	return compactProjectionAttributes(map[string]string{
		"questionnaire_run_id":     record.RunID,
		"answer_id":                answer.ID,
		"question_id":              answer.QuestionID,
		"gap_id":                   gap.ID,
		"gap_code":                 gap.Code,
		"reason":                   projectionAttributeValue(gap.Reason),
		"slot_id":                  gap.SlotID,
		"control_id":               gap.ControlID,
		"evidence_packet_id":       gap.PacketID,
		"review_state":             gap.ReviewState,
		"questionnaire_direction":  record.Direction,
		"questionnaire_status":     record.Status,
		"questionnaire_source_id":  record.SourceID,
		"questionnaire_runtime_id": record.RuntimeID,
		"source_system":            QuestionnaireProjectionSourceID,
	})
}

func sourceLocatorAttributes(locator *ports.QuestionnaireSourceLocator) map[string]string {
	if locator == nil {
		return nil
	}
	return compactProjectionAttributes(map[string]string{
		"source_artifact_urn": locator.SourceArtifactURN,
		"source_format":       locator.SourceFormat,
		"source_filename":     locator.SourceFilename,
		"sheet_name":          locator.SheetName,
		"cell":                locator.Cell,
		"column_name":         locator.ColumnName,
		"row_number":          positiveIntString(locator.RowNumber),
		"line_number":         positiveIntString(locator.LineNumber),
		"page_number":         positiveIntString(locator.PageNumber),
		"source_text":         projectionAttributeValue(locator.Text),
		"portal_url":          locator.PortalURL,
		"portal_field_id":     locator.PortalFieldID,
		"portal_field_label":  locator.PortalFieldLabel,
	})
}

func questionSourceArtifactURN(record ports.QuestionnaireRunRecord, question ports.QuestionnaireQuestion) string {
	if !sourceLocatorHasPrecision(question.SourceLocator) {
		return ""
	}
	sourceArtifactURN := strings.TrimSpace(question.SourceLocator.SourceArtifactURN)
	if sourceArtifactURN == "" {
		sourceArtifactURN = strings.TrimSpace(record.Attributes[QuestionnaireAttributeSourceArtifactURN])
	}
	if !isSourceArtifactURN(record.TenantID, sourceArtifactURN) {
		return ""
	}
	return sourceArtifactURN
}

func sourceLocatorHasPrecision(locator *ports.QuestionnaireSourceLocator) bool {
	if locator == nil {
		return false
	}
	if strings.TrimSpace(locator.Cell) != "" || strings.TrimSpace(locator.PortalFieldID) != "" || strings.TrimSpace(locator.PortalFieldLabel) != "" {
		return true
	}
	return locator.RowNumber > 0 || locator.LineNumber > 0 || locator.PageNumber > 0
}

func citationLinkAttributes(citation ports.QuestionnaireCitation, matchType string) map[string]string {
	return compactProjectionAttributes(map[string]string{
		"match_type":         matchType,
		"citation_id":        citation.ID,
		"evidence_id":        citation.EvidenceID,
		"evidence_packet_id": citation.EvidencePacketID,
		"evidence_type":      citation.EvidenceType,
		"control_id":         citation.ControlID,
		"freshness_status":   citation.FreshnessStatus,
		"source_id":          citation.SourceID,
		"runtime_id":         citation.RuntimeID,
		"source_event_ids":   joinProjectionValues(citation.SourceEventIDs),
		"graph_root_urns":    joinProjectionValues(citation.GraphRootURNs),
		"graph_path_ids":     joinProjectionValues(citation.GraphPathIDs),
	})
}

func assignmentLinkAttributes(record ports.QuestionnaireRunRecord, assignment ports.QuestionnaireAssignment) map[string]string {
	attrs := map[string]string{
		"match_type":           "questionnaire_assignment",
		"questionnaire_run_id": record.RunID,
		"assignment_id":        assignment.ID,
		"question_id":          assignment.QuestionID,
		"gap_id":               assignment.GapID,
		"slot_id":              assignment.SlotID,
		"owner_id":             assignment.OwnerID,
		"team":                 assignment.Team,
		"status":               assignment.Status,
		"reason":               projectionAttributeValue(assignment.Reason),
	}
	if assignment.DueAt != nil {
		attrs["due_at"] = assignment.DueAt.UTC().Format(time.RFC3339)
	}
	if assignment.CreatedAt != nil {
		attrs["created_at"] = assignment.CreatedAt.UTC().Format(time.RFC3339)
	}
	if assignment.UpdatedAt != nil {
		attrs["updated_at"] = assignment.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return compactProjectionAttributes(attrs)
}

func projectionSourceID(record ports.QuestionnaireRunRecord) string {
	return firstNonEmpty(record.SourceID, QuestionnaireProjectionSourceID)
}

func questionnaireQuestionURN(tenantID string, runID string, questionID string) string {
	return questionnaireWorkItemURN(tenantID, "questionnaire_question", runID, "question", firstNonEmpty(questionID, "question"))
}

func questionnaireAnswerURN(tenantID string, runID string, questionID string, answerID string) string {
	return questionnaireWorkItemURN(tenantID, "questionnaire_answer", runID, "question", firstNonEmpty(questionID, "unassigned"), "answer", firstNonEmpty(answerID, "answer"))
}

func questionnaireSlotURN(tenantID string, runID string, questionID string, slotID string) string {
	return questionnaireWorkItemURN(tenantID, "questionnaire_evidence_slot", runID, "question", firstNonEmpty(questionID, "unassigned"), "slot", firstNonEmpty(slotID, "slot"))
}

func questionnaireGapURN(tenantID string, runID string, questionID string, gapID string) string {
	return questionnaireWorkItemURN(tenantID, "questionnaire_evidence_gap", runID, "question", firstNonEmpty(questionID, "unassigned"), "gap", firstNonEmpty(gapID, "gap"))
}

func questionnaireWorkItemURN(tenantID string, kind string, runID string, parts ...string) string {
	segments := []string{"questionnaire_run", cerebrourn.EncodeSegment(firstNonEmpty(runID, "run"))}
	for _, part := range parts {
		encoded := cerebrourn.EncodeSegment(part)
		if encoded == "" {
			continue
		}
		segments = append(segments, encoded)
	}
	value, err := cerebrourn.Mint(tenantID, kind, segments...)
	if err != nil {
		return ""
	}
	return value
}

func questionnaireQuestionRefID(question ports.QuestionnaireQuestion) string {
	return firstNonEmpty(question.ID, projectionStableID(question.Question, question.NormalizedQuestion, question.Section))
}

func questionnaireAnswerRefID(answer ports.QuestionnaireRunAnswer) string {
	return firstNonEmpty(answer.ID, projectionStableID(answer.QuestionID, answer.Question, answer.SourceAnswerID))
}

func questionnaireSlotRefID(slot ports.QuestionnaireEvidenceSlot) string {
	return firstNonEmpty(slot.ID, projectionStableID(slot.Label, slot.State, strings.Join(slot.CitationIDs, "|")))
}

func questionnaireGapRefID(gap ports.QuestionnaireEvidenceGap) string {
	return firstNonEmpty(gap.ID, projectionStableID(gap.Code, gap.SlotID, gap.ControlID, gap.PacketID, gap.Reason))
}

func projectionStableID(values ...string) string {
	return cerebrourn.StableExternalID(strings.Join(values, "\x00"), "id-missing")
}

func questionURNForAnswer(answer ports.QuestionnaireRunAnswer, byID map[string]string, byRef map[string]string) string {
	if value := byID[strings.TrimSpace(answer.QuestionID)]; value != "" {
		return value
	}
	if value := byRef[strings.TrimSpace(answer.QuestionID)]; value != "" {
		return value
	}
	return ""
}

func answerControlIDs(answer ports.QuestionnaireRunAnswer) []string {
	controls := append([]string(nil), answer.Controls...)
	for _, citation := range answer.Citations {
		controls = append(controls, citation.ControlID)
	}
	return uniqueSorted(controls)
}

func citationLookupKeys(citation ports.QuestionnaireCitation) []string {
	return uniqueSorted([]string{
		citation.ID,
		citation.EvidenceID,
		citation.EvidencePacketID,
		citation.ResourceURN,
	})
}

func questionnaireSlotKey(questionID string, slotID string) string {
	return strings.TrimSpace(questionID) + "\x00" + strings.TrimSpace(slotID)
}

func assignmentTargetURN(assignment ports.QuestionnaireAssignment, questionURNsByID map[string]string, slotURNsByKey map[string]string, slotURNsByID map[string]string, gapURNsByID map[string]string) string {
	if gapURN := gapURNsByID[strings.TrimSpace(assignment.GapID)]; gapURN != "" {
		return gapURN
	}
	if slotURN := slotURNsByKey[questionnaireSlotKey(assignment.QuestionID, assignment.SlotID)]; slotURN != "" {
		return slotURN
	}
	if slotURN := slotURNsByID[strings.TrimSpace(assignment.SlotID)]; slotURN != "" {
		return slotURN
	}
	if questionURN := questionURNsByID[strings.TrimSpace(assignment.QuestionID)]; questionURN != "" {
		return questionURN
	}
	return ""
}

func gapEvidenceURN(tenantID string, gap ports.QuestionnaireEvidenceGap) string {
	packetID := strings.TrimSpace(gap.PacketID)
	if packetID == "" {
		return ""
	}
	return citationResourceURN(tenantID, ports.QuestionnaireCitation{ID: packetID, EvidencePacketID: packetID})
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
		if !isControlURN(tenantID, controlID) {
			return ""
		}
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
	return isSameTenantKindURN(tenantID, value, "runtime_evidence", "runtime.evidence")
}

func isControlURN(tenantID string, value string) bool {
	return isSameTenantKindURN(tenantID, value, "control")
}

func isSourceArtifactURN(tenantID string, value string) bool {
	return isSameTenantKindURN(tenantID, value, "assurance_document", "security_review", "security_questionnaire", "penetration_test", "runtime_evidence", "runtime.evidence")
}

func isSameTenantCerebroURN(tenantID string, value string) bool {
	parsed, err := cerebrourn.Parse(value)
	if err != nil {
		return false
	}
	return parsed.TenantID == strings.TrimSpace(tenantID)
}

func isSameTenantKindURN(tenantID string, value string, kinds ...string) bool {
	parsed, err := cerebrourn.Parse(value)
	if err != nil {
		return false
	}
	if parsed.TenantID != strings.TrimSpace(tenantID) {
		return false
	}
	for _, kind := range kinds {
		if parsed.Kind == kind {
			return true
		}
	}
	return false
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

func joinProjectionValues(values []string) string {
	return strings.Join(uniqueSorted(values), ",")
}

func positiveIntString(value int) string {
	if value <= 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func projectionLabel(value string) string {
	value = projectionAttributeValue(value)
	if value == "" {
		return "Questionnaire work item"
	}
	return value
}

func projectionAttributeValue(value string) string {
	value = strings.TrimSpace(value)
	const maxProjectionAttributeBytes = 512
	if len(value) <= maxProjectionAttributeBytes {
		return value
	}
	truncated := value[:maxProjectionAttributeBytes]
	for !utf8.ValidString(truncated) && len(truncated) > 0 {
		truncated = truncated[:len(truncated)-1]
	}
	return strings.TrimSpace(truncated)
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
