package evidencepackets

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grccontrol"
)

const (
	AccessEvidenceUseOperationProof = "operating_effectiveness"
	AccessEvidenceUseReviewContext  = "review_context"
)

type GraphBackedAccessEvidenceInput struct {
	TenantID         string
	PeriodStart      time.Time
	PeriodEnd        time.Time
	ReviewerURN      string
	OwnerURN         string
	ExceptionState   string
	SourceFreshness  []AccessSourceFreshness
	PolicyCitations  []string
	EffectiveAccess  *graphquery.EffectiveAccessPathResult
	SupportedControl []string
}

type AccessSourceFreshness struct {
	SourceID   string `json:"source_id,omitempty"`
	RuntimeID  string `json:"runtime_id,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
	Status     string `json:"status"`
}

type AccessSourceCitation struct {
	SourceID    string `json:"source_id,omitempty"`
	RuntimeID   string `json:"runtime_id,omitempty"`
	EventID     string `json:"event_id,omitempty"`
	GraphPathID string `json:"graph_path_id,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
}

type AccessEvidenceConfidence struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons,omitempty"`
}

type AccessEvidenceSubject struct {
	AccessEvidenceSubjectIdentity
	AccessEvidenceSubjectPosture
	AccessEvidenceReviewContext
	AccessEvidenceSupport
	AccessEvidenceProofSplit
	AccessItems []AccessEvidenceItem `json:"access_items,omitempty"`
}

type AccessEvidenceSubjectIdentity struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id,omitempty"`
	EvidenceUse    string `json:"evidence_use"`
	SubjectURN     string `json:"subject_urn"`
	SubjectType    string `json:"subject_type,omitempty"`
	SubjectLabel   string `json:"subject_label,omitempty"`
	PrincipalURN   string `json:"principal_urn,omitempty"`
	PrincipalType  string `json:"principal_type,omitempty"`
	PrincipalLabel string `json:"principal_label,omitempty"`
}

type AccessEvidenceSubjectPosture struct {
	AccountStatus  string `json:"account_status,omitempty"`
	LifecycleState string `json:"lifecycle_state,omitempty"`
	MFAPosture     string `json:"mfa_posture,omitempty"`
}

type AccessEvidenceReviewContext struct {
	ReviewerURN       string                  `json:"reviewer_urn,omitempty"`
	OwnerURN          string                  `json:"owner_urn,omitempty"`
	ExceptionState    string                  `json:"exception_state,omitempty"`
	ManualReviewState string                  `json:"manual_review_state,omitempty"`
	PeriodStart       string                  `json:"period_start,omitempty"`
	PeriodEnd         string                  `json:"period_end,omitempty"`
	Freshness         []AccessSourceFreshness `json:"freshness,omitempty"`
	SourceFreshness   []AccessSourceFreshness `json:"source_freshness,omitempty"`
}

type AccessEvidenceSupport struct {
	SourceCitations   []AccessSourceCitation   `json:"source_citations,omitempty"`
	PolicyCitations   []string                 `json:"policy_citations,omitempty"`
	IncludedBecause   []string                 `json:"included_because,omitempty"`
	RiskSignals       []string                 `json:"risk_signals,omitempty"`
	ChangeSummary     []string                 `json:"change_summary,omitempty"`
	MissingFacts      []string                 `json:"missing_facts,omitempty"`
	UnsupportedClaims []string                 `json:"unsupported_claims,omitempty"`
	OverclaimGuards   []string                 `json:"overclaim_guards,omitempty"`
	Confidence        AccessEvidenceConfidence `json:"confidence"`
	SupportedControls []string                 `json:"supported_controls,omitempty"`
	Citations         EvidenceCitations        `json:"citations"`
}

type AccessEvidenceProofSplit struct {
	OperatingEffectivenessItemIDs []string `json:"operating_effectiveness_item_ids,omitempty"`
	ReviewContextItemIDs          []string `json:"review_context_item_ids,omitempty"`
	ManualReviewOnlyItemIDs       []string `json:"manual_review_only_item_ids,omitempty"`
}

type AccessEvidenceItem struct {
	AccessEvidenceItemIdentity
	AccessEvidenceItemPath
	AccessEvidenceItemClassification
	AccessEvidenceItemProvenance
	Attributes map[string]string `json:"attributes,omitempty"`
}

type AccessEvidenceItemIdentity struct {
	ID             string `json:"id"`
	EvidenceUse    string `json:"evidence_use"`
	AssignmentKind string `json:"assignment_kind,omitempty"`
}

type AccessEvidenceItemPath struct {
	AccessTargetURN   string `json:"access_target_urn,omitempty"`
	AccessTargetType  string `json:"access_target_type,omitempty"`
	AccessTargetLabel string `json:"access_target_label,omitempty"`
	MediatorURN       string `json:"mediator_urn,omitempty"`
	MediatorType      string `json:"mediator_type,omitempty"`
	MediatorLabel     string `json:"mediator_label,omitempty"`
	EntitlementURN    string `json:"entitlement_urn,omitempty"`
	EntitlementType   string `json:"entitlement_type,omitempty"`
	EntitlementLabel  string `json:"entitlement_label,omitempty"`
	CapabilityURN     string `json:"capability_urn,omitempty"`
	CapabilityType    string `json:"capability_type,omitempty"`
	CapabilityLabel   string `json:"capability_label,omitempty"`
}

type AccessEvidenceItemClassification struct {
	Privileged          bool     `json:"privileged"`
	Sensitive           bool     `json:"sensitive"`
	Classification      []string `json:"classification,omitempty"`
	ChangedDuringPeriod bool     `json:"changed_during_period"`
}

type AccessEvidenceItemProvenance struct {
	SourceIDs       []string               `json:"source_ids,omitempty"`
	RuntimeIDs      []string               `json:"runtime_ids,omitempty"`
	EventIDs        []string               `json:"event_ids,omitempty"`
	GraphPathIDs    []string               `json:"graph_path_ids,omitempty"`
	GraphRoots      []string               `json:"graph_root_urns,omitempty"`
	SourceCitations []AccessSourceCitation `json:"source_citations,omitempty"`
}

type EvidenceReasoningTask struct {
	ID               string            `json:"id"`
	SubjectID        string            `json:"subject_id,omitempty"`
	Question         string            `json:"question"`
	AnswerScope      string            `json:"answer_scope"`
	ControlIDs       []string          `json:"control_ids,omitempty"`
	PolicyCitations  []string          `json:"policy_citations,omitempty"`
	CitationRoots    []string          `json:"citation_graph_root_urns,omitempty"`
	CitationPathIDs  []string          `json:"citation_graph_path_ids,omitempty"`
	CitationEventIDs []string          `json:"citation_event_ids,omitempty"`
	Guards           []string          `json:"guards,omitempty"`
	Attributes       map[string]string `json:"attributes,omitempty"`
}

func BuildWithGraphBackedAccessEvidence(result grccontrol.PacketResult, input GraphBackedAccessEvidenceInput) Response {
	response := Build(result)
	return AddGraphBackedAccessEvidence(response, input)
}

func AddGraphBackedAccessEvidence(response Response, input GraphBackedAccessEvidenceInput) Response {
	subjects, graphRows, graphPaths, reasoning := graphBackedAccessRecords(input)
	if len(subjects) == 0 {
		return response
	}
	response.Access = append(response.Access, subjects...)
	response.Reasoning = append(response.Reasoning, reasoning...)
	response.GraphRows = append(response.GraphRows, graphRows...)
	response.GraphPaths = append(response.GraphPaths, graphPaths...)
	sort.Slice(response.Access, func(i, j int) bool { return response.Access[i].ID < response.Access[j].ID })
	sort.Slice(response.Reasoning, func(i, j int) bool { return response.Reasoning[i].ID < response.Reasoning[j].ID })
	sort.Slice(response.GraphRows, func(i, j int) bool { return response.GraphRows[i].ID < response.GraphRows[j].ID })
	sort.Slice(response.GraphPaths, func(i, j int) bool { return response.GraphPaths[i].ID < response.GraphPaths[j].ID })
	response.Program.GraphPathCount = len(response.GraphPaths)
	response.Snapshot.GraphPathCount = len(response.GraphPaths)
	response.Snapshot.Hash = snapshotHash(response.Program, response.Frameworks, response.Controls, response.Requests, response.Packets, response.Items, response.Findings, response.Resources, response.Lineage, response.Claims, response.Runs, response.GraphRows, response.GraphPaths, response.Access, response.Reasoning, response.Exceptions)
	response.Artifacts = exportArtifacts(response.Export, response.Snapshot)
	return response
}

func graphBackedAccessRecords(input GraphBackedAccessEvidenceInput) ([]AccessEvidenceSubject, []GraphEvidenceRecord, []GraphPathRecord, []EvidenceReasoningTask) {
	if input.EffectiveAccess == nil || len(input.EffectiveAccess.Paths) == 0 {
		return nil, nil, nil, nil
	}
	subjectsByKey := map[string]*AccessEvidenceSubject{}
	pathIDsBySubject := map[string][]string{}
	rowsBySubject := map[string]*GraphEvidenceRecord{}
	graphPaths := []GraphPathRecord{}
	for pathIndex, path := range input.EffectiveAccess.Paths {
		subjectURN := firstNonEmpty(path.Identity.URN, path.Principal.URN)
		if subjectURN == "" {
			continue
		}
		subjectID := stableID("access-subject", subjectURN)
		subject := subjectsByKey[subjectID]
		if subject == nil {
			subject = &AccessEvidenceSubject{
				AccessEvidenceSubjectIdentity: AccessEvidenceSubjectIdentity{
					ID:             subjectID,
					TenantID:       firstNonEmpty(input.TenantID, input.EffectiveAccess.TenantID),
					EvidenceUse:    AccessEvidenceUseReviewContext,
					SubjectURN:     subjectURN,
					SubjectType:    path.Identity.EntityType,
					SubjectLabel:   path.Identity.Label,
					PrincipalURN:   path.Principal.URN,
					PrincipalType:  path.Principal.EntityType,
					PrincipalLabel: path.Principal.Label,
				},
				AccessEvidenceReviewContext: AccessEvidenceReviewContext{
					ReviewerURN:     strings.TrimSpace(input.ReviewerURN),
					OwnerURN:        strings.TrimSpace(input.OwnerURN),
					ExceptionState:  firstNonEmpty(input.ExceptionState, "not_recorded"),
					PeriodStart:     formatTime(input.PeriodStart),
					PeriodEnd:       formatTime(input.PeriodEnd),
					SourceFreshness: append([]AccessSourceFreshness(nil), input.SourceFreshness...),
					Freshness:       append([]AccessSourceFreshness(nil), input.SourceFreshness...),
				},
				AccessEvidenceSupport: AccessEvidenceSupport{
					PolicyCitations:   uniqueSortedStrings(input.PolicyCitations),
					SupportedControls: accessControlSupport(input.SupportedControl),
					OverclaimGuards:   accessOverclaimGuards(),
				},
			}
			subjectsByKey[subjectID] = subject
			rowsBySubject[subjectID] = &GraphEvidenceRecord{
				ID:         stableID("graph-access-row", subjectID),
				EvidenceID: subjectID,
				Label:      "graph_backed_access_review_subject",
				Attributes: map[string]string{
					"evidence_use": AccessEvidenceUseReviewContext,
					"tenant_id":    subject.TenantID,
				},
			}
		}
		item, pathRecords := accessItemFromPath(subjectID, pathIndex, path, input)
		if item.ID == "" {
			continue
		}
		deriveSubjectPosture(subject, path)
		subject.AccessItems = append(subject.AccessItems, item)
		subject.Citations.EventIDs = uniqueSortedStrings(append(subject.Citations.EventIDs, item.EventIDs...))
		subject.Citations.GraphRoots = uniqueSortedStrings(append(subject.Citations.GraphRoots, item.GraphRoots...))
		subject.SourceCitations = mergeSourceCitations(subject.SourceCitations, item.SourceCitations)
		subject.IncludedBecause = uniqueSortedStrings(append(subject.IncludedBecause, includedBecause(path, item)...))
		subject.RiskSignals = uniqueSortedStrings(append(subject.RiskSignals, riskSignals(item, subject)...))
		subject.ChangeSummary = uniqueSortedStrings(append(subject.ChangeSummary, changeSummary(item)...))
		if item.EvidenceUse == AccessEvidenceUseOperationProof {
			subject.EvidenceUse = AccessEvidenceUseOperationProof
			rowsBySubject[subjectID].Attributes["evidence_use"] = AccessEvidenceUseOperationProof
			subject.OperatingEffectivenessItemIDs = append(subject.OperatingEffectivenessItemIDs, item.ID)
		} else {
			subject.ReviewContextItemIDs = append(subject.ReviewContextItemIDs, item.ID)
			subject.ManualReviewOnlyItemIDs = append(subject.ManualReviewOnlyItemIDs, item.ID)
		}
		pathIDsBySubject[subjectID] = append(pathIDsBySubject[subjectID], item.GraphPathIDs...)
		graphPaths = append(graphPaths, pathRecords...)
	}
	subjects := make([]AccessEvidenceSubject, 0, len(subjectsByKey))
	graphRows := make([]GraphEvidenceRecord, 0, len(rowsBySubject))
	for id, subject := range subjectsByKey {
		sort.Slice(subject.AccessItems, func(i, j int) bool { return subject.AccessItems[i].ID < subject.AccessItems[j].ID })
		subject.SourceFreshness = mergeAccessFreshness(subject.SourceFreshness, subject.AccessItems)
		subject.Freshness = append([]AccessSourceFreshness(nil), subject.SourceFreshness...)
		subject.OperatingEffectivenessItemIDs = uniqueSortedStrings(subject.OperatingEffectivenessItemIDs)
		subject.ReviewContextItemIDs = uniqueSortedStrings(subject.ReviewContextItemIDs)
		subject.ManualReviewOnlyItemIDs = uniqueSortedStrings(subject.ManualReviewOnlyItemIDs)
		subject.MissingFacts = missingAccessFacts(*subject)
		subject.UnsupportedClaims = unsupportedAccessClaims(*subject)
		subject.ManualReviewState = manualReviewState(*subject)
		subject.Confidence = confidenceForAccessSubject(*subject)
		if len(subject.SourceFreshness) == 0 {
			subject.RiskSignals = uniqueSortedStrings(append(subject.RiskSignals, "source_freshness_missing"))
		}
		if subject.MFAPosture == "" {
			subject.RiskSignals = uniqueSortedStrings(append(subject.RiskSignals, "mfa_posture_unknown"))
		}
		if subject.AccountStatus == "" {
			subject.AccountStatus = "unknown"
		}
		if subject.LifecycleState == "" {
			subject.LifecycleState = "unknown"
		}
		if len(subject.MissingFacts) > 0 {
			subject.RiskSignals = uniqueSortedStrings(append(subject.RiskSignals, subject.MissingFacts...))
		}
		if hasStaleFreshness(subject.SourceFreshness) {
			subject.RiskSignals = uniqueSortedStrings(append(subject.RiskSignals, "source_freshness_stale"))
		}
		if row := rowsBySubject[id]; row != nil {
			row.PathIDs = uniqueSortedStrings(pathIDsBySubject[id])
			graphRows = append(graphRows, *row)
		}
		subjects = append(subjects, *subject)
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].ID < subjects[j].ID })
	sort.Slice(graphRows, func(i, j int) bool { return graphRows[i].ID < graphRows[j].ID })
	sort.Slice(graphPaths, func(i, j int) bool { return graphPaths[i].ID < graphPaths[j].ID })
	return subjects, graphRows, graphPaths, reasoningTasksForAccessSubjects(subjects)
}

func accessItemFromPath(subjectID string, pathIndex int, path graphquery.EffectiveAccessPath, input GraphBackedAccessEvidenceInput) (AccessEvidenceItem, []GraphPathRecord) {
	pathIDs := []string{}
	eventIDs := []string{}
	sourceIDs := []string{}
	runtimeIDs := []string{}
	sourceCitations := []AccessSourceCitation{}
	changed := changedDuringPeriod(path, input.PeriodStart, input.PeriodEnd)
	evidenceUse := AccessEvidenceUseReviewContext
	if path.SupportsOperationProof(changed) {
		evidenceUse = AccessEvidenceUseOperationProof
	}
	roots := []string{path.Identity.URN, path.Principal.URN, path.AccessTarget.URN, path.Entitlement.URN, path.Capability.URN}
	if path.Mediator != nil {
		roots = append(roots, path.Mediator.URN)
	}
	graphPaths := make([]GraphPathRecord, 0, len(path.Edges))
	for edgeIndex, edge := range path.Edges {
		pathID := stableID("graph-access-path", subjectID, path.AccessTarget.URN, path.Capability.URN, edge.From.URN, edge.Relation, edge.To.URN, fmt.Sprint(pathIndex), fmt.Sprint(edgeIndex))
		pathIDs = append(pathIDs, pathID)
		eventIDs = append(eventIDs, edge.EventID)
		sourceIDs = append(sourceIDs, edge.SourceID)
		runtimeIDs = append(runtimeIDs, edge.RuntimeID)
		sourceCitations = append(sourceCitations, AccessSourceCitation{
			SourceID:    edge.SourceID,
			RuntimeID:   edge.RuntimeID,
			EventID:     edge.EventID,
			GraphPathID: pathID,
			ObservedAt:  edge.At,
		})
		attributes := copyStringMap(edge.Attributes)
		if attributes == nil {
			attributes = map[string]string{}
		}
		attributes["evidence_use"] = evidenceUse
		attributes["assignment_kind"] = strings.TrimSpace(path.AssignmentKind)
		if edge.SourceID != "" {
			attributes["source_id"] = edge.SourceID
		}
		if edge.RuntimeID != "" {
			attributes["runtime_id"] = edge.RuntimeID
		}
		if edge.EventID != "" {
			attributes["event_id"] = edge.EventID
		}
		graphPaths = append(graphPaths, GraphPathRecord{
			ID:         pathID,
			EvidenceID: subjectID,
			FromURN:    edge.From.URN,
			FromType:   edge.From.EntityType,
			Relation:   edge.Relation,
			ToURN:      edge.To.URN,
			ToType:     edge.To.EntityType,
			ObservedAt: edge.At,
			Attributes: attributes,
		})
	}
	item := AccessEvidenceItem{
		AccessEvidenceItemIdentity: AccessEvidenceItemIdentity{
			ID:             stableID("access-item", subjectID, path.AccessTarget.URN, path.Entitlement.URN, path.Capability.URN, path.AssignmentKind),
			EvidenceUse:    evidenceUse,
			AssignmentKind: strings.TrimSpace(path.AssignmentKind),
		},
		AccessEvidenceItemPath: AccessEvidenceItemPath{
			AccessTargetURN:   path.AccessTarget.URN,
			AccessTargetType:  path.AccessTarget.EntityType,
			AccessTargetLabel: path.AccessTarget.Label,
			EntitlementURN:    path.Entitlement.URN,
			EntitlementType:   path.Entitlement.EntityType,
			EntitlementLabel:  path.Entitlement.Label,
			CapabilityURN:     path.Capability.URN,
			CapabilityType:    path.Capability.EntityType,
			CapabilityLabel:   path.Capability.Label,
		},
		AccessEvidenceItemClassification: AccessEvidenceItemClassification{
			Privileged:          path.IsPrivileged(),
			Sensitive:           path.IsSensitive(),
			Classification:      path.AccessClassification(),
			ChangedDuringPeriod: changed,
		},
		AccessEvidenceItemProvenance: AccessEvidenceItemProvenance{
			SourceIDs:       uniqueSortedStrings(sourceIDs),
			RuntimeIDs:      uniqueSortedStrings(runtimeIDs),
			EventIDs:        uniqueSortedStrings(eventIDs),
			GraphPathIDs:    uniqueSortedStrings(pathIDs),
			GraphRoots:      uniqueSortedStrings(roots),
			SourceCitations: mergeSourceCitations(nil, sourceCitations),
		},
		Attributes: map[string]string{
			"relation_chain": strings.Join(path.RelationChain, " > "),
		},
	}
	if path.Mediator != nil {
		item.MediatorURN = path.Mediator.URN
		item.MediatorType = path.Mediator.EntityType
		item.MediatorLabel = path.Mediator.Label
	}
	return item, graphPaths
}

func deriveSubjectPosture(subject *AccessEvidenceSubject, path graphquery.EffectiveAccessPath) {
	for _, edge := range path.Edges {
		subject.AccountStatus = firstNonEmpty(subject.AccountStatus, edge.Attributes["account_status"], edge.Attributes["status"])
		subject.LifecycleState = firstNonEmpty(subject.LifecycleState, edge.Attributes["lifecycle_state"], edge.Attributes["lifecycle_status"])
		subject.MFAPosture = firstNonEmpty(subject.MFAPosture, edge.Attributes["mfa_posture"], edge.Attributes["mfa_status"], edge.Attributes["mfa_enrolled"])
	}
}

func includedBecause(path graphquery.EffectiveAccessPath, item AccessEvidenceItem) []string {
	reasons := []string{"subject_has_graph_backed_access_path"}
	if item.MediatorURN != "" {
		reasons = append(reasons, "access_is_group_mediated")
	}
	if item.Privileged {
		reasons = append(reasons, "access_is_privileged")
	}
	if item.ChangedDuringPeriod {
		reasons = append(reasons, "access_changed_during_review_period")
	}
	if path.AssignmentKind != "" {
		reasons = append(reasons, path.AssignmentKind)
	}
	return reasons
}

func riskSignals(item AccessEvidenceItem, subject *AccessEvidenceSubject) []string {
	signals := []string{}
	if item.Privileged {
		signals = append(signals, "privileged_access")
	}
	if item.Sensitive {
		signals = append(signals, "sensitive_access")
	}
	if item.EvidenceUse == AccessEvidenceUseReviewContext {
		signals = append(signals, "context_only_access_item")
	}
	mfa := strings.ToLower(subject.MFAPosture)
	if mfa == "false" || mfa == "disabled" || mfa == "not_enrolled" || mfa == "unenrolled" {
		signals = append(signals, "mfa_not_enrolled")
	}
	lifecycle := strings.ToLower(subject.LifecycleState)
	if lifecycle == "deprovisioned" || lifecycle == "suspended" || lifecycle == "terminated" || lifecycle == "inactive" {
		signals = append(signals, "access_after_inactive_lifecycle_state")
	}
	if lifecycle == "dormant" || strings.EqualFold(subject.AccountStatus, "dormant") {
		signals = append(signals, "dormant_user_access")
	}
	return signals
}

func changeSummary(item AccessEvidenceItem) []string {
	if item.ChangedDuringPeriod {
		return []string{"graph_access_edge_observed_during_review_period"}
	}
	return nil
}

func changedDuringPeriod(path graphquery.EffectiveAccessPath, start time.Time, end time.Time) bool {
	if start.IsZero() && end.IsZero() {
		return false
	}
	for _, edge := range path.Edges {
		if edge.At == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, edge.At)
		if err != nil {
			continue
		}
		if !start.IsZero() && at.Before(start) {
			continue
		}
		if !end.IsZero() && at.After(end) {
			continue
		}
		return true
	}
	return false
}

func mergeAccessFreshness(existing []AccessSourceFreshness, items []AccessEvidenceItem) []AccessSourceFreshness {
	byKey := map[string]AccessSourceFreshness{}
	for _, freshness := range existing {
		key := stableID(freshness.SourceID, freshness.RuntimeID, freshness.ObservedAt)
		byKey[key] = freshness
	}
	for _, item := range items {
		for _, runtimeID := range item.RuntimeIDs {
			if accessFreshnessCoversRuntime(existing, runtimeID) {
				continue
			}
			key := stableID("", runtimeID, "")
			if _, ok := byKey[key]; !ok {
				byKey[key] = AccessSourceFreshness{RuntimeID: runtimeID, Status: "observed"}
			}
		}
		for _, sourceID := range item.SourceIDs {
			if accessFreshnessCoversSource(existing, sourceID) {
				continue
			}
			key := stableID(sourceID, "", "")
			if _, ok := byKey[key]; !ok {
				byKey[key] = AccessSourceFreshness{SourceID: sourceID, Status: "observed"}
			}
		}
	}
	out := make([]AccessSourceFreshness, 0, len(byKey))
	for _, freshness := range byKey {
		if freshness.Status == "" {
			freshness.Status = "observed"
		}
		out = append(out, freshness)
	}
	sort.Slice(out, func(i, j int) bool {
		return stableID(out[i].SourceID, out[i].RuntimeID, out[i].ObservedAt) < stableID(out[j].SourceID, out[j].RuntimeID, out[j].ObservedAt)
	})
	return out
}

func accessFreshnessCoversRuntime(values []AccessSourceFreshness, runtimeID string) bool {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return true
	}
	for _, value := range values {
		if strings.TrimSpace(value.RuntimeID) == runtimeID {
			return true
		}
	}
	return false
}

func accessFreshnessCoversSource(values []AccessSourceFreshness, sourceID string) bool {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return true
	}
	for _, value := range values {
		if strings.TrimSpace(value.SourceID) == sourceID {
			return true
		}
	}
	return false
}

func reasoningTasksForAccessSubjects(subjects []AccessEvidenceSubject) []EvidenceReasoningTask {
	tasks := []EvidenceReasoningTask{}
	questions := []string{
		"Why was this subject included in the access review evidence?",
		"What access is privileged for this subject?",
		"What changed during the review period?",
		"What remains risky after reviewer context and exceptions?",
		"Which controls does this evidence support?",
	}
	for _, subject := range subjects {
		pathIDs := []string{}
		for _, item := range subject.AccessItems {
			pathIDs = append(pathIDs, item.GraphPathIDs...)
		}
		for _, question := range questions {
			tasks = append(tasks, EvidenceReasoningTask{
				ID:               stableID("access-reasoning", subject.ID, question),
				SubjectID:        subject.ID,
				Question:         question,
				AnswerScope:      "Use only cited access evidence subject, access items, graph path records, source freshness, reviewer, exception, and period fields.",
				ControlIDs:       append([]string(nil), subject.SupportedControls...),
				PolicyCitations:  append([]string(nil), subject.PolicyCitations...),
				CitationRoots:    append([]string(nil), subject.Citations.GraphRoots...),
				CitationPathIDs:  uniqueSortedStrings(pathIDs),
				CitationEventIDs: append([]string(nil), subject.Citations.EventIDs...),
				Guards:           append([]string(nil), subject.OverclaimGuards...),
			})
		}
	}
	return tasks
}

func missingAccessFacts(subject AccessEvidenceSubject) []string {
	missing := []string{}
	if subject.MFAPosture == "" || subject.MFAPosture == "unknown" {
		missing = append(missing, "mfa_posture_unknown")
	}
	if subject.LifecycleState == "" || subject.LifecycleState == "unknown" {
		missing = append(missing, "lifecycle_state_unknown")
	}
	if subject.AccountStatus == "" || subject.AccountStatus == "unknown" {
		missing = append(missing, "account_status_unknown")
	}
	if len(subject.SourceFreshness) == 0 {
		missing = append(missing, "source_freshness_missing")
	}
	if subject.ReviewerURN == "" {
		missing = append(missing, "reviewer_missing")
	}
	return uniqueSortedStrings(missing)
}

func unsupportedAccessClaims(subject AccessEvidenceSubject) []string {
	claims := []string{}
	if subject.ReviewerURN == "" {
		claims = append(claims, "reviewer_approval")
	}
	if len(subject.SourceFreshness) == 0 || hasStaleFreshness(subject.SourceFreshness) {
		claims = append(claims, "current_source_complete")
	}
	if subject.MFAPosture == "" || subject.MFAPosture == "unknown" {
		claims = append(claims, "mfa_enforced")
	}
	if len(subject.OperatingEffectivenessItemIDs) == 0 {
		claims = append(claims, "operating_effectiveness")
	}
	return uniqueSortedStrings(claims)
}

func manualReviewState(subject AccessEvidenceSubject) string {
	if len(subject.UnsupportedClaims) > 0 || len(subject.ManualReviewOnlyItemIDs) > 0 || len(subject.MissingFacts) > 0 {
		return "needs_manual_review"
	}
	return "ready_for_review"
}

func confidenceForAccessSubject(subject AccessEvidenceSubject) AccessEvidenceConfidence {
	reasons := []string{}
	level := "high"
	if len(subject.OperatingEffectivenessItemIDs) == 0 {
		level = "blocked"
		reasons = append(reasons, "no_operating_effectiveness_proof")
	}
	if len(subject.SourceFreshness) == 0 {
		level = "blocked"
		reasons = append(reasons, "source_freshness_missing")
	} else if hasStaleFreshness(subject.SourceFreshness) && level != "blocked" {
		level = "medium"
		reasons = append(reasons, "stale_source_freshness")
	}
	if len(subject.MissingFacts) > 0 && level == "high" {
		level = "medium"
		reasons = append(reasons, "missing_context_facts")
	}
	if subject.ReviewerURN == "" && level == "high" {
		level = "medium"
		reasons = append(reasons, "reviewer_missing")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "graph_access_paths_cited")
	}
	return AccessEvidenceConfidence{Level: level, Reasons: uniqueSortedStrings(reasons)}
}

func hasStaleFreshness(values []AccessSourceFreshness) bool {
	for _, value := range values {
		status := strings.ToLower(strings.TrimSpace(value.Status))
		if status == "stale" || status == "expired" {
			return true
		}
	}
	return false
}

func accessOverclaimGuards() []string {
	return []string{
		"Do not claim reviewer approval unless reviewer or exception fields prove it.",
		"Treat missing MFA, lifecycle, reviewer, or freshness data as unknown, not passing.",
		"Do not infer access outside the cited graph paths.",
		"Do not use review-context items as operating-effectiveness proof.",
	}
}

func mergeSourceCitations(existing []AccessSourceCitation, added []AccessSourceCitation) []AccessSourceCitation {
	byKey := map[string]AccessSourceCitation{}
	for _, citation := range append(existing, added...) {
		if citation.SourceID == "" && citation.RuntimeID == "" && citation.EventID == "" && citation.GraphPathID == "" && citation.ObservedAt == "" {
			continue
		}
		key := stableID(citation.SourceID, citation.RuntimeID, citation.EventID, citation.GraphPathID, citation.ObservedAt)
		byKey[key] = citation
	}
	out := make([]AccessSourceCitation, 0, len(byKey))
	for _, citation := range byKey {
		out = append(out, citation)
	}
	sort.Slice(out, func(i, j int) bool {
		return stableID(out[i].SourceID, out[i].RuntimeID, out[i].EventID, out[i].GraphPathID, out[i].ObservedAt) < stableID(out[j].SourceID, out[j].RuntimeID, out[j].EventID, out[j].GraphPathID, out[j].ObservedAt)
	})
	return out
}

func accessControlSupport(input []string) []string {
	if len(input) > 0 {
		return uniqueSortedStrings(input)
	}
	return []string{
		"access_review",
		"privileged_access",
		"mfa",
		"deprovisioning",
		"dormant_account_review",
		"external_account_review",
	}
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
