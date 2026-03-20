package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyAcknowledgmentSyncRequest records one explicit
// policy-scoped acknowledgment event across the people who currently owe that
// policy. When PersonIDs is empty, all current assignees are considered.
type OrganizationalPolicyAcknowledgmentSyncRequest struct {
	PolicyID       string         `json:"policy_id"`
	PersonIDs      []string       `json:"person_ids,omitempty"`
	AcknowledgedAt time.Time      `json:"acknowledged_at,omitempty"`
	SourceSystem   string         `json:"source_system,omitempty"`
	SourceEventID  string         `json:"source_event_id,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// OrganizationalPolicyAcknowledgmentSyncResult summarizes one policy-scoped
// acknowledgment sync across currently assigned people.
type OrganizationalPolicyAcknowledgmentSyncResult struct {
	PolicyID                     string                                     `json:"policy_id"`
	AcknowledgedPersonIDs        []string                                   `json:"acknowledged_person_ids,omitempty"`
	AlreadyAcknowledgedPersonIDs []string                                   `json:"already_acknowledged_person_ids,omitempty"`
	Acknowledgments              []OrganizationalPolicyAcknowledgmentResult `json:"acknowledgments,omitempty"`
	SourceSystem                 string                                     `json:"source_system"`
	SourceEventID                string                                     `json:"source_event_id"`
}

// AcknowledgeOrganizationalPolicyForAssignedPeople records current-version
// acknowledgments for the people who currently owe one policy. This supports
// policy-centric LMS ingestion without requiring callers to replay one write
// per person.
func AcknowledgeOrganizationalPolicyForAssignedPeople(g *Graph, req OrganizationalPolicyAcknowledgmentSyncRequest) (OrganizationalPolicyAcknowledgmentSyncResult, error) {
	if g == nil {
		return OrganizationalPolicyAcknowledgmentSyncResult{}, fmt.Errorf("graph is required")
	}

	policyID := strings.TrimSpace(req.PolicyID)
	if policyID == "" {
		return OrganizationalPolicyAcknowledgmentSyncResult{}, fmt.Errorf("policy_id is required")
	}

	report, err := OrganizationalPolicyAssigneeRoster(g, policyID)
	if err != nil {
		return OrganizationalPolicyAcknowledgmentSyncResult{}, err
	}

	assigneesByID := make(map[string]OrganizationalPolicyAssignee, len(report.Assignees))
	for _, assignee := range report.Assignees {
		assigneesByID[assignee.PersonID] = assignee
	}

	targetPersonIDs := uniquePolicyStrings(req.PersonIDs)
	if len(targetPersonIDs) == 0 {
		targetPersonIDs = make([]string, 0, len(report.Assignees))
		for _, assignee := range report.Assignees {
			targetPersonIDs = append(targetPersonIDs, assignee.PersonID)
		}
		sort.Strings(targetPersonIDs)
	}

	for _, personID := range targetPersonIDs {
		if _, ok := assigneesByID[personID]; !ok {
			return OrganizationalPolicyAcknowledgmentSyncResult{}, fmt.Errorf("person %s is not currently assigned to policy %s", personID, policyID)
		}
	}

	metadata := NormalizeWriteMetadata(req.AcknowledgedAt, req.AcknowledgedAt, nil, req.SourceSystem, req.SourceEventID, req.Confidence, WriteMetadataDefaults{
		SourceSystem:      "policy_acknowledgment",
		SourceEventPrefix: "policy-acknowledgment-sync",
		DefaultConfidence: 1.0,
	})

	alreadyAcknowledged := make([]string, 0, len(targetPersonIDs))
	acknowledgedPersonIDs := make([]string, 0, len(targetPersonIDs))
	acknowledgments := make([]OrganizationalPolicyAcknowledgmentResult, 0, len(targetPersonIDs))

	for _, personID := range targetPersonIDs {
		assignee := assigneesByID[personID]
		if assignee.Status == OrganizationalPolicyAssigneeStatusAcknowledged {
			alreadyAcknowledged = append(alreadyAcknowledged, personID)
			continue
		}
		sourceEventID := metadata.SourceEventID
		if sourceEventID != "" {
			sourceEventID = fmt.Sprintf("%s:person:%s", sourceEventID, personID)
		}

		result, err := AcknowledgeOrganizationalPolicy(g, OrganizationalPolicyAcknowledgmentRequest{
			PersonID:       personID,
			PolicyID:       policyID,
			AcknowledgedAt: metadata.ObservedAt,
			SourceSystem:   metadata.SourceSystem,
			SourceEventID:  sourceEventID,
			Confidence:     metadata.Confidence,
			Metadata:       cloneAnyMap(req.Metadata),
		})
		if err != nil {
			return OrganizationalPolicyAcknowledgmentSyncResult{}, err
		}
		acknowledgedPersonIDs = append(acknowledgedPersonIDs, personID)
		acknowledgments = append(acknowledgments, result)
	}

	sort.Strings(alreadyAcknowledged)
	sort.Strings(acknowledgedPersonIDs)

	return OrganizationalPolicyAcknowledgmentSyncResult{
		PolicyID:                     policyID,
		AcknowledgedPersonIDs:        acknowledgedPersonIDs,
		AlreadyAcknowledgedPersonIDs: alreadyAcknowledged,
		Acknowledgments:              acknowledgments,
		SourceSystem:                 metadata.SourceSystem,
		SourceEventID:                metadata.SourceEventID,
	}, nil
}
