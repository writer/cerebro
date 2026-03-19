package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyPersonAcknowledgmentSyncRequest records one explicit
// person-scoped acknowledgment event across the policies they currently owe.
// When PolicyIDs is empty, all currently assigned policies are considered.
type OrganizationalPolicyPersonAcknowledgmentSyncRequest struct {
	PersonID       string         `json:"person_id"`
	PolicyIDs      []string       `json:"policy_ids,omitempty"`
	AcknowledgedAt time.Time      `json:"acknowledged_at,omitempty"`
	SourceSystem   string         `json:"source_system,omitempty"`
	SourceEventID  string         `json:"source_event_id,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// OrganizationalPolicyPersonAcknowledgmentSyncResult summarizes one person-
// scoped acknowledgment sync across currently assigned policies.
type OrganizationalPolicyPersonAcknowledgmentSyncResult struct {
	PersonID                     string                                     `json:"person_id"`
	AcknowledgedPolicyIDs        []string                                   `json:"acknowledged_policy_ids,omitempty"`
	AlreadyAcknowledgedPolicyIDs []string                                   `json:"already_acknowledged_policy_ids,omitempty"`
	Acknowledgments              []OrganizationalPolicyAcknowledgmentResult `json:"acknowledgments,omitempty"`
	SourceSystem                 string                                     `json:"source_system"`
	SourceEventID                string                                     `json:"source_event_id"`
}

// AcknowledgeAssignedOrganizationalPoliciesForPerson records current-version
// acknowledgments for the policies a person currently owes. This supports LMS
// and onboarding sync flows without requiring callers to replay one
// acknowledgment write per assigned policy.
func AcknowledgeAssignedOrganizationalPoliciesForPerson(g *Graph, req OrganizationalPolicyPersonAcknowledgmentSyncRequest) (OrganizationalPolicyPersonAcknowledgmentSyncResult, error) {
	if g == nil {
		return OrganizationalPolicyPersonAcknowledgmentSyncResult{}, fmt.Errorf("graph is required")
	}

	personID := strings.TrimSpace(req.PersonID)
	if personID == "" {
		return OrganizationalPolicyPersonAcknowledgmentSyncResult{}, fmt.Errorf("person_id is required")
	}

	report, err := OrganizationalPolicyAcknowledgmentStatusForPerson(g, personID)
	if err != nil {
		return OrganizationalPolicyPersonAcknowledgmentSyncResult{}, err
	}

	requiredByID := make(map[string]OrganizationalPolicyPersonRequirement, len(report.Policies))
	for _, policy := range report.Policies {
		requiredByID[policy.PolicyID] = policy
	}

	targetPolicyIDs := uniquePolicyStrings(req.PolicyIDs)
	if len(targetPolicyIDs) == 0 {
		targetPolicyIDs = make([]string, 0, len(report.Policies))
		for _, policy := range report.Policies {
			targetPolicyIDs = append(targetPolicyIDs, policy.PolicyID)
		}
		sort.Strings(targetPolicyIDs)
	}

	for _, policyID := range targetPolicyIDs {
		if _, ok := requiredByID[policyID]; !ok {
			return OrganizationalPolicyPersonAcknowledgmentSyncResult{}, fmt.Errorf("policy %s is not currently assigned to person %s", policyID, personID)
		}
	}

	metadata := NormalizeWriteMetadata(req.AcknowledgedAt, req.AcknowledgedAt, nil, req.SourceSystem, req.SourceEventID, req.Confidence, WriteMetadataDefaults{
		SourceSystem:      "policy_acknowledgment",
		SourceEventPrefix: "policy-acknowledgment-sync",
		DefaultConfidence: 1.0,
	})

	alreadyAcknowledged := make([]string, 0, len(targetPolicyIDs))
	acknowledgedPolicyIDs := make([]string, 0, len(targetPolicyIDs))
	acknowledgments := make([]OrganizationalPolicyAcknowledgmentResult, 0, len(targetPolicyIDs))

	for _, policyID := range targetPolicyIDs {
		requirement := requiredByID[policyID]
		if requirement.Status == OrganizationalPolicyPersonStatusAcknowledged {
			alreadyAcknowledged = append(alreadyAcknowledged, policyID)
			continue
		}
		sourceEventID := metadata.SourceEventID
		if sourceEventID != "" {
			sourceEventID = fmt.Sprintf("%s:policy:%s", sourceEventID, policyID)
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
			return OrganizationalPolicyPersonAcknowledgmentSyncResult{}, err
		}
		acknowledgedPolicyIDs = append(acknowledgedPolicyIDs, policyID)
		acknowledgments = append(acknowledgments, result)
	}

	sort.Strings(alreadyAcknowledged)
	sort.Strings(acknowledgedPolicyIDs)

	return OrganizationalPolicyPersonAcknowledgmentSyncResult{
		PersonID:                     personID,
		AcknowledgedPolicyIDs:        acknowledgedPolicyIDs,
		AlreadyAcknowledgedPolicyIDs: alreadyAcknowledged,
		Acknowledgments:              acknowledgments,
		SourceSystem:                 metadata.SourceSystem,
		SourceEventID:                metadata.SourceEventID,
	}, nil
}
