package graph

import (
	"fmt"
	"strings"
	"time"
)

// OrganizationalPolicyDepartmentAssignmentRequest updates the department-level
// assignment scope for one existing policy without rewriting the full policy
// record.
type OrganizationalPolicyDepartmentAssignmentRequest struct {
	PolicyID            string         `json:"policy_id"`
	AddDepartmentIDs    []string       `json:"add_department_ids,omitempty"`
	RemoveDepartmentIDs []string       `json:"remove_department_ids,omitempty"`
	SourceSystem        string         `json:"source_system,omitempty"`
	SourceEventID       string         `json:"source_event_id,omitempty"`
	ObservedAt          time.Time      `json:"observed_at,omitempty"`
	ValidFrom           time.Time      `json:"valid_from,omitempty"`
	ValidTo             *time.Time     `json:"valid_to,omitempty"`
	RecordedAt          time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom     time.Time      `json:"transaction_from,omitempty"`
	TransactionTo       *time.Time     `json:"transaction_to,omitempty"`
	Confidence          float64        `json:"confidence,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

// OrganizationalPolicyDepartmentAssignmentResult summarizes one department
// assignment update.
type OrganizationalPolicyDepartmentAssignmentResult struct {
	PolicyID              string   `json:"policy_id"`
	PolicyVersion         string   `json:"policy_version"`
	DepartmentIDs         []string `json:"department_ids,omitempty"`
	AddedDepartmentIDs    []string `json:"added_department_ids,omitempty"`
	RemovedDepartmentIDs  []string `json:"removed_department_ids,omitempty"`
	ChangedFields         []string `json:"changed_fields,omitempty"`
	VersionHistoryEntries int      `json:"version_history_entries"`
	SourceSystem          string   `json:"source_system"`
	SourceEventID         string   `json:"source_event_id"`
}

// UpdateOrganizationalPolicyDepartmentAssignments updates only the department
// assignments for an existing policy while preserving direct person scope.
func UpdateOrganizationalPolicyDepartmentAssignments(g *Graph, req OrganizationalPolicyDepartmentAssignmentRequest) (OrganizationalPolicyDepartmentAssignmentResult, error) {
	if g == nil {
		return OrganizationalPolicyDepartmentAssignmentResult{}, fmt.Errorf("graph is required")
	}

	policyID := strings.TrimSpace(req.PolicyID)
	if policyID == "" {
		return OrganizationalPolicyDepartmentAssignmentResult{}, fmt.Errorf("policy_id is required")
	}

	policy, ok := g.GetNode(policyID)
	if !ok || policy == nil || policy.Kind != NodeKindPolicy {
		return OrganizationalPolicyDepartmentAssignmentResult{}, fmt.Errorf("policy not found: %s", policyID)
	}

	addDepartmentIDs, err := validatePolicyTargets(g, req.AddDepartmentIDs, NodeKindDepartment)
	if err != nil {
		return OrganizationalPolicyDepartmentAssignmentResult{}, err
	}
	removeDepartmentIDs, err := validatePolicyTargets(g, req.RemoveDepartmentIDs, NodeKindDepartment)
	if err != nil {
		return OrganizationalPolicyDepartmentAssignmentResult{}, err
	}
	if overlap := overlappingPolicyStrings(addDepartmentIDs, removeDepartmentIDs); len(overlap) > 0 {
		return OrganizationalPolicyDepartmentAssignmentResult{}, fmt.Errorf("department ids cannot be added and removed in the same update: %s", strings.Join(overlap, ", "))
	}

	current := organizationalPolicyVersionStateFromGraph(policy, g)
	nextDepartmentIDs, addedDepartmentIDs, removedDepartmentIDs := updatePolicyAssignmentSet(current.RequiredDepartmentIDs, addDepartmentIDs, removeDepartmentIDs)
	metadata := NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, WriteMetadataDefaults{
		RecordedAt:        req.RecordedAt,
		TransactionFrom:   req.TransactionFrom,
		TransactionTo:     req.TransactionTo,
		SourceSystem:      "policy_assignment",
		SourceEventPrefix: "organizational-policy-assignment",
		DefaultConfidence: 0.95,
	})

	historyEntries, changedFields := updateExistingOrganizationalPolicyAssignments(g, policy, nextDepartmentIDs, current.RequiredPersonIDs, metadata, req.Metadata)

	return OrganizationalPolicyDepartmentAssignmentResult{
		PolicyID:              policyID,
		PolicyVersion:         current.PolicyVersion,
		DepartmentIDs:         nextDepartmentIDs,
		AddedDepartmentIDs:    addedDepartmentIDs,
		RemovedDepartmentIDs:  removedDepartmentIDs,
		ChangedFields:         changedFields,
		VersionHistoryEntries: len(historyEntries),
		SourceSystem:          metadata.SourceSystem,
		SourceEventID:         metadata.SourceEventID,
	}, nil
}
