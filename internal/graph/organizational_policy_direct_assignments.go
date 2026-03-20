package graph

import (
	"fmt"
	"strings"
	"time"
)

// OrganizationalPolicyDirectPersonAssignmentRequest updates the direct
// person-level assignment scope for one existing policy without rewriting the
// full policy record.
type OrganizationalPolicyDirectPersonAssignmentRequest struct {
	PolicyID        string         `json:"policy_id"`
	AddPersonIDs    []string       `json:"add_person_ids,omitempty"`
	RemovePersonIDs []string       `json:"remove_person_ids,omitempty"`
	SourceSystem    string         `json:"source_system,omitempty"`
	SourceEventID   string         `json:"source_event_id,omitempty"`
	ObservedAt      time.Time      `json:"observed_at,omitempty"`
	ValidFrom       time.Time      `json:"valid_from,omitempty"`
	ValidTo         *time.Time     `json:"valid_to,omitempty"`
	RecordedAt      time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom time.Time      `json:"transaction_from,omitempty"`
	TransactionTo   *time.Time     `json:"transaction_to,omitempty"`
	Confidence      float64        `json:"confidence,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// OrganizationalPolicyDirectPersonAssignmentResult summarizes one direct
// person-assignment update.
type OrganizationalPolicyDirectPersonAssignmentResult struct {
	PolicyID              string   `json:"policy_id"`
	PolicyVersion         string   `json:"policy_version"`
	DirectPersonIDs       []string `json:"direct_person_ids,omitempty"`
	AddedPersonIDs        []string `json:"added_person_ids,omitempty"`
	RemovedPersonIDs      []string `json:"removed_person_ids,omitempty"`
	ChangedFields         []string `json:"changed_fields,omitempty"`
	VersionHistoryEntries int      `json:"version_history_entries"`
	SourceSystem          string   `json:"source_system"`
	SourceEventID         string   `json:"source_event_id"`
}

// UpdateOrganizationalPolicyDirectPersonAssignments updates only the direct
// person assignments for an existing policy while preserving department scope.
func UpdateOrganizationalPolicyDirectPersonAssignments(g *Graph, req OrganizationalPolicyDirectPersonAssignmentRequest) (OrganizationalPolicyDirectPersonAssignmentResult, error) {
	if g == nil {
		return OrganizationalPolicyDirectPersonAssignmentResult{}, fmt.Errorf("graph is required")
	}

	policyID := strings.TrimSpace(req.PolicyID)
	if policyID == "" {
		return OrganizationalPolicyDirectPersonAssignmentResult{}, fmt.Errorf("policy_id is required")
	}

	policy, ok := g.GetNode(policyID)
	if !ok || policy == nil || policy.Kind != NodeKindPolicy {
		return OrganizationalPolicyDirectPersonAssignmentResult{}, fmt.Errorf("policy not found: %s", policyID)
	}

	addPersonIDs, err := validatePolicyTargets(g, req.AddPersonIDs, NodeKindPerson)
	if err != nil {
		return OrganizationalPolicyDirectPersonAssignmentResult{}, err
	}
	removePersonIDs, err := validatePolicyTargets(g, req.RemovePersonIDs, NodeKindPerson)
	if err != nil {
		return OrganizationalPolicyDirectPersonAssignmentResult{}, err
	}
	if overlap := overlappingPolicyStrings(addPersonIDs, removePersonIDs); len(overlap) > 0 {
		return OrganizationalPolicyDirectPersonAssignmentResult{}, fmt.Errorf("person ids cannot be added and removed in the same update: %s", strings.Join(overlap, ", "))
	}

	current := organizationalPolicyVersionStateFromGraph(policy, g)
	nextPersonIDs, addedPersonIDs, removedPersonIDs := updatePolicyAssignmentSet(current.RequiredPersonIDs, addPersonIDs, removePersonIDs)
	metadata := NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, WriteMetadataDefaults{
		RecordedAt:        req.RecordedAt,
		TransactionFrom:   req.TransactionFrom,
		TransactionTo:     req.TransactionTo,
		SourceSystem:      "policy_assignment",
		SourceEventPrefix: "organizational-policy-assignment",
		DefaultConfidence: 0.95,
	})
	historyEntries, changedFields := updateExistingOrganizationalPolicyAssignments(g, policy, current.RequiredDepartmentIDs, nextPersonIDs, metadata, req.Metadata)

	return OrganizationalPolicyDirectPersonAssignmentResult{
		PolicyID:              policyID,
		PolicyVersion:         current.PolicyVersion,
		DirectPersonIDs:       nextPersonIDs,
		AddedPersonIDs:        addedPersonIDs,
		RemovedPersonIDs:      removedPersonIDs,
		ChangedFields:         changedFields,
		VersionHistoryEntries: len(historyEntries),
		SourceSystem:          metadata.SourceSystem,
		SourceEventID:         metadata.SourceEventID,
	}, nil
}

func updateExistingOrganizationalPolicyAssignments(g *Graph, policy *Node, nextDepartmentIDs, nextPersonIDs []string, metadata WriteMetadata, requestMetadata map[string]any) ([]OrganizationalPolicyVersionHistoryEntry, []string) {
	if g == nil || policy == nil {
		return nil, nil
	}

	current := organizationalPolicyVersionStateFromGraph(policy, g)
	properties := cloneAnyMap(policy.Properties)
	if properties == nil {
		properties = make(map[string]any)
	}
	for key, value := range requestMetadata {
		properties[key] = value
	}
	properties["policy_id"] = policy.ID
	properties["policy_version"] = current.PolicyVersion
	if title := firstNonEmpty(readString(properties, "title"), policy.Name); title != "" {
		properties["title"] = title
	}
	metadata.ApplyTo(properties)

	historyEntries, changedFields := nextOrganizationalPolicyVersionHistory(policy, g, organizationalPolicyVersionState{
		PolicyVersion:         current.PolicyVersion,
		Title:                 current.Title,
		Summary:               current.Summary,
		ContentDigest:         current.ContentDigest,
		OwnerID:               current.OwnerID,
		ReviewCycleDays:       current.ReviewCycleDays,
		FrameworkMappings:     current.FrameworkMappings,
		RequiredDepartmentIDs: nextDepartmentIDs,
		RequiredPersonIDs:     nextPersonIDs,
	}, metadata)
	if len(historyEntries) > 0 {
		properties["version_history"] = organizationalPolicyVersionHistoryProperty(historyEntries)
	}

	updated := *policy
	updated.Provider = metadata.SourceSystem
	updated.Properties = properties
	g.AddNode(&updated)

	assignmentTargets := append([]string{}, nextDepartmentIDs...)
	assignmentTargets = append(assignmentTargets, nextPersonIDs...)
	syncOrganizationalPolicyAssignments(g, policy.ID, assignmentTargets, metadata)

	return historyEntries, changedFields
}

func updatePolicyAssignmentSet(currentIDs, addIDs, removeIDs []string) ([]string, []string, []string) {
	current := make(map[string]struct{}, len(currentIDs))
	for _, targetID := range uniquePolicyStrings(currentIDs) {
		current[targetID] = struct{}{}
	}

	added := make(map[string]struct{}, len(addIDs))
	for _, targetID := range uniquePolicyStrings(addIDs) {
		if _, exists := current[targetID]; exists {
			continue
		}
		current[targetID] = struct{}{}
		added[targetID] = struct{}{}
	}

	removed := make(map[string]struct{}, len(removeIDs))
	for _, targetID := range uniquePolicyStrings(removeIDs) {
		if _, exists := current[targetID]; !exists {
			continue
		}
		delete(current, targetID)
		removed[targetID] = struct{}{}
		delete(added, targetID)
	}

	return sortedSet(current), sortedSet(added), sortedSet(removed)
}

func overlappingPolicyStrings(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	leftSet := make(map[string]struct{}, len(left))
	for _, value := range uniquePolicyStrings(left) {
		leftSet[value] = struct{}{}
	}
	overlap := make(map[string]struct{})
	for _, value := range uniquePolicyStrings(right) {
		if _, ok := leftSet[value]; ok {
			overlap[value] = struct{}{}
		}
	}
	return sortedSet(overlap)
}
