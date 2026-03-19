package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	OrganizationalPolicyPersonStatusPending      = "pending"
	OrganizationalPolicyPersonStatusAcknowledged = "acknowledged"
	OrganizationalPolicyPersonStatusStale        = "stale"
)

// OrganizationalPolicyPersonRequirement captures one required policy for a
// person plus the current acknowledgment status for that policy.
type OrganizationalPolicyPersonRequirement struct {
	PolicyID            string     `json:"policy_id"`
	PolicyName          string     `json:"policy_name,omitempty"`
	PolicyVersion       string     `json:"policy_version"`
	Status              string     `json:"status"`
	DirectAssignment    bool       `json:"direct_assignment,omitempty"`
	DepartmentIDs       []string   `json:"department_ids,omitempty"`
	AcknowledgedVersion string     `json:"acknowledged_version,omitempty"`
	AcknowledgedAt      *time.Time `json:"acknowledged_at,omitempty"`
}

// OrganizationalPolicyPersonAcknowledgmentReport summarizes all current policy
// requirements for one person. This supports reminder and onboarding flows.
type OrganizationalPolicyPersonAcknowledgmentReport struct {
	PersonID             string                                  `json:"person_id"`
	PersonName           string                                  `json:"person_name,omitempty"`
	GeneratedAt          time.Time                               `json:"generated_at"`
	RequiredPolicies     int                                     `json:"required_policies"`
	AcknowledgedPolicies int                                     `json:"acknowledged_policies"`
	PendingPolicyIDs     []string                                `json:"pending_policy_ids,omitempty"`
	StalePolicyIDs       []string                                `json:"stale_policy_ids,omitempty"`
	Policies             []OrganizationalPolicyPersonRequirement `json:"policies,omitempty"`
}

// OrganizationalPolicyAcknowledgmentStatusForPerson computes which policies a
// person is required to acknowledge through direct assignment or department
// membership and whether the current version has been acknowledged.
func OrganizationalPolicyAcknowledgmentStatusForPerson(g *Graph, personID string) (*OrganizationalPolicyPersonAcknowledgmentReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	personID = strings.TrimSpace(personID)
	if personID == "" {
		return nil, fmt.Errorf("person_id is required")
	}

	person, ok := g.GetNode(personID)
	if !ok || person == nil || person.Kind != NodeKindPerson {
		return nil, fmt.Errorf("person not found: %s", personID)
	}

	departmentIDs := personDepartmentIDs(g, personID)
	ackByPolicy := personPolicyAcknowledgments(g, personID)

	type requirementAccumulator struct {
		policy      *Node
		direct      bool
		departments map[string]struct{}
	}

	required := make(map[string]*requirementAccumulator)
	addRequirement := func(policy *Node, direct bool, departmentID string) {
		if policy == nil || policy.Kind != NodeKindPolicy {
			return
		}
		acc := required[policy.ID]
		if acc == nil {
			acc = &requirementAccumulator{
				policy:      policy,
				departments: make(map[string]struct{}),
			}
			required[policy.ID] = acc
		}
		if direct {
			acc.direct = true
		}
		if departmentID != "" {
			acc.departments[departmentID] = struct{}{}
		}
	}

	for _, edge := range g.GetInEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo || edge.Target != personID {
			continue
		}
		policy, ok := g.GetNode(edge.Source)
		if !ok || policy == nil || policy.Kind != NodeKindPolicy {
			continue
		}
		addRequirement(policy, true, "")
	}

	for departmentID := range departmentIDs {
		for _, edge := range g.GetInEdges(departmentID) {
			if edge == nil || edge.Kind != EdgeKindAssignedTo || edge.Target != departmentID {
				continue
			}
			policy, ok := g.GetNode(edge.Source)
			if !ok || policy == nil || policy.Kind != NodeKindPolicy {
				continue
			}
			addRequirement(policy, false, departmentID)
		}
	}

	requirements := make([]OrganizationalPolicyPersonRequirement, 0, len(required))
	pendingPolicyIDs := make([]string, 0, len(required))
	stalePolicyIDs := make([]string, 0, len(required))
	acknowledgedPolicies := 0

	for policyID, acc := range required {
		policy := acc.policy
		currentVersion := currentOrganizationalPolicyVersion(policy)
		status := OrganizationalPolicyPersonStatusPending
		ackVersion := ""
		var acknowledgedAt *time.Time

		if ack := ackByPolicy[policyID]; ack != nil {
			ackVersion = strings.TrimSpace(readString(ack.Properties, "policy_version"))
			if currentVersion == "" || strings.EqualFold(ackVersion, currentVersion) {
				status = OrganizationalPolicyPersonStatusAcknowledged
				acknowledgedPolicies++
			} else {
				status = OrganizationalPolicyPersonStatusStale
			}
			if parsed := parseOrganizationalPolicyTime(readString(ack.Properties, "acknowledged_at")); !parsed.IsZero() {
				copy := parsed
				acknowledgedAt = &copy
			}
		}

		switch status {
		case OrganizationalPolicyPersonStatusPending:
			pendingPolicyIDs = append(pendingPolicyIDs, policyID)
		case OrganizationalPolicyPersonStatusStale:
			stalePolicyIDs = append(stalePolicyIDs, policyID)
		}

		requirements = append(requirements, OrganizationalPolicyPersonRequirement{
			PolicyID:            policyID,
			PolicyName:          firstNonEmpty(strings.TrimSpace(policy.Name), strings.TrimSpace(readString(policy.Properties, "title"))),
			PolicyVersion:       currentVersion,
			Status:              status,
			DirectAssignment:    acc.direct,
			DepartmentIDs:       sortedSet(acc.departments),
			AcknowledgedVersion: ackVersion,
			AcknowledgedAt:      acknowledgedAt,
		})
	}

	sort.Slice(requirements, func(i, j int) bool {
		return requirements[i].PolicyID < requirements[j].PolicyID
	})
	sort.Strings(pendingPolicyIDs)
	sort.Strings(stalePolicyIDs)

	return &OrganizationalPolicyPersonAcknowledgmentReport{
		PersonID:             personID,
		PersonName:           firstNonEmpty(strings.TrimSpace(person.Name), personID),
		GeneratedAt:          time.Now().UTC(),
		RequiredPolicies:     len(requirements),
		AcknowledgedPolicies: acknowledgedPolicies,
		PendingPolicyIDs:     pendingPolicyIDs,
		StalePolicyIDs:       stalePolicyIDs,
		Policies:             requirements,
	}, nil
}

func personDepartmentIDs(g *Graph, personID string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		department, ok := g.GetNode(edge.Target)
		if !ok || department == nil || department.Kind != NodeKindDepartment {
			continue
		}
		out[department.ID] = struct{}{}
	}
	return out
}

func personPolicyAcknowledgments(g *Graph, personID string) map[string]*Edge {
	out := make(map[string]*Edge)
	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindAcknowledged {
			continue
		}
		policy, ok := g.GetNode(edge.Target)
		if !ok || policy == nil || policy.Kind != NodeKindPolicy {
			continue
		}
		out[policy.ID] = edge
	}
	return out
}

func parseOrganizationalPolicyTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
