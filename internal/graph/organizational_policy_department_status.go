package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyDepartmentPolicyStatus captures one department's current
// acknowledgment posture for a policy that applies to one or more members.
type OrganizationalPolicyDepartmentPolicyStatus struct {
	PolicyID                   string   `json:"policy_id"`
	PolicyName                 string   `json:"policy_name,omitempty"`
	PolicyVersion              string   `json:"policy_version,omitempty"`
	DirectDepartmentAssignment bool     `json:"direct_department_assignment"`
	RequiredPeople             int      `json:"required_people"`
	AcknowledgedPeople         int      `json:"acknowledged_people"`
	Coverage                   float64  `json:"coverage"`
	PendingPersonIDs           []string `json:"pending_person_ids,omitempty"`
	Satisfied                  bool     `json:"satisfied"`
}

// OrganizationalPolicyDepartmentStatusReport summarizes all policies that
// currently apply to one department through direct assignment or department
// member obligations.
type OrganizationalPolicyDepartmentStatusReport struct {
	DepartmentID         string                                       `json:"department_id"`
	DepartmentName       string                                       `json:"department_name,omitempty"`
	GeneratedAt          time.Time                                    `json:"generated_at"`
	PolicyCount          int                                          `json:"policy_count"`
	SatisfiedPolicyCount int                                          `json:"satisfied_policy_count"`
	AllPoliciesSatisfied bool                                         `json:"all_policies_satisfied"`
	Policies             []OrganizationalPolicyDepartmentPolicyStatus `json:"policies,omitempty"`
}

// OrganizationalPolicyAcknowledgmentStatusForDepartment returns current-policy
// acknowledgment status for one department across all applicable policies.
func OrganizationalPolicyAcknowledgmentStatusForDepartment(g *Graph, departmentID string) (*OrganizationalPolicyDepartmentStatusReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	departmentID = strings.TrimSpace(departmentID)
	if departmentID == "" {
		return nil, fmt.Errorf("department_id is required")
	}

	department, ok := g.GetNode(departmentID)
	if !ok || department == nil || department.Kind != NodeKindDepartment {
		return nil, fmt.Errorf("department not found: %s", departmentID)
	}

	policies := make([]OrganizationalPolicyDepartmentPolicyStatus, 0)
	satisfied := 0
	for _, policy := range g.GetNodesByKind(NodeKindPolicy) {
		status, err := OrganizationalPolicyAcknowledgmentStatus(g, policy.ID)
		if err != nil {
			return nil, err
		}

		rollup, ok := organizationalPolicyDepartmentRollup(status, departmentID)
		if !ok {
			continue
		}

		current := OrganizationalPolicyDepartmentPolicyStatus{
			PolicyID:                   status.PolicyID,
			PolicyName:                 status.PolicyName,
			PolicyVersion:              status.PolicyVersion,
			DirectDepartmentAssignment: policyAssignedToDepartment(g, status.PolicyID, departmentID),
			RequiredPeople:             rollup.RequiredPeople,
			AcknowledgedPeople:         rollup.AcknowledgedPeople,
			Coverage:                   rollup.Coverage,
			PendingPersonIDs:           append([]string(nil), rollup.PendingPersonIDs...),
			Satisfied:                  len(rollup.PendingPersonIDs) == 0,
		}
		if current.Satisfied {
			satisfied++
		}
		policies = append(policies, current)
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].PolicyID < policies[j].PolicyID
	})

	return &OrganizationalPolicyDepartmentStatusReport{
		DepartmentID:         departmentID,
		DepartmentName:       firstNonEmpty(strings.TrimSpace(department.Name), departmentID),
		GeneratedAt:          time.Now().UTC(),
		PolicyCount:          len(policies),
		SatisfiedPolicyCount: satisfied,
		AllPoliciesSatisfied: len(policies) > 0 && satisfied == len(policies),
		Policies:             policies,
	}, nil
}

func organizationalPolicyDepartmentRollup(status *OrganizationalPolicyAcknowledgmentReport, departmentID string) (OrganizationalPolicyDepartmentRollup, bool) {
	if status == nil {
		return OrganizationalPolicyDepartmentRollup{}, false
	}
	for _, department := range status.Departments {
		if department.DepartmentID == departmentID {
			return department, true
		}
	}
	return OrganizationalPolicyDepartmentRollup{}, false
}

func policyAssignedToDepartment(g *Graph, policyID, departmentID string) bool {
	if g == nil {
		return false
	}
	for _, edge := range g.GetOutEdges(policyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo || edge.Target != departmentID {
			continue
		}
		return true
	}
	return false
}
