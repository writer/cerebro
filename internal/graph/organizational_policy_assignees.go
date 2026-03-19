package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	OrganizationalPolicyAssigneeStatusAcknowledged = "acknowledged"
	OrganizationalPolicyAssigneeStatusPending      = "pending"
	OrganizationalPolicyAssigneeStatusStale        = "stale"
)

// OrganizationalPolicyAssignee captures one person currently assigned to a policy.
type OrganizationalPolicyAssignee struct {
	PersonID            string     `json:"person_id"`
	PersonName          string     `json:"person_name,omitempty"`
	Status              string     `json:"status"`
	DirectAssignment    bool       `json:"direct_assignment,omitempty"`
	DepartmentIDs       []string   `json:"department_ids,omitempty"`
	AcknowledgedVersion string     `json:"acknowledged_version,omitempty"`
	AcknowledgedAt      *time.Time `json:"acknowledged_at,omitempty"`
}

// OrganizationalPolicyAssigneeRosterReport summarizes the current assignee
// roster for one policy version.
type OrganizationalPolicyAssigneeRosterReport struct {
	PolicyID           string                         `json:"policy_id"`
	PolicyName         string                         `json:"policy_name,omitempty"`
	PolicyVersion      string                         `json:"policy_version"`
	GeneratedAt        time.Time                      `json:"generated_at"`
	RequiredPeople     int                            `json:"required_people"`
	AcknowledgedPeople int                            `json:"acknowledged_people"`
	PendingPeople      int                            `json:"pending_people"`
	StalePeople        int                            `json:"stale_people"`
	Assignees          []OrganizationalPolicyAssignee `json:"assignees,omitempty"`
}

// OrganizationalPolicyAssigneeRoster returns the current assignee roster for one
// policy, including assignment provenance and acknowledgement state.
func OrganizationalPolicyAssigneeRoster(g *Graph, policyID string) (*OrganizationalPolicyAssigneeRosterReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("policy_id is required")
	}

	policy, ok := g.GetNode(policyID)
	if !ok || policy == nil || policy.Kind != NodeKindPolicy {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	currentVersion := currentOrganizationalPolicyVersion(policy)
	departmentMembers, _ := departmentMembersByID(g)
	departmentsForPerson := departmentsByPerson(g)
	requiredPeople := make(map[string]*OrganizationalPolicyAssignee)
	assignedDepartments := make(map[string]struct{})

	for _, edge := range g.GetOutEdges(policyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil {
			continue
		}
		switch target.Kind {
		case NodeKindPerson:
			assignee := policyAssignee(requiredPeople, target)
			assignee.DirectAssignment = true
		case NodeKindDepartment:
			assignedDepartments[target.ID] = struct{}{}
			for personID := range departmentMembers[target.ID] {
				person, ok := g.GetNode(personID)
				if !ok || person == nil || person.Kind != NodeKindPerson {
					continue
				}
				assignee := policyAssignee(requiredPeople, person)
				assignee.DepartmentIDs = sortedSet(departmentsIntersection(departmentsForPerson[personID], assignedDepartments))
			}
		}
	}

	acknowledgedPeople := 0
	pendingPeople := 0
	stalePeople := 0
	assignees := make([]OrganizationalPolicyAssignee, 0, len(requiredPeople))
	for personID, assignee := range requiredPeople {
		ack := policyAcknowledgmentForPerson(g, personID, policyID)
		if ack == nil {
			assignee.Status = OrganizationalPolicyAssigneeStatusPending
			pendingPeople++
			assignees = append(assignees, *assignee)
			continue
		}

		assignee.AcknowledgedVersion = strings.TrimSpace(readString(ack.Properties, "policy_version"))
		if parsed := parseOrganizationalPolicyReminderTime(readString(ack.Properties, "acknowledged_at")); !parsed.IsZero() {
			copy := parsed
			assignee.AcknowledgedAt = &copy
		}
		if currentVersion != "" && !strings.EqualFold(assignee.AcknowledgedVersion, currentVersion) {
			assignee.Status = OrganizationalPolicyAssigneeStatusStale
			stalePeople++
		} else {
			assignee.Status = OrganizationalPolicyAssigneeStatusAcknowledged
			acknowledgedPeople++
		}
		assignees = append(assignees, *assignee)
	}

	sort.Slice(assignees, func(i, j int) bool {
		return assignees[i].PersonID < assignees[j].PersonID
	})

	return &OrganizationalPolicyAssigneeRosterReport{
		PolicyID:           policyID,
		PolicyName:         firstNonEmpty(strings.TrimSpace(policy.Name), strings.TrimSpace(readString(policy.Properties, "title"))),
		PolicyVersion:      currentVersion,
		GeneratedAt:        time.Now().UTC(),
		RequiredPeople:     len(assignees),
		AcknowledgedPeople: acknowledgedPeople,
		PendingPeople:      pendingPeople,
		StalePeople:        stalePeople,
		Assignees:          assignees,
	}, nil
}

func policyAssignee(bucket map[string]*OrganizationalPolicyAssignee, person *Node) *OrganizationalPolicyAssignee {
	if person == nil {
		return nil
	}
	current := bucket[person.ID]
	if current != nil {
		return current
	}
	current = &OrganizationalPolicyAssignee{
		PersonID:   person.ID,
		PersonName: firstNonEmpty(strings.TrimSpace(person.Name), person.ID),
	}
	bucket[person.ID] = current
	return current
}
