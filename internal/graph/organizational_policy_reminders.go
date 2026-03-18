package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	OrganizationalPolicyReminderStatusPending = "pending"
	OrganizationalPolicyReminderStatusStale   = "stale"
)

// OrganizationalPolicyReminderCandidate captures one person who still needs a
// reminder for the current version of a policy.
type OrganizationalPolicyReminderCandidate struct {
	PersonID            string     `json:"person_id"`
	PersonName          string     `json:"person_name,omitempty"`
	Status              string     `json:"status"`
	DirectAssignment    bool       `json:"direct_assignment,omitempty"`
	DepartmentIDs       []string   `json:"department_ids,omitempty"`
	AcknowledgedVersion string     `json:"acknowledged_version,omitempty"`
	AcknowledgedAt      *time.Time `json:"acknowledged_at,omitempty"`
}

// OrganizationalPolicyReminderReport summarizes who still needs a reminder for
// a policy's current version.
type OrganizationalPolicyReminderReport struct {
	PolicyID           string                                  `json:"policy_id"`
	PolicyName         string                                  `json:"policy_name,omitempty"`
	PolicyVersion      string                                  `json:"policy_version"`
	GeneratedAt        time.Time                               `json:"generated_at"`
	PendingPeople      int                                     `json:"pending_people"`
	StalePeople        int                                     `json:"stale_people"`
	ReminderCandidates []OrganizationalPolicyReminderCandidate `json:"reminder_candidates,omitempty"`
}

// OrganizationalPolicyAcknowledgmentReminders lists the people who still need
// reminders for the current policy version, including stale acknowledgments.
func OrganizationalPolicyAcknowledgmentReminders(g *Graph, policyID string) (*OrganizationalPolicyReminderReport, error) {
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
	requiredPeople := make(map[string]*OrganizationalPolicyReminderCandidate)
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
			candidate := reminderCandidate(requiredPeople, target)
			candidate.DirectAssignment = true
		case NodeKindDepartment:
			assignedDepartments[target.ID] = struct{}{}
			for personID := range departmentMembers[target.ID] {
				person, ok := g.GetNode(personID)
				if !ok || person == nil || person.Kind != NodeKindPerson {
					continue
				}
				candidate := reminderCandidate(requiredPeople, person)
				candidate.DepartmentIDs = sortedSet(departmentsIntersection(departmentsForPerson[personID], assignedDepartments))
			}
		}
	}

	pendingPeople := 0
	stalePeople := 0
	candidates := make([]OrganizationalPolicyReminderCandidate, 0, len(requiredPeople))
	for personID, candidate := range requiredPeople {
		ack := policyAcknowledgmentForPerson(g, personID, policyID)
		if ack == nil {
			candidate.Status = OrganizationalPolicyReminderStatusPending
			pendingPeople++
			candidates = append(candidates, *candidate)
			continue
		}

		candidate.AcknowledgedVersion = strings.TrimSpace(readString(ack.Properties, "policy_version"))
		if parsed := parseOrganizationalPolicyReminderTime(readString(ack.Properties, "acknowledged_at")); !parsed.IsZero() {
			copy := parsed
			candidate.AcknowledgedAt = &copy
		}
		if currentVersion != "" && !strings.EqualFold(candidate.AcknowledgedVersion, currentVersion) {
			candidate.Status = OrganizationalPolicyReminderStatusStale
			stalePeople++
			candidates = append(candidates, *candidate)
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].PersonID < candidates[j].PersonID
	})

	return &OrganizationalPolicyReminderReport{
		PolicyID:           policyID,
		PolicyName:         firstNonEmpty(strings.TrimSpace(policy.Name), strings.TrimSpace(readString(policy.Properties, "title"))),
		PolicyVersion:      currentVersion,
		GeneratedAt:        time.Now().UTC(),
		PendingPeople:      pendingPeople,
		StalePeople:        stalePeople,
		ReminderCandidates: candidates,
	}, nil
}

func reminderCandidate(bucket map[string]*OrganizationalPolicyReminderCandidate, person *Node) *OrganizationalPolicyReminderCandidate {
	if person == nil {
		return nil
	}
	current := bucket[person.ID]
	if current != nil {
		return current
	}
	current = &OrganizationalPolicyReminderCandidate{
		PersonID:   person.ID,
		PersonName: firstNonEmpty(strings.TrimSpace(person.Name), person.ID),
	}
	bucket[person.ID] = current
	return current
}

func departmentsIntersection(personDepartments map[string]struct{}, assignedDepartments map[string]struct{}) map[string]struct{} {
	if len(personDepartments) == 0 || len(assignedDepartments) == 0 {
		return nil
	}
	out := make(map[string]struct{})
	for departmentID := range personDepartments {
		if _, ok := assignedDepartments[departmentID]; ok {
			out[departmentID] = struct{}{}
		}
	}
	return out
}

func policyAcknowledgmentForPerson(g *Graph, personID, policyID string) *Edge {
	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindAcknowledged || edge.Target != policyID {
			continue
		}
		return edge
	}
	return nil
}

func parseOrganizationalPolicyReminderTime(raw string) time.Time {
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
