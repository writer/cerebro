package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyReminderQueueOptions scopes the program-wide reminder
// queue to one framework family when needed.
type OrganizationalPolicyReminderQueueOptions struct {
	Framework string `json:"framework,omitempty"`
}

// OrganizationalPolicyReminderQueueItem captures one actionable reminder for a
// person-policy pair.
type OrganizationalPolicyReminderQueueItem struct {
	PolicyID            string     `json:"policy_id"`
	PolicyName          string     `json:"policy_name,omitempty"`
	PolicyVersion       string     `json:"policy_version,omitempty"`
	PersonID            string     `json:"person_id"`
	PersonName          string     `json:"person_name,omitempty"`
	Status              string     `json:"status"`
	DirectAssignment    bool       `json:"direct_assignment,omitempty"`
	DepartmentIDs       []string   `json:"department_ids,omitempty"`
	AcknowledgedVersion string     `json:"acknowledged_version,omitempty"`
	AcknowledgedAt      *time.Time `json:"acknowledged_at,omitempty"`
}

// OrganizationalPolicyReminderQueueReport summarizes all outstanding policy
// reminders across the scoped policy program.
type OrganizationalPolicyReminderQueueReport struct {
	GeneratedAt           time.Time                               `json:"generated_at"`
	Framework             string                                  `json:"framework,omitempty"`
	PolicyCount           int                                     `json:"policy_count"`
	PoliciesWithReminders int                                     `json:"policies_with_reminders"`
	ReminderCount         int                                     `json:"reminder_count"`
	PendingReminders      int                                     `json:"pending_reminders"`
	StaleReminders        int                                     `json:"stale_reminders"`
	Items                 []OrganizationalPolicyReminderQueueItem `json:"items,omitempty"`
}

// OrganizationalPolicyProgramReminderQueue returns the actionable reminder
// queue across all in-scope policies, preserving per-policy assignment context.
func OrganizationalPolicyProgramReminderQueue(g *Graph, opts OrganizationalPolicyReminderQueueOptions) (*OrganizationalPolicyReminderQueueReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	framework := canonicalOrganizationalPolicyFrameworkID(opts.Framework)
	policies := g.GetNodesByKindIndexed(NodeKindPolicy)
	items := make([]OrganizationalPolicyReminderQueueItem, 0)
	policyCount := 0
	policiesWithReminders := 0
	pendingReminders := 0
	staleReminders := 0

	for _, policy := range policies {
		if policy == nil {
			continue
		}
		if framework != "" && !organizationalPolicyNodeMatchesFramework(policy, framework) {
			continue
		}
		policyCount++

		report, err := OrganizationalPolicyAcknowledgmentReminders(g, policy.ID)
		if err != nil {
			return nil, err
		}
		if len(report.ReminderCandidates) == 0 {
			continue
		}
		policiesWithReminders++

		for _, candidate := range report.ReminderCandidates {
			switch candidate.Status {
			case OrganizationalPolicyReminderStatusPending:
				pendingReminders++
			case OrganizationalPolicyReminderStatusStale:
				staleReminders++
			}
			items = append(items, OrganizationalPolicyReminderQueueItem{
				PolicyID:            report.PolicyID,
				PolicyName:          report.PolicyName,
				PolicyVersion:       report.PolicyVersion,
				PersonID:            candidate.PersonID,
				PersonName:          candidate.PersonName,
				Status:              candidate.Status,
				DirectAssignment:    candidate.DirectAssignment,
				DepartmentIDs:       append([]string(nil), candidate.DepartmentIDs...),
				AcknowledgedVersion: candidate.AcknowledgedVersion,
				AcknowledgedAt:      cloneTimePointer(candidate.AcknowledgedAt),
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		if rank := organizationalPolicyReminderQueueStatusRank(left.Status) - organizationalPolicyReminderQueueStatusRank(right.Status); rank != 0 {
			return rank < 0
		}
		if left.PolicyID != right.PolicyID {
			return left.PolicyID < right.PolicyID
		}
		if left.PersonID != right.PersonID {
			return left.PersonID < right.PersonID
		}
		return strings.Compare(left.AcknowledgedVersion, right.AcknowledgedVersion) < 0
	})

	return &OrganizationalPolicyReminderQueueReport{
		GeneratedAt:           time.Now().UTC(),
		Framework:             framework,
		PolicyCount:           policyCount,
		PoliciesWithReminders: policiesWithReminders,
		ReminderCount:         len(items),
		PendingReminders:      pendingReminders,
		StaleReminders:        staleReminders,
		Items:                 items,
	}, nil
}

func organizationalPolicyNodeMatchesFramework(policy *Node, framework string) bool {
	if policy == nil {
		return false
	}
	framework = canonicalOrganizationalPolicyFrameworkID(framework)
	if framework == "" {
		return true
	}
	for _, current := range policyStringSlice(policy.Properties["framework_mappings"]) {
		if canonicalOrganizationalPolicyFrameworkFamily(current) == framework {
			return true
		}
	}
	return false
}

func canonicalOrganizationalPolicyFrameworkFamily(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.Index(value, ":"); idx >= 0 {
		value = value[:idx]
	}
	return canonicalOrganizationalPolicyFrameworkID(value)
}

func policyStringSlice(raw any) []string {
	switch typed := raw.(type) {
	case []string:
		return uniquePolicyStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := strings.TrimSpace(fmt.Sprint(item)); value != "" {
				values = append(values, value)
			}
		}
		return uniquePolicyStrings(values)
	default:
		return nil
	}
}

func organizationalPolicyReminderQueueStatusRank(status string) int {
	switch status {
	case OrganizationalPolicyReminderStatusStale:
		return 0
	case OrganizationalPolicyReminderStatusPending:
		return 1
	default:
		return 2
	}
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}
