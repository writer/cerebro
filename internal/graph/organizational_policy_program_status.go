package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyProgramStatusOptions scopes program-level rollups.
type OrganizationalPolicyProgramStatusOptions struct {
	Framework string `json:"framework,omitempty"`
}

// OrganizationalPolicyProgramPolicyStatus captures current-version
// acknowledgment posture for one registered policy.
type OrganizationalPolicyProgramPolicyStatus struct {
	PolicyID           string   `json:"policy_id"`
	PolicyName         string   `json:"policy_name,omitempty"`
	PolicyVersion      string   `json:"policy_version,omitempty"`
	FrameworkMappings  []string `json:"framework_mappings,omitempty"`
	RequiredPeople     int      `json:"required_people"`
	AcknowledgedPeople int      `json:"acknowledged_people"`
	PendingPeople      int      `json:"pending_people"`
	Coverage           float64  `json:"coverage"`
	DepartmentGapIDs   []string `json:"department_gap_ids,omitempty"`
	UnscopedPending    int      `json:"unscoped_pending_people,omitempty"`
	FullyAcknowledged  bool     `json:"fully_acknowledged"`
}

// OrganizationalPolicyProgramStatusReport summarizes policy acknowledgment
// posture across the whole program.
type OrganizationalPolicyProgramStatusReport struct {
	Framework                    string                                    `json:"framework,omitempty"`
	GeneratedAt                  time.Time                                 `json:"generated_at"`
	PolicyCount                  int                                       `json:"policy_count"`
	FullyAcknowledgedPolicies    int                                       `json:"fully_acknowledged_policies"`
	TotalRequiredAcknowledgments int                                       `json:"total_required_acknowledgments"`
	TotalAcknowledged            int                                       `json:"total_acknowledged"`
	Coverage                     float64                                   `json:"coverage"`
	Policies                     []OrganizationalPolicyProgramPolicyStatus `json:"policies,omitempty"`
}

// OrganizationalPolicyProgramStatus returns a program-level rollup across all
// registered policies, optionally filtered to one framework family.
func OrganizationalPolicyProgramStatus(g *Graph, opts OrganizationalPolicyProgramStatusOptions) (*OrganizationalPolicyProgramStatusReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	framework := canonicalOrganizationalPolicyFrameworkID(opts.Framework)
	policies := append([]*Node(nil), g.GetNodesByKind(NodeKindPolicy)...)
	sort.Slice(policies, func(i, j int) bool {
		if policies[i] == nil || policies[j] == nil {
			return policies[i] != nil
		}
		return policies[i].ID < policies[j].ID
	})

	programPolicies := make([]OrganizationalPolicyProgramPolicyStatus, 0, len(policies))
	totalRequired := 0
	totalAcknowledged := 0
	fullyAcknowledged := 0

	for _, policy := range policies {
		if policy == nil {
			continue
		}
		mappings := organizationalPolicyStringSlice(policy.Properties["framework_mappings"])
		if framework != "" && !organizationalPolicyMatchesFramework(mappings, framework) {
			continue
		}

		status, err := OrganizationalPolicyAcknowledgmentStatus(g, policy.ID)
		if err != nil {
			return nil, err
		}

		departmentGapIDs := make([]string, 0, len(status.Departments))
		for _, department := range status.Departments {
			if len(department.PendingPersonIDs) > 0 {
				departmentGapIDs = append(departmentGapIDs, department.DepartmentID)
			}
		}
		sort.Strings(departmentGapIDs)

		current := OrganizationalPolicyProgramPolicyStatus{
			PolicyID:           status.PolicyID,
			PolicyName:         status.PolicyName,
			PolicyVersion:      status.PolicyVersion,
			FrameworkMappings:  mappings,
			RequiredPeople:     status.RequiredPeople,
			AcknowledgedPeople: status.AcknowledgedPeople,
			PendingPeople:      len(status.PendingPersonIDs),
			Coverage:           status.Coverage,
			DepartmentGapIDs:   departmentGapIDs,
			UnscopedPending:    len(status.UnscopedPendingPersonIDs),
			FullyAcknowledged:  len(status.PendingPersonIDs) == 0 && status.RequiredPeople > 0,
		}
		if current.FullyAcknowledged {
			fullyAcknowledged++
		}
		totalRequired += current.RequiredPeople
		totalAcknowledged += current.AcknowledgedPeople
		programPolicies = append(programPolicies, current)
	}

	return &OrganizationalPolicyProgramStatusReport{
		Framework:                    framework,
		GeneratedAt:                  time.Now().UTC(),
		PolicyCount:                  len(programPolicies),
		FullyAcknowledgedPolicies:    fullyAcknowledged,
		TotalRequiredAcknowledgments: totalRequired,
		TotalAcknowledged:            totalAcknowledged,
		Coverage:                     ratio(totalAcknowledged, totalRequired),
		Policies:                     programPolicies,
	}, nil
}

func organizationalPolicyMatchesFramework(mappings []string, framework string) bool {
	framework = canonicalOrganizationalPolicyFrameworkID(framework)
	if framework == "" {
		return true
	}
	for _, mapping := range mappings {
		current := strings.TrimSpace(mapping)
		if current == "" {
			continue
		}
		current = strings.SplitN(current, ":", 2)[0]
		if canonicalOrganizationalPolicyFrameworkID(current) == framework {
			return true
		}
	}
	return false
}
