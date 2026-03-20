package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyControlEvidencePolicy captures one mapped policy's
// current-version acknowledgment posture for a framework control.
type OrganizationalPolicyControlEvidencePolicy struct {
	PolicyID            string   `json:"policy_id"`
	PolicyName          string   `json:"policy_name,omitempty"`
	PolicyVersion       string   `json:"policy_version,omitempty"`
	RequiredPeople      int      `json:"required_people"`
	AcknowledgedPeople  int      `json:"acknowledged_people"`
	Coverage            float64  `json:"coverage"`
	PendingPersonIDs    []string `json:"pending_person_ids,omitempty"`
	Satisfied           bool     `json:"satisfied"`
	MatchedFrameworkIDs []string `json:"matched_framework_ids,omitempty"`
}

// OrganizationalPolicyControlEvidenceReport summarizes all policies currently
// mapped to one framework control plus their acknowledgment posture.
type OrganizationalPolicyControlEvidenceReport struct {
	FrameworkID          string                                      `json:"framework_id"`
	ControlID            string                                      `json:"control_id"`
	GeneratedAt          time.Time                                   `json:"generated_at"`
	PolicyCount          int                                         `json:"policy_count"`
	SatisfiedPolicyCount int                                         `json:"satisfied_policy_count"`
	AllPoliciesSatisfied bool                                        `json:"all_policies_satisfied"`
	Policies             []OrganizationalPolicyControlEvidencePolicy `json:"policies,omitempty"`
}

// OrganizationalPolicyControlEvidenceForControl returns current-version policy
// acknowledgment evidence for one canonical framework/control pair.
func OrganizationalPolicyControlEvidenceForControl(g *Graph, frameworkID, controlID string) (*OrganizationalPolicyControlEvidenceReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	frameworkID = canonicalOrganizationalPolicyFrameworkID(frameworkID)
	if frameworkID == "" {
		return nil, fmt.Errorf("framework_id is required")
	}
	controlID = canonicalOrganizationalPolicyControlID(controlID)
	if controlID == "" {
		return nil, fmt.Errorf("control_id is required")
	}

	policies := make([]OrganizationalPolicyControlEvidencePolicy, 0)
	satisfied := 0
	for _, policy := range g.GetNodesByKind(NodeKindPolicy) {
		matchedMappings := organizationalPolicyMatchingControlMappings(policy, frameworkID, controlID)
		if len(matchedMappings) == 0 {
			continue
		}

		status, err := OrganizationalPolicyAcknowledgmentStatus(g, policy.ID)
		if err != nil {
			return nil, err
		}

		satisfiedPolicy := len(status.PendingPersonIDs) == 0
		if satisfiedPolicy {
			satisfied++
		}
		policies = append(policies, OrganizationalPolicyControlEvidencePolicy{
			PolicyID:            policy.ID,
			PolicyName:          status.PolicyName,
			PolicyVersion:       status.PolicyVersion,
			RequiredPeople:      status.RequiredPeople,
			AcknowledgedPeople:  status.AcknowledgedPeople,
			Coverage:            status.Coverage,
			PendingPersonIDs:    append([]string(nil), status.PendingPersonIDs...),
			Satisfied:           satisfiedPolicy,
			MatchedFrameworkIDs: append([]string(nil), matchedMappings...),
		})
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].PolicyID < policies[j].PolicyID
	})

	return &OrganizationalPolicyControlEvidenceReport{
		FrameworkID:          frameworkID,
		ControlID:            controlID,
		GeneratedAt:          time.Now().UTC(),
		PolicyCount:          len(policies),
		SatisfiedPolicyCount: satisfied,
		AllPoliciesSatisfied: len(policies) > 0 && satisfied == len(policies),
		Policies:             policies,
	}, nil
}

func organizationalPolicyMatchingControlMappings(policy *Node, frameworkID, controlID string) []string {
	if policy == nil {
		return nil
	}
	mappings := organizationalPolicyStringSlice(policy.Properties["framework_mappings"])
	if len(mappings) == 0 {
		return nil
	}

	matched := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		currentFramework, currentControl, ok := organizationalPolicyFrameworkControlParts(mapping)
		if !ok {
			continue
		}
		if currentFramework != frameworkID || currentControl != controlID {
			continue
		}
		matched = append(matched, mapping)
	}
	return uniquePolicyStrings(matched)
}

func organizationalPolicyFrameworkControlParts(mapping string) (string, string, bool) {
	framework, control, ok := strings.Cut(strings.TrimSpace(mapping), ":")
	if !ok {
		return "", "", false
	}
	framework = canonicalOrganizationalPolicyFrameworkID(framework)
	control = canonicalOrganizationalPolicyControlID(control)
	if framework == "" || control == "" {
		return "", "", false
	}
	return framework, control, true
}

func canonicalOrganizationalPolicyControlID(value string) string {
	return normalizeOrgKey(value)
}
