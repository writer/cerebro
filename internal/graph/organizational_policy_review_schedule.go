package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	OrganizationalPolicyReviewStatusCurrent = "current"
	OrganizationalPolicyReviewStatusDue     = "due"
	OrganizationalPolicyReviewStatusOverdue = "overdue"
)

// OrganizationalPolicyReviewItem captures the current review posture for one
// organizational policy.
type OrganizationalPolicyReviewItem struct {
	PolicyID        string    `json:"policy_id"`
	PolicyName      string    `json:"policy_name,omitempty"`
	PolicyVersion   string    `json:"policy_version"`
	OwnerID         string    `json:"owner_id,omitempty"`
	ReviewCycleDays int       `json:"review_cycle_days"`
	LastReviewedAt  time.Time `json:"last_reviewed_at"`
	NextReviewAt    time.Time `json:"next_review_at"`
	Status          string    `json:"status"`
	DaysUntilReview int       `json:"days_until_review"`
}

// OrganizationalPolicyReviewSchedule summarizes all policies that have an
// active review cadence configured.
type OrganizationalPolicyReviewSchedule struct {
	GeneratedAt     time.Time                        `json:"generated_at"`
	PolicyCount     int                              `json:"policy_count"`
	DuePolicies     int                              `json:"due_policies"`
	OverduePolicies int                              `json:"overdue_policies"`
	Policies        []OrganizationalPolicyReviewItem `json:"policies,omitempty"`
}

// OrganizationalPolicyReviewScheduleAt computes review due dates for all
// policy nodes with a positive review cycle.
func OrganizationalPolicyReviewScheduleAt(g *Graph, asOf time.Time) (*OrganizationalPolicyReviewSchedule, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	} else {
		asOf = asOf.UTC()
	}

	items := make([]OrganizationalPolicyReviewItem, 0)
	duePolicies := 0
	overduePolicies := 0

	for _, policy := range g.GetNodesByKindIndexed(NodeKindPolicy) {
		if policy == nil {
			continue
		}
		reviewCycleDays := readInt(policy.Properties, "review_cycle_days")
		if reviewCycleDays <= 0 {
			continue
		}

		lastReviewedAt := organizationalPolicyLastReviewedAt(g, policy)
		if lastReviewedAt.IsZero() {
			lastReviewedAt = asOf
		}
		nextReviewAt := lastReviewedAt.AddDate(0, 0, reviewCycleDays)
		status := OrganizationalPolicyReviewStatusCurrent
		daysUntilReview := wholeDaysBetween(asOf, nextReviewAt)

		switch {
		case sameCalendarDay(nextReviewAt, asOf):
			status = OrganizationalPolicyReviewStatusDue
			duePolicies++
		case nextReviewAt.Before(asOf):
			status = OrganizationalPolicyReviewStatusOverdue
			overduePolicies++
		}

		items = append(items, OrganizationalPolicyReviewItem{
			PolicyID:        policy.ID,
			PolicyName:      firstNonEmpty(strings.TrimSpace(policy.Name), strings.TrimSpace(readString(policy.Properties, "title"))),
			PolicyVersion:   currentOrganizationalPolicyVersion(policy),
			OwnerID:         strings.TrimSpace(readString(policy.Properties, "owner_id")),
			ReviewCycleDays: reviewCycleDays,
			LastReviewedAt:  lastReviewedAt,
			NextReviewAt:    nextReviewAt,
			Status:          status,
			DaysUntilReview: daysUntilReview,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if !items[i].NextReviewAt.Equal(items[j].NextReviewAt) {
			return items[i].NextReviewAt.Before(items[j].NextReviewAt)
		}
		return items[i].PolicyID < items[j].PolicyID
	})

	return &OrganizationalPolicyReviewSchedule{
		GeneratedAt:     asOf,
		PolicyCount:     len(items),
		DuePolicies:     duePolicies,
		OverduePolicies: overduePolicies,
		Policies:        items,
	}, nil
}

func organizationalPolicyLastReviewedAt(g *Graph, policy *Node) time.Time {
	if policy == nil {
		return time.Time{}
	}
	history, err := OrganizationalPolicyVersionHistory(g, policy.ID)
	if err == nil && len(history) > 0 {
		last := history[len(history)-1]
		if !last.ObservedAt.IsZero() {
			return last.ObservedAt.UTC()
		}
	}
	return organizationalPolicyTime(policy.Properties, "observed_at", "valid_from")
}

func wholeDaysBetween(asOf, target time.Time) int {
	asOf = truncateToDay(asOf)
	target = truncateToDay(target)
	return int(target.Sub(asOf).Hours() / 24)
}

func sameCalendarDay(left, right time.Time) bool {
	return truncateToDay(left).Equal(truncateToDay(right))
}

func truncateToDay(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}
