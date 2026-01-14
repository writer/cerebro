package graph

import (
	"time"

	"github.com/google/uuid"
)

// AccessReview represents a periodic review of access rights
type AccessReview struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Status      ReviewStatus        `json:"status"`
	Scope       ReviewScope         `json:"scope"`
	Items       []*AccessReviewItem `json:"items"`
	CreatedAt   time.Time           `json:"created_at"`
	StartedAt   *time.Time          `json:"started_at,omitempty"`
	CompletedAt *time.Time          `json:"completed_at,omitempty"`
	DueDate     *time.Time          `json:"due_date,omitempty"`
	CreatedBy   string              `json:"created_by"`
	Stats       ReviewStats         `json:"stats"`
}

// ReviewStatus represents the status of an access review
type ReviewStatus string

const (
	ReviewStatusPending    ReviewStatus = "pending"
	ReviewStatusInProgress ReviewStatus = "in_progress"
	ReviewStatusCompleted  ReviewStatus = "completed"
	ReviewStatusCanceled   ReviewStatus = "canceled"
)

// ReviewScope defines what should be reviewed
type ReviewScope struct {
	Type       ScopeType `json:"type"`
	AccountIDs []string  `json:"account_ids,omitempty"`
	Principals []string  `json:"principals,omitempty"`
	Resources  []string  `json:"resources,omitempty"`
	RiskLevels []string  `json:"risk_levels,omitempty"`
}

// ScopeType defines the type of review scope
type ScopeType string

const (
	ScopeTypeAll            ScopeType = "all"
	ScopeTypeAccount        ScopeType = "account"
	ScopeTypePrincipal      ScopeType = "principal"
	ScopeTypeResource       ScopeType = "resource"
	ScopeTypeHighRisk       ScopeType = "high_risk"
	ScopeTypeCrossAccount   ScopeType = "cross_account"
	ScopeTypePrivilegeCreep ScopeType = "privilege_creep"
)

// AccessReviewItem represents a single access relationship to review
type AccessReviewItem struct {
	ID            string          `json:"id"`
	ReviewID      string          `json:"review_id"`
	PrincipalID   string          `json:"principal_id"`
	PrincipalName string          `json:"principal_name"`
	ResourceID    string          `json:"resource_id"`
	ResourceName  string          `json:"resource_name"`
	AccessType    EdgeKind        `json:"access_type"`
	RiskLevel     RiskLevel       `json:"risk_level"`
	Path          []string        `json:"path,omitempty"`
	Decision      *ReviewDecision `json:"decision,omitempty"`
	Flags         []string        `json:"flags,omitempty"`
}

// ReviewDecision represents a decision on a review item
type ReviewDecision struct {
	Action    DecisionAction `json:"action"`
	DecidedBy string         `json:"decided_by"`
	DecidedAt time.Time      `json:"decided_at"`
	Reason    string         `json:"reason,omitempty"`
	TicketID  string         `json:"ticket_id,omitempty"`
}

// DecisionAction represents the action taken on a review item
type DecisionAction string

const (
	DecisionApprove  DecisionAction = "approve"
	DecisionRevoke   DecisionAction = "revoke"
	DecisionModify   DecisionAction = "modify"
	DecisionEscalate DecisionAction = "escalate"
	DecisionSkip     DecisionAction = "skip"
)

// ReviewStats contains statistics about a review
type ReviewStats struct {
	TotalItems    int `json:"total_items"`
	Reviewed      int `json:"reviewed"`
	Approved      int `json:"approved"`
	Revoked       int `json:"revoked"`
	Modified      int `json:"modified"`
	Escalated     int `json:"escalated"`
	Skipped       int `json:"skipped"`
	HighRiskItems int `json:"high_risk_items"`
}

// CreateAccessReview creates a new access review from the graph
func CreateAccessReview(g *Graph, name string, scope ReviewScope, createdBy string) *AccessReview {
	review := &AccessReview{
		ID:        uuid.New().String(),
		Name:      name,
		Status:    ReviewStatusPending,
		Scope:     scope,
		CreatedAt: time.Now(),
		CreatedBy: createdBy,
	}

	// Generate review items based on scope
	items := generateReviewItems(g, scope)
	review.Items = items
	review.Stats.TotalItems = len(items)

	// Count high risk items
	for _, item := range items {
		if item.RiskLevel == RiskCritical || item.RiskLevel == RiskHigh {
			review.Stats.HighRiskItems++
		}
	}

	return review
}

func generateReviewItems(g *Graph, scope ReviewScope) []*AccessReviewItem {
	var items []*AccessReviewItem

	switch scope.Type {
	case ScopeTypeAll:
		items = generateAllAccessItems(g)
	case ScopeTypeAccount:
		items = generateAccountAccessItems(g, scope.AccountIDs)
	case ScopeTypePrincipal:
		items = generatePrincipalAccessItems(g, scope.Principals)
	case ScopeTypeResource:
		items = generateResourceAccessItems(g, scope.Resources)
	case ScopeTypeHighRisk:
		items = generateHighRiskItems(g)
	case ScopeTypeCrossAccount:
		items = generateCrossAccountItems(g)
	case ScopeTypePrivilegeCreep:
		items = generatePrivilegeCreepItems(g)
	}

	return items
}

func generateAllAccessItems(g *Graph) []*AccessReviewItem {
	var items []*AccessReviewItem
	seen := make(map[string]bool)

	for _, node := range g.GetAllNodes() {
		if !node.IsIdentity() {
			continue
		}

		result := BlastRadius(g, node.ID, 3)
		for _, rn := range result.ReachableNodes {
			key := node.ID + "->" + rn.Node.ID
			if seen[key] {
				continue
			}
			seen[key] = true

			items = append(items, &AccessReviewItem{
				ID:            uuid.New().String(),
				PrincipalID:   node.ID,
				PrincipalName: node.Name,
				ResourceID:    rn.Node.ID,
				ResourceName:  rn.Node.Name,
				AccessType:    rn.EdgeKind,
				RiskLevel:     rn.Node.Risk,
				Path:          rn.Path,
			})
		}
	}

	return items
}

func generateAccountAccessItems(g *Graph, accountIDs []string) []*AccessReviewItem {
	accountSet := make(map[string]bool)
	for _, id := range accountIDs {
		accountSet[id] = true
	}

	var items []*AccessReviewItem
	seen := make(map[string]bool)

	for _, node := range g.GetAllNodes() {
		if !node.IsIdentity() || !accountSet[node.Account] {
			continue
		}

		result := BlastRadius(g, node.ID, 3)
		for _, rn := range result.ReachableNodes {
			key := node.ID + "->" + rn.Node.ID
			if seen[key] {
				continue
			}
			seen[key] = true

			items = append(items, &AccessReviewItem{
				ID:            uuid.New().String(),
				PrincipalID:   node.ID,
				PrincipalName: node.Name,
				ResourceID:    rn.Node.ID,
				ResourceName:  rn.Node.Name,
				AccessType:    rn.EdgeKind,
				RiskLevel:     rn.Node.Risk,
				Path:          rn.Path,
			})
		}
	}

	return items
}

func generatePrincipalAccessItems(g *Graph, principals []string) []*AccessReviewItem {
	var items []*AccessReviewItem

	for _, pid := range principals {
		node, ok := g.GetNode(pid)
		if !ok {
			continue
		}

		result := BlastRadius(g, pid, 3)
		for _, rn := range result.ReachableNodes {
			items = append(items, &AccessReviewItem{
				ID:            uuid.New().String(),
				PrincipalID:   pid,
				PrincipalName: node.Name,
				ResourceID:    rn.Node.ID,
				ResourceName:  rn.Node.Name,
				AccessType:    rn.EdgeKind,
				RiskLevel:     rn.Node.Risk,
				Path:          rn.Path,
			})
		}
	}

	return items
}

func generateResourceAccessItems(g *Graph, resources []string) []*AccessReviewItem {
	var items []*AccessReviewItem

	for _, rid := range resources {
		resource, ok := g.GetNode(rid)
		if !ok {
			continue
		}

		result := ReverseAccess(g, rid, 3)
		for _, acc := range result.AccessibleBy {
			items = append(items, &AccessReviewItem{
				ID:            uuid.New().String(),
				PrincipalID:   acc.Node.ID,
				PrincipalName: acc.Node.Name,
				ResourceID:    rid,
				ResourceName:  resource.Name,
				AccessType:    acc.EdgeKind,
				RiskLevel:     resource.Risk,
				Path:          acc.Path,
			})
		}
	}

	return items
}

func generateHighRiskItems(g *Graph) []*AccessReviewItem {
	var items []*AccessReviewItem
	seen := make(map[string]bool)

	// Find all high-risk resources
	for _, node := range g.GetAllNodes() {
		if !node.IsResource() {
			continue
		}
		if node.Risk != RiskCritical && node.Risk != RiskHigh {
			continue
		}

		result := ReverseAccess(g, node.ID, 3)
		for _, acc := range result.AccessibleBy {
			key := acc.Node.ID + "->" + node.ID
			if seen[key] {
				continue
			}
			seen[key] = true

			flags := []string{"high_risk_resource"}
			if node.Risk == RiskCritical {
				flags = append(flags, "critical")
			}

			items = append(items, &AccessReviewItem{
				ID:            uuid.New().String(),
				PrincipalID:   acc.Node.ID,
				PrincipalName: acc.Node.Name,
				ResourceID:    node.ID,
				ResourceName:  node.Name,
				AccessType:    acc.EdgeKind,
				RiskLevel:     node.Risk,
				Path:          acc.Path,
				Flags:         flags,
			})
		}
	}

	return items
}

func generateCrossAccountItems(g *Graph) []*AccessReviewItem {
	edges := g.GetCrossAccountEdges()
	items := make([]*AccessReviewItem, 0, len(edges))

	for _, edge := range edges {
		sourceNode, _ := g.GetNode(edge.Source)
		targetNode, _ := g.GetNode(edge.Target)

		if sourceNode == nil || targetNode == nil {
			continue
		}

		riskLevel := RiskMedium
		if targetNode.Risk == RiskCritical || targetNode.Risk == RiskHigh {
			riskLevel = targetNode.Risk
		}

		items = append(items, &AccessReviewItem{
			ID:            uuid.New().String(),
			PrincipalID:   edge.Source,
			PrincipalName: sourceNode.Name,
			ResourceID:    edge.Target,
			ResourceName:  targetNode.Name,
			AccessType:    edge.Kind,
			RiskLevel:     riskLevel,
			Path:          []string{edge.Source, edge.Target},
			Flags:         []string{"cross_account"},
		})
	}

	return items
}

func generatePrivilegeCreepItems(g *Graph) []*AccessReviewItem {
	var items []*AccessReviewItem

	creepCases := FindPrivilegeCreep(g, 1.5)
	for _, outlier := range creepCases {
		node, _ := g.GetNode(outlier.PrincipalID)
		if node == nil {
			continue
		}

		result := BlastRadius(g, outlier.PrincipalID, 3)
		for _, rn := range result.ReachableNodes {
			items = append(items, &AccessReviewItem{
				ID:            uuid.New().String(),
				PrincipalID:   outlier.PrincipalID,
				PrincipalName: node.Name,
				ResourceID:    rn.Node.ID,
				ResourceName:  rn.Node.Name,
				AccessType:    rn.EdgeKind,
				RiskLevel:     rn.Node.Risk,
				Path:          rn.Path,
				Flags:         []string{"privilege_creep"},
			})
		}
	}

	return items
}

// RecordDecision records a decision on a review item
func (r *AccessReview) RecordDecision(itemID string, decision ReviewDecision) bool {
	for _, item := range r.Items {
		if item.ID == itemID {
			item.Decision = &decision
			r.updateStats()
			return true
		}
	}
	return false
}

func (r *AccessReview) updateStats() {
	r.Stats.Reviewed = 0
	r.Stats.Approved = 0
	r.Stats.Revoked = 0
	r.Stats.Modified = 0
	r.Stats.Escalated = 0
	r.Stats.Skipped = 0

	for _, item := range r.Items {
		if item.Decision == nil {
			continue
		}
		r.Stats.Reviewed++
		switch item.Decision.Action {
		case DecisionApprove:
			r.Stats.Approved++
		case DecisionRevoke:
			r.Stats.Revoked++
		case DecisionModify:
			r.Stats.Modified++
		case DecisionEscalate:
			r.Stats.Escalated++
		case DecisionSkip:
			r.Stats.Skipped++
		}
	}
}

// Start marks the review as in progress
func (r *AccessReview) Start() {
	now := time.Now()
	r.StartedAt = &now
	r.Status = ReviewStatusInProgress
}

// Complete marks the review as completed
func (r *AccessReview) Complete() {
	now := time.Now()
	r.CompletedAt = &now
	r.Status = ReviewStatusCompleted
}

// Cancel marks the review as canceled
func (r *AccessReview) Cancel() {
	r.Status = ReviewStatusCanceled
}

// Progress returns the completion percentage
func (r *AccessReview) Progress() float64 {
	if r.Stats.TotalItems == 0 {
		return 100.0
	}
	return float64(r.Stats.Reviewed) / float64(r.Stats.TotalItems) * 100.0
}

// PendingItems returns items that haven't been reviewed yet
func (r *AccessReview) PendingItems() []*AccessReviewItem {
	var pending []*AccessReviewItem
	for _, item := range r.Items {
		if item.Decision == nil {
			pending = append(pending, item)
		}
	}
	return pending
}

// ItemsByRisk returns items grouped by risk level
func (r *AccessReview) ItemsByRisk() map[RiskLevel][]*AccessReviewItem {
	result := make(map[RiskLevel][]*AccessReviewItem)
	for _, item := range r.Items {
		result[item.RiskLevel] = append(result[item.RiskLevel], item)
	}
	return result
}
