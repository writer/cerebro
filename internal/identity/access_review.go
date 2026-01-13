package identity

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AccessReview represents a periodic review of user access
type AccessReview struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Type        ReviewType      `json:"type"`
	Status      ReviewStatus    `json:"status"`
	Scope       ReviewScope     `json:"scope"`
	Schedule    *ReviewSchedule `json:"schedule,omitempty"`
	Reviewers   []string        `json:"reviewers"`
	Items       []ReviewItem    `json:"items"`
	Stats       ReviewStats     `json:"stats"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	DueAt       *time.Time      `json:"due_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

type ReviewType string

const (
	ReviewTypeUserAccess     ReviewType = "user_access"
	ReviewTypeServiceAccount ReviewType = "service_account"
	ReviewTypePrivileged     ReviewType = "privileged"
	ReviewTypeEntitlement    ReviewType = "entitlement"
	ReviewTypeApplication    ReviewType = "application"
)

type ReviewStatus string

const (
	ReviewStatusDraft      ReviewStatus = "draft"
	ReviewStatusScheduled  ReviewStatus = "scheduled"
	ReviewStatusInProgress ReviewStatus = "in_progress"
	ReviewStatusCompleted  ReviewStatus = "completed"
	ReviewStatusCanceled   ReviewStatus = "canceled"
)

type ReviewScope struct {
	Providers    []string `json:"providers,omitempty"`    // aws, gcp, azure
	Accounts     []string `json:"accounts,omitempty"`     // specific accounts
	Applications []string `json:"applications,omitempty"` // specific apps
	Roles        []string `json:"roles,omitempty"`        // specific roles
	Users        []string `json:"users,omitempty"`        // specific users
}

type ReviewSchedule struct {
	Frequency string     `json:"frequency"` // daily, weekly, monthly, quarterly
	NextRun   time.Time  `json:"next_run"`
	LastRun   *time.Time `json:"last_run,omitempty"`
}

type ReviewItem struct {
	ID          string                 `json:"id"`
	ReviewID    string                 `json:"review_id"`
	Type        string                 `json:"type"` // user, service_account, role_binding
	Principal   Principal              `json:"principal"`
	Access      []AccessGrant          `json:"access"`
	RiskScore   int                    `json:"risk_score"`
	RiskFactors []string               `json:"risk_factors,omitempty"`
	Decision    *ReviewDecision        `json:"decision,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type Principal struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"` // user, service_account, group
	Name      string     `json:"name"`
	Email     string     `json:"email,omitempty"`
	Provider  string     `json:"provider"`
	Account   string     `json:"account"`
	LastLogin *time.Time `json:"last_login,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type AccessGrant struct {
	ID           string     `json:"id"`
	Resource     string     `json:"resource"`
	ResourceType string     `json:"resource_type"`
	Permission   string     `json:"permission"`
	Role         string     `json:"role,omitempty"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	GrantedBy    string     `json:"granted_by,omitempty"`
}

type ReviewDecision struct {
	Action      DecisionAction `json:"action"`
	Reviewer    string         `json:"reviewer"`
	Comment     string         `json:"comment,omitempty"`
	DecidedAt   time.Time      `json:"decided_at"`
	EffectiveAt *time.Time     `json:"effective_at,omitempty"`
}

type DecisionAction string

const (
	DecisionApprove  DecisionAction = "approve"
	DecisionRevoke   DecisionAction = "revoke"
	DecisionModify   DecisionAction = "modify"
	DecisionEscalate DecisionAction = "escalate"
	DecisionDefer    DecisionAction = "defer"
)

type ReviewStats struct {
	TotalItems    int `json:"total_items"`
	Pending       int `json:"pending"`
	Approved      int `json:"approved"`
	Revoked       int `json:"revoked"`
	Escalated     int `json:"escalated"`
	HighRisk      int `json:"high_risk"`
	CompletionPct int `json:"completion_pct"`
}

// Service manages access reviews
type Service struct {
	reviews map[string]*AccessReview
	items   map[string]*ReviewItem
	mu      sync.RWMutex
}

func NewService() *Service {
	return &Service{
		reviews: make(map[string]*AccessReview),
		items:   make(map[string]*ReviewItem),
	}
}

func (s *Service) CreateReview(ctx context.Context, review *AccessReview) (*AccessReview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	review.ID = uuid.New().String()
	review.Status = ReviewStatusDraft
	review.CreatedAt = time.Now()
	review.Stats = ReviewStats{}

	s.reviews[review.ID] = review
	return review, nil
}

func (s *Service) GetReview(ctx context.Context, id string) (*AccessReview, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reviews[id]
	return r, ok
}

func (s *Service) ListReviews(ctx context.Context, status ReviewStatus) []*AccessReview {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*AccessReview
	for _, r := range s.reviews {
		if status == "" || r.Status == status {
			result = append(result, r)
		}
	}
	return result
}

func (s *Service) StartReview(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	review, ok := s.reviews[id]
	if !ok {
		return nil
	}

	now := time.Now()
	review.Status = ReviewStatusInProgress
	review.StartedAt = &now

	return nil
}

func (s *Service) AddReviewItem(ctx context.Context, reviewID string, item *ReviewItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	review, ok := s.reviews[reviewID]
	if !ok {
		return nil
	}

	item.ID = uuid.New().String()
	item.ReviewID = reviewID
	review.Items = append(review.Items, *item)
	review.Stats.TotalItems++
	review.Stats.Pending++

	if item.RiskScore >= 80 {
		review.Stats.HighRisk++
	}

	s.items[item.ID] = item
	return nil
}

func (s *Service) RecordDecision(ctx context.Context, itemID string, decision *ReviewDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return nil
	}

	item.Decision = decision

	// Update review stats
	review, ok := s.reviews[item.ReviewID]
	if ok {
		review.Stats.Pending--
		switch decision.Action {
		case DecisionApprove:
			review.Stats.Approved++
		case DecisionRevoke:
			review.Stats.Revoked++
		case DecisionEscalate:
			review.Stats.Escalated++
		}

		completed := review.Stats.TotalItems - review.Stats.Pending
		review.Stats.CompletionPct = (completed * 100) / review.Stats.TotalItems

		// Check if review is complete
		if review.Stats.Pending == 0 {
			now := time.Now()
			review.Status = ReviewStatusCompleted
			review.CompletedAt = &now
		}
	}

	return nil
}

func (s *Service) GetPendingItems(ctx context.Context, reviewerID string) []*ReviewItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var pending []*ReviewItem
	for _, item := range s.items {
		if item.Decision == nil {
			pending = append(pending, item)
		}
	}
	return pending
}

// RiskCalculator computes risk scores for review items
type RiskCalculator struct {
	weights map[string]int
}

func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{
		weights: map[string]int{
			"admin_access":       30,
			"no_mfa":             20,
			"no_recent_login":    15,
			"service_account":    10,
			"cross_account":      10,
			"sensitive_resource": 15,
			"long_standing":      10,
			"no_justification":   10,
		},
	}
}

func (rc *RiskCalculator) Calculate(item *ReviewItem) (int, []string) {
	score := 0
	var factors []string

	// Check for admin/privileged access
	for _, grant := range item.Access {
		if grant.Role == "admin" || grant.Role == "owner" || grant.Permission == "*" {
			score += rc.weights["admin_access"]
			factors = append(factors, "Has admin/owner access")
			break
		}
	}

	// Check for service accounts
	if item.Principal.Type == "service_account" {
		score += rc.weights["service_account"]
		factors = append(factors, "Service account")
	}

	// Check for no recent login
	if item.Principal.LastLogin != nil {
		if time.Since(*item.Principal.LastLogin) > 90*24*time.Hour {
			score += rc.weights["no_recent_login"]
			factors = append(factors, "No login in 90+ days")
		}
	}

	// Check for long-standing access
	for _, grant := range item.Access {
		if time.Since(grant.GrantedAt) > 365*24*time.Hour {
			score += rc.weights["long_standing"]
			factors = append(factors, "Access granted over 1 year ago")
			break
		}
	}

	if score > 100 {
		score = 100
	}

	return score, factors
}
