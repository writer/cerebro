package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/graph"
)

// AccessReview represents a periodic graph-powered review of access rights.
type AccessReview struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description,omitempty"`
	Type             ReviewType      `json:"type"`
	Status           ReviewStatus    `json:"status"`
	Scope            ReviewScope     `json:"scope"`
	Schedule         *ReviewSchedule `json:"schedule,omitempty"`
	Reviewers        []string        `json:"reviewers,omitempty"`
	Items            []ReviewItem    `json:"items"`
	Stats            ReviewStats     `json:"stats"`
	CreatedBy        string          `json:"created_by"`
	CreatedAt        time.Time       `json:"created_at"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	DueAt            *time.Time      `json:"due_at,omitempty"`
	CompletedAt      *time.Time      `json:"completed_at,omitempty"`
	GenerationSource string          `json:"generation_source,omitempty"`
	Events           []ReviewEvent   `json:"events,omitempty"`
	Metadata         map[string]any  `json:"metadata,omitempty"`
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
	Mode         ReviewScopeMode `json:"mode,omitempty"`
	Providers    []string        `json:"providers,omitempty"`
	Accounts     []string        `json:"accounts,omitempty"`
	Applications []string        `json:"applications,omitempty"`
	Roles        []string        `json:"roles,omitempty"`
	Users        []string        `json:"users,omitempty"`
	Resources    []string        `json:"resources,omitempty"`
	RiskLevels   []string        `json:"risk_levels,omitempty"`
}

type ReviewScopeMode string

const (
	ReviewScopeModeAll            ReviewScopeMode = "all"
	ReviewScopeModeAccount        ReviewScopeMode = "account"
	ReviewScopeModePrincipal      ReviewScopeMode = "principal"
	ReviewScopeModeResource       ReviewScopeMode = "resource"
	ReviewScopeModeHighRisk       ReviewScopeMode = "high_risk"
	ReviewScopeModeCrossAccount   ReviewScopeMode = "cross_account"
	ReviewScopeModePrivilegeCreep ReviewScopeMode = "privilege_creep"
)

type ReviewSchedule struct {
	Frequency string     `json:"frequency"`
	NextRun   time.Time  `json:"next_run"`
	LastRun   *time.Time `json:"last_run,omitempty"`
}

type ReviewItem struct {
	ID                 string                `json:"id"`
	ReviewID           string                `json:"review_id"`
	Type               string                `json:"type"`
	Principal          Principal             `json:"principal"`
	Access             []AccessGrant         `json:"access"`
	RiskScore          int                   `json:"risk_score"`
	RiskFactors        []string              `json:"risk_factors,omitempty"`
	Decision           *ReviewDecision       `json:"decision,omitempty"`
	Recommendation     *ReviewRecommendation `json:"recommendation,omitempty"`
	ReviewerCandidates []string              `json:"reviewer_candidates,omitempty"`
	LastActivity       *time.Time            `json:"last_activity,omitempty"`
	Path               []string              `json:"path,omitempty"`
	Flags              []string              `json:"flags,omitempty"`
	Metadata           map[string]any        `json:"metadata,omitempty"`
}

type Principal struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
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

type ReviewRecommendation struct {
	Action     DecisionAction `json:"action"`
	Reason     string         `json:"reason"`
	Confidence string         `json:"confidence,omitempty"`
}

type ReviewEvent struct {
	Sequence   int64           `json:"sequence"`
	Type       string          `json:"type"`
	RecordedAt time.Time       `json:"recorded_at"`
	Actor      string          `json:"actor,omitempty"`
	ItemID     string          `json:"item_id,omitempty"`
	Decision   *ReviewDecision `json:"decision,omitempty"`
	Metadata   map[string]any  `json:"metadata,omitempty"`
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
	Modified      int `json:"modified"`
	Escalated     int `json:"escalated"`
	Deferred      int `json:"deferred"`
	HighRisk      int `json:"high_risk"`
	CompletionPct int `json:"completion_pct"`
}

type Service struct {
	store          Store
	graphResolver  func(context.Context) *graph.Graph
	riskCalculator *RiskCalculator
}

type ServiceOption func(*Service)

func WithStore(store Store) ServiceOption {
	return func(s *Service) {
		if store != nil {
			s.store = store
		}
	}
}

func WithExecutionStore(store executionstore.Store) ServiceOption {
	return func(s *Service) {
		if store != nil {
			s.store = NewSQLiteStoreWithExecutionStore(store, DefaultStoreNamespace)
		}
	}
}

func WithGraphResolver(resolver func(context.Context) *graph.Graph) ServiceOption {
	return func(s *Service) {
		s.graphResolver = resolver
	}
}

func NewService(opts ...ServiceOption) *Service {
	svc := &Service{
		store:          NewMemoryStore(),
		riskCalculator: NewRiskCalculator(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(svc)
		}
	}
	return svc
}

func (s *Service) CreateReview(ctx context.Context, review *AccessReview) (*AccessReview, error) {
	if review == nil {
		return nil, cerrors.E(cerrors.Op("identity.CreateReview"), cerrors.ErrInvalidInput, "review payload is required")
	}
	if strings.TrimSpace(review.Name) == "" {
		return nil, cerrors.E(cerrors.Op("identity.CreateReview"), cerrors.ErrInvalidInput, "review name is required")
	}

	now := time.Now().UTC()
	created := *review
	created.ID = uuid.New().String()
	created.Name = strings.TrimSpace(review.Name)
	created.Description = strings.TrimSpace(review.Description)
	created.CreatedAt = now
	created.Events = nil
	created.GenerationSource = strings.TrimSpace(review.GenerationSource)
	if created.GenerationSource == "" {
		created.GenerationSource = "manual"
	}
	if created.Type == "" {
		created.Type = ReviewTypeUserAccess
	}
	created.Status = ReviewStatusDraft
	if created.Schedule != nil && !created.Schedule.NextRun.IsZero() && created.Schedule.NextRun.After(now) {
		created.Status = ReviewStatusScheduled
	}
	if created.DueAt == nil && created.Schedule != nil && !created.Schedule.NextRun.IsZero() {
		due := created.Schedule.NextRun
		created.DueAt = &due
	}
	if created.GenerationSource == "graph" && len(created.Items) == 0 {
		items, err := s.generateReviewItems(ctx, &created)
		if err != nil {
			return nil, err
		}
		created.Items = items
	}
	created.recalculateStats()
	if err := s.store.SaveReview(ctx, &created); err != nil {
		return nil, fmt.Errorf("save access review: %w", err)
	}
	_, err := s.store.AppendEvent(ctx, created.ID, ReviewEvent{
		Type:       "review.created",
		RecordedAt: now,
		Actor:      created.CreatedBy,
		Metadata: map[string]any{
			"item_count": created.Stats.TotalItems,
			"scope_mode": created.Scope.effectiveMode(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("append access review event: %w", err)
	}
	return s.store.LoadReview(ctx, created.ID)
}

func (s *Service) GetReview(ctx context.Context, id string) (*AccessReview, bool) {
	review, err := s.store.LoadReview(ctx, strings.TrimSpace(id))
	return review, err == nil && review != nil
}

func (s *Service) ListReviews(ctx context.Context, status ReviewStatus) []*AccessReview {
	reviews, err := s.store.ListReviews(ctx, status)
	if err != nil {
		return nil
	}
	return reviews
}

func (s *Service) StartReview(ctx context.Context, id string) error {
	review, err := s.loadRequiredReview(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	review.Status = ReviewStatusInProgress
	review.StartedAt = &now
	if review.Schedule != nil {
		review.Schedule.LastRun = &now
	}
	if err := s.store.SaveReview(ctx, review); err != nil {
		return fmt.Errorf("save started access review: %w", err)
	}
	_, err = s.store.AppendEvent(ctx, review.ID, ReviewEvent{Type: "review.started", RecordedAt: now})
	if err != nil {
		return fmt.Errorf("append access review event: %w", err)
	}
	return nil
}

func (s *Service) AddReviewItem(ctx context.Context, reviewID string, item *ReviewItem) error {
	if item == nil {
		return cerrors.E(cerrors.Op("identity.AddReviewItem"), cerrors.ErrInvalidInput, "review item is required")
	}
	review, err := s.loadRequiredReview(ctx, reviewID)
	if err != nil {
		return err
	}
	prepared := s.prepareManualReviewItem(review, item)
	review.Items = append(review.Items, prepared)
	review.recalculateStats()
	if err := s.store.SaveReview(ctx, review); err != nil {
		return fmt.Errorf("save access review: %w", err)
	}
	_, err = s.store.AppendEvent(ctx, review.ID, ReviewEvent{
		Type:       "review.item_added",
		RecordedAt: time.Now().UTC(),
		ItemID:     prepared.ID,
		Metadata: map[string]any{
			"risk_score": prepared.RiskScore,
		},
	})
	if err != nil {
		return fmt.Errorf("append access review event: %w", err)
	}
	return nil
}

func (s *Service) RecordDecision(ctx context.Context, reviewID, itemID string, decision *ReviewDecision) error {
	if decision == nil {
		return cerrors.E(cerrors.Op("identity.RecordDecision"), cerrors.ErrInvalidInput, "review decision is required")
	}
	review, err := s.loadRequiredReview(ctx, reviewID)
	if err != nil {
		return err
	}
	normalizedItemID := strings.TrimSpace(itemID)
	for i := range review.Items {
		if review.Items[i].ID != normalizedItemID {
			continue
		}
		if strings.TrimSpace(review.Items[i].ReviewID) != "" && strings.TrimSpace(review.Items[i].ReviewID) != strings.TrimSpace(review.ID) {
			return cerrors.E(cerrors.Op("identity.RecordDecision"), cerrors.ErrInvalidInput, "review item does not belong to review")
		}
		decided := *decision
		if decided.DecidedAt.IsZero() {
			decided.DecidedAt = time.Now().UTC()
		}
		review.Items[i].Decision = &decided
		review.recalculateStats()
		if review.Stats.Pending == 0 {
			completed := decided.DecidedAt.UTC()
			review.Status = ReviewStatusCompleted
			review.CompletedAt = &completed
		}
		if err := s.store.SaveReview(ctx, review); err != nil {
			return fmt.Errorf("save access review decision: %w", err)
		}
		_, err = s.store.AppendEvent(ctx, review.ID, ReviewEvent{
			Type:       "review.item_decided",
			RecordedAt: decided.DecidedAt.UTC(),
			Actor:      decided.Reviewer,
			ItemID:     review.Items[i].ID,
			Decision:   &decided,
		})
		if err != nil {
			return fmt.Errorf("append access review event: %w", err)
		}
		if review.Status == ReviewStatusCompleted {
			_, err = s.store.AppendEvent(ctx, review.ID, ReviewEvent{Type: "review.completed", RecordedAt: decided.DecidedAt.UTC()})
			if err != nil {
				return fmt.Errorf("append access review completion event: %w", err)
			}
		}
		return nil
	}
	return cerrors.E(cerrors.Op("identity.RecordDecision"), cerrors.ErrNotFound, "review item not found in review")
}

func (s *Service) GetPendingItems(ctx context.Context, reviewerID string) []*ReviewItem {
	reviews, err := s.store.ListReviews(ctx, ReviewStatusInProgress)
	if err != nil {
		return nil
	}
	var pending []*ReviewItem
	for _, review := range reviews {
		full, err := s.store.LoadReview(ctx, review.ID)
		if err != nil || full == nil {
			continue
		}
		for i := range full.Items {
			item := &full.Items[i]
			if item.Decision != nil {
				continue
			}
			if reviewerID == "" || containsString(item.ReviewerCandidates, reviewerID) {
				pending = append(pending, item)
			}
		}
	}
	return pending
}

func (s *Service) loadRequiredReview(ctx context.Context, reviewID string) (*AccessReview, error) {
	review, err := s.store.LoadReview(ctx, strings.TrimSpace(reviewID))
	if err != nil {
		return nil, fmt.Errorf("load access review: %w", err)
	}
	if review == nil {
		return nil, cerrors.E(cerrors.Op("identity.loadRequiredReview"), cerrors.ErrNotFound, "access review not found")
	}
	return review, nil
}

func (s *Service) prepareManualReviewItem(review *AccessReview, item *ReviewItem) ReviewItem {
	prepared := *item
	prepared.ID = uuid.New().String()
	prepared.ReviewID = review.ID
	if prepared.Metadata == nil {
		prepared.Metadata = map[string]any{}
	}
	if prepared.RiskScore == 0 {
		prepared.RiskScore, prepared.RiskFactors = s.riskCalculator.Calculate(&prepared)
	}
	if prepared.Recommendation == nil {
		prepared.Recommendation = &ReviewRecommendation{Action: DecisionDefer, Reason: "manual review item requires reviewer judgment", Confidence: "low"}
	}
	return prepared
}

func (r *AccessReview) recalculateStats() {
	r.Stats = ReviewStats{TotalItems: len(r.Items), Pending: len(r.Items)}
	for _, item := range r.Items {
		if item.RiskScore >= 80 {
			r.Stats.HighRisk++
		}
		if item.Decision == nil {
			continue
		}
		r.Stats.Pending--
		switch item.Decision.Action {
		case DecisionApprove:
			r.Stats.Approved++
		case DecisionRevoke:
			r.Stats.Revoked++
		case DecisionModify:
			r.Stats.Modified++
		case DecisionEscalate:
			r.Stats.Escalated++
		case DecisionDefer:
			r.Stats.Deferred++
		}
	}
	if r.Stats.TotalItems > 0 {
		completed := r.Stats.TotalItems - r.Stats.Pending
		r.Stats.CompletionPct = (completed * 100) / r.Stats.TotalItems
	}
}

func (s ReviewScope) effectiveMode() ReviewScopeMode {
	if s.Mode != "" {
		return s.Mode
	}
	switch {
	case len(s.Resources) > 0:
		return ReviewScopeModeResource
	case len(s.Users) > 0:
		return ReviewScopeModePrincipal
	case len(s.Accounts) > 0:
		return ReviewScopeModeAccount
	default:
		return ReviewScopeModeAll
	}
}

// RiskCalculator computes risk scores for review items.
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

	for _, grant := range item.Access {
		role := strings.ToLower(strings.TrimSpace(grant.Role))
		perm := strings.ToLower(strings.TrimSpace(grant.Permission))
		if role == "admin" || role == "owner" || perm == "*" || strings.Contains(perm, "admin") {
			score += rc.weights["admin_access"]
			factors = append(factors, "Has admin/owner access")
			break
		}
	}

	if item.Principal.Type == "service_account" {
		score += rc.weights["service_account"]
		factors = append(factors, "Service account")
	}

	lastActivity := item.LastActivity
	if lastActivity == nil {
		lastActivity = item.Principal.LastLogin
	}
	if lastActivity != nil {
		if time.Since(*lastActivity) > 90*24*time.Hour {
			score += rc.weights["no_recent_login"]
			factors = append(factors, "No login in 90+ days")
		}
	}

	for _, grant := range item.Access {
		if !grant.GrantedAt.IsZero() && time.Since(grant.GrantedAt) > 365*24*time.Hour {
			score += rc.weights["long_standing"]
			factors = append(factors, "Access granted over 1 year ago")
			break
		}
	}

	if score > 100 {
		score = 100
	}
	return score, uniqueStrings(factors)
}

func containsString(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
