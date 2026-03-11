package identity

import (
	"context"
	"testing"
	"time"
)

func TestServiceCreateReview(t *testing.T) {
	svc := NewService()

	review := &AccessReview{
		Name:        "Q1 Access Review",
		Description: "Quarterly access review",
		Type:        ReviewTypeUserAccess,
		Reviewers:   []string{"admin@company.com"},
	}

	created, err := svc.CreateReview(context.Background(), review)
	if err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}

	if created.ID == "" {
		t.Error("expected ID to be set")
	}
	if created.Status != ReviewStatusDraft {
		t.Errorf("expected status 'draft', got '%s'", created.Status)
	}
	if created.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestServiceGetReview(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{
		Name: "Test Review",
	})

	got, ok := svc.GetReview(context.Background(), review.ID)
	if !ok {
		t.Fatal("expected to find review")
	}
	if got.Name != "Test Review" {
		t.Errorf("expected name 'Test Review', got '%s'", got.Name)
	}

	_, ok = svc.GetReview(context.Background(), "nonexistent")
	if ok {
		t.Error("expected not to find nonexistent review")
	}
}

func TestServiceListReviews(t *testing.T) {
	svc := NewService()

	if _, err := svc.CreateReview(context.Background(), &AccessReview{Name: "Review 1"}); err != nil {
		t.Fatalf("CreateReview Review 1 failed: %v", err)
	}
	if _, err := svc.CreateReview(context.Background(), &AccessReview{Name: "Review 2"}); err != nil {
		t.Fatalf("CreateReview Review 2 failed: %v", err)
	}

	reviews := svc.ListReviews(context.Background(), "")
	if len(reviews) != 2 {
		t.Errorf("expected 2 reviews, got %d", len(reviews))
	}

	// Filter by status
	reviews = svc.ListReviews(context.Background(), ReviewStatusDraft)
	if len(reviews) != 2 {
		t.Errorf("expected 2 draft reviews, got %d", len(reviews))
	}

	reviews = svc.ListReviews(context.Background(), ReviewStatusCompleted)
	if len(reviews) != 0 {
		t.Errorf("expected 0 completed reviews, got %d", len(reviews))
	}
}

func TestServiceStartReview(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Test Review"})

	err := svc.StartReview(context.Background(), review.ID)
	if err != nil {
		t.Fatalf("StartReview failed: %v", err)
	}

	got, _ := svc.GetReview(context.Background(), review.ID)
	if got.Status != ReviewStatusInProgress {
		t.Errorf("expected status 'in_progress', got '%s'", got.Status)
	}
	if got.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}
}

func TestServiceAddReviewItem(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Test Review"})

	item := &ReviewItem{
		Type: "user",
		Principal: Principal{
			ID:       "user-1",
			Type:     "user",
			Name:     "John Doe",
			Email:    "john@company.com",
			Provider: "okta",
		},
		Access: []AccessGrant{
			{
				Resource:   "admin-bucket",
				Permission: "read",
			},
		},
		RiskScore: 50,
	}

	err := svc.AddReviewItem(context.Background(), review.ID, item)
	if err != nil {
		t.Fatalf("AddReviewItem failed: %v", err)
	}

	got, _ := svc.GetReview(context.Background(), review.ID)
	if got.Stats.TotalItems != 1 {
		t.Errorf("expected 1 total item, got %d", got.Stats.TotalItems)
	}
	if got.Stats.Pending != 1 {
		t.Errorf("expected 1 pending item, got %d", got.Stats.Pending)
	}
}

func TestServiceRecordDecision(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Test Review"})

	item := &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-1"},
		RiskScore: 30,
	}
	if err := svc.AddReviewItem(context.Background(), review.ID, item); err != nil {
		t.Fatalf("AddReviewItem failed: %v", err)
	}

	// Get item ID
	got, _ := svc.GetReview(context.Background(), review.ID)
	itemID := got.Items[0].ID

	decision := &ReviewDecision{
		Action:   DecisionApprove,
		Reviewer: "admin@company.com",
		Comment:  "Access verified",
	}

	err := svc.RecordDecision(context.Background(), itemID, decision)
	if err != nil {
		t.Fatalf("RecordDecision failed: %v", err)
	}

	// Check stats updated
	got, _ = svc.GetReview(context.Background(), review.ID)
	if got.Stats.Pending != 0 {
		t.Errorf("expected 0 pending, got %d", got.Stats.Pending)
	}
	if got.Stats.Approved != 1 {
		t.Errorf("expected 1 approved, got %d", got.Stats.Approved)
	}
	if got.Stats.CompletionPct != 100 {
		t.Errorf("expected 100%% completion, got %d%%", got.Stats.CompletionPct)
	}
	if got.Status != ReviewStatusCompleted {
		t.Errorf("expected status 'completed', got '%s'", got.Status)
	}
}

func TestServiceRecordDecisionRevoke(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Test Review"})

	if err := svc.AddReviewItem(context.Background(), review.ID, &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-1"},
	}); err != nil {
		t.Fatalf("AddReviewItem failed: %v", err)
	}

	got, _ := svc.GetReview(context.Background(), review.ID)
	itemID := got.Items[0].ID

	decision := &ReviewDecision{
		Action:   DecisionRevoke,
		Reviewer: "admin@company.com",
		Comment:  "Access no longer needed",
	}

	if err := svc.RecordDecision(context.Background(), itemID, decision); err != nil {
		t.Fatalf("RecordDecision failed: %v", err)
	}

	got, _ = svc.GetReview(context.Background(), review.ID)
	if got.Stats.Revoked != 1 {
		t.Errorf("expected 1 revoked, got %d", got.Stats.Revoked)
	}
}

func TestServiceHighRiskTracking(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Test Review"})

	// Low risk item
	if err := svc.AddReviewItem(context.Background(), review.ID, &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-1"},
		RiskScore: 30,
	}); err != nil {
		t.Fatalf("AddReviewItem low risk failed: %v", err)
	}

	// High risk item (>= 80)
	if err := svc.AddReviewItem(context.Background(), review.ID, &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-2"},
		RiskScore: 85,
	}); err != nil {
		t.Fatalf("AddReviewItem high risk failed: %v", err)
	}

	got, _ := svc.GetReview(context.Background(), review.ID)
	if got.Stats.HighRisk != 1 {
		t.Errorf("expected 1 high risk item, got %d", got.Stats.HighRisk)
	}
}

func TestRiskCalculator(t *testing.T) {
	calc := NewRiskCalculator()

	item := &ReviewItem{
		Principal: Principal{
			Type: "service_account",
		},
		Access: []AccessGrant{
			{
				Role:      "admin",
				GrantedAt: time.Now().AddDate(-2, 0, 0), // 2 years ago
			},
		},
	}

	score, factors := calc.Calculate(item)

	if score < 50 {
		t.Errorf("expected high risk score, got %d", score)
	}

	// Should have multiple risk factors
	if len(factors) < 2 {
		t.Errorf("expected multiple risk factors, got %d", len(factors))
	}

	// Check for expected factors
	hasAdminFactor := false
	hasServiceAccountFactor := false
	hasLongStandingFactor := false

	for _, f := range factors {
		if f == "Has admin/owner access" {
			hasAdminFactor = true
		}
		if f == "Service account" {
			hasServiceAccountFactor = true
		}
		if f == "Access granted over 1 year ago" {
			hasLongStandingFactor = true
		}
	}

	if !hasAdminFactor {
		t.Error("expected admin access factor")
	}
	if !hasServiceAccountFactor {
		t.Error("expected service account factor")
	}
	if !hasLongStandingFactor {
		t.Error("expected long-standing access factor")
	}
}

func TestRiskCalculatorNoRecentLogin(t *testing.T) {
	calc := NewRiskCalculator()

	lastLogin := time.Now().AddDate(0, -4, 0) // 4 months ago
	item := &ReviewItem{
		Principal: Principal{
			Type:      "user",
			LastLogin: &lastLogin,
		},
	}

	score, factors := calc.Calculate(item)

	if score == 0 {
		t.Error("expected non-zero risk score")
	}

	hasNoLoginFactor := false
	for _, f := range factors {
		if f == "No login in 90+ days" {
			hasNoLoginFactor = true
		}
	}

	if !hasNoLoginFactor {
		t.Error("expected no recent login factor")
	}
}
