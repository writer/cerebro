package identity

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/executionstore"
	"github.com/evalops/cerebro/internal/graph"
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

	err := svc.RecordDecision(context.Background(), review.ID, itemID, decision)
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

	if err := svc.RecordDecision(context.Background(), review.ID, itemID, decision); err != nil {
		t.Fatalf("RecordDecision failed: %v", err)
	}
	got, _ = svc.GetReview(context.Background(), review.ID)
	if got.Stats.Revoked != 1 {
		t.Errorf("expected 1 revoked, got %d", got.Stats.Revoked)
	}
}

func TestServiceRecordDecisionCountsModifyAndDefer(t *testing.T) {
	svc := NewService()

	review, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Decision coverage review"})
	if err := svc.AddReviewItem(context.Background(), review.ID, &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-1"},
	}); err != nil {
		t.Fatalf("AddReviewItem 1 failed: %v", err)
	}
	if err := svc.AddReviewItem(context.Background(), review.ID, &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-2"},
	}); err != nil {
		t.Fatalf("AddReviewItem 2 failed: %v", err)
	}

	got, _ := svc.GetReview(context.Background(), review.ID)
	itemAID := got.Items[0].ID
	itemBID := got.Items[1].ID

	if err := svc.RecordDecision(context.Background(), review.ID, itemAID, &ReviewDecision{
		Action:   DecisionModify,
		Reviewer: "admin@company.com",
	}); err != nil {
		t.Fatalf("RecordDecision modify failed: %v", err)
	}
	if err := svc.RecordDecision(context.Background(), review.ID, itemBID, &ReviewDecision{
		Action:   DecisionDefer,
		Reviewer: "admin@company.com",
	}); err != nil {
		t.Fatalf("RecordDecision defer failed: %v", err)
	}

	got, _ = svc.GetReview(context.Background(), review.ID)
	if got.Stats.Pending != 0 {
		t.Fatalf("expected 0 pending, got %d", got.Stats.Pending)
	}
	if got.Stats.Modified != 1 {
		t.Fatalf("expected 1 modified, got %d", got.Stats.Modified)
	}
	if got.Stats.Deferred != 1 {
		t.Fatalf("expected 1 deferred, got %d", got.Stats.Deferred)
	}
	if got.Stats.CompletionPct != 100 {
		t.Fatalf("expected 100%% completion, got %d%%", got.Stats.CompletionPct)
	}
	if got.Status != ReviewStatusCompleted {
		t.Fatalf("expected review to complete after all decisions, got %s", got.Status)
	}
}

func TestServiceRecordDecisionRejectsForeignReviewItem(t *testing.T) {
	svc := NewService()

	reviewA, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Review A"})
	reviewB, _ := svc.CreateReview(context.Background(), &AccessReview{Name: "Review B"})

	if err := svc.AddReviewItem(context.Background(), reviewA.ID, &ReviewItem{
		Type:      "user",
		Principal: Principal{ID: "user-1"},
	}); err != nil {
		t.Fatalf("AddReviewItem failed: %v", err)
	}

	gotA, _ := svc.GetReview(context.Background(), reviewA.ID)
	itemID := gotA.Items[0].ID

	err := svc.RecordDecision(context.Background(), reviewB.ID, itemID, &ReviewDecision{
		Action:   DecisionApprove,
		Reviewer: "admin@company.com",
	})
	if err == nil {
		t.Fatal("expected foreign review item decision to fail")
	}

	gotA, _ = svc.GetReview(context.Background(), reviewA.ID)
	if gotA.Items[0].Decision != nil {
		t.Fatal("expected foreign review item decision to leave source review unchanged")
	}

	gotB, _ := svc.GetReview(context.Background(), reviewB.ID)
	if len(gotB.Items) != 0 {
		t.Fatalf("expected target review to remain unchanged, got %d items", len(gotB.Items))
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

func TestServiceCreateReviewGeneratesGraphCampaignItems(t *testing.T) {
	g := graph.New()
	lastLogin := time.Now().Add(-120 * 24 * time.Hour).UTC()
	g.AddNode(&graph.Node{
		ID:        "user:alice",
		Kind:      graph.NodeKindUser,
		Name:      "alice@example.com",
		Provider:  "aws",
		Account:   "123456789012",
		CreatedAt: time.Now().Add(-400 * 24 * time.Hour).UTC(),
		Properties: map[string]any{
			"email":      "alice@example.com",
			"last_login": lastLogin.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:        "person:bob",
		Kind:      graph.NodeKindPerson,
		Name:      "Bob Reviewer",
		Provider:  "internal",
		Account:   "corp",
		CreatedAt: time.Now().Add(-500 * 24 * time.Hour).UTC(),
	})
	g.AddNode(&graph.Node{
		ID:        "bucket:prod-data",
		Kind:      graph.NodeKindBucket,
		Name:      "prod-data",
		Provider:  "aws",
		Account:   "123456789012",
		Risk:      graph.RiskCritical,
		CreatedAt: time.Now().Add(-500 * 24 * time.Hour).UTC(),
	})
	g.AddEdge(&graph.Edge{
		ID:     "alice-admin",
		Source: "user:alice",
		Target: "bucket:prod-data",
		Kind:   graph.EdgeKindCanAdmin,
		Effect: graph.EdgeEffectAllow,
	})
	g.AddEdge(&graph.Edge{
		ID:     "bob-owns-bucket",
		Source: "person:bob",
		Target: "bucket:prod-data",
		Kind:   graph.EdgeKindOwns,
		Effect: graph.EdgeEffectAllow,
	})

	svc := NewService(WithGraphResolver(func(context.Context) *graph.Graph { return g }))
	review, err := svc.CreateReview(context.Background(), &AccessReview{
		Name:             "Quarterly Prod Review",
		CreatedBy:        "secops@example.com",
		GenerationSource: "graph",
		Scope: ReviewScope{
			Mode:      ReviewScopeModeResource,
			Resources: []string{"bucket:prod-data"},
			Users:     []string{"user:alice"},
		},
	})
	if err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}
	if len(review.Items) != 1 {
		t.Fatalf("expected 1 generated item, got %d", len(review.Items))
	}
	item := review.Items[0]
	if item.Recommendation == nil || item.Recommendation.Action != DecisionEscalate {
		t.Fatalf("expected escalate recommendation, got %#v", item.Recommendation)
	}
	if !containsString(item.ReviewerCandidates, "person:bob") {
		t.Fatalf("expected owner in reviewer candidates, got %#v", item.ReviewerCandidates)
	}
	if item.Metadata["resource_id"] != "bucket:prod-data" {
		t.Fatalf("expected resource metadata, got %#v", item.Metadata)
	}
	if !containsString(item.Flags, "stale_access") || !containsString(item.Flags, "sensitive_resource") {
		t.Fatalf("expected stale/sensitive flags, got %#v", item.Flags)
	}
}

func TestServicePersistsReviewsInSharedExecutionStore(t *testing.T) {
	shared, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	t.Cleanup(func() { _ = shared.Close() })

	svc := NewService(WithExecutionStore(shared))
	review, err := svc.CreateReview(context.Background(), &AccessReview{
		Name:      "Persisted Review",
		Type:      ReviewTypeUserAccess,
		CreatedBy: "tester@example.com",
		Items: []ReviewItem{{
			Type:      "user",
			Principal: Principal{ID: "user:alice", Type: "user", Name: "Alice"},
			Access:    []AccessGrant{{Resource: "bucket:data", Permission: "read", GrantedAt: time.Now().UTC()}},
			RiskScore: 25,
		}},
	})
	if err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}
	if err := svc.StartReview(context.Background(), review.ID); err != nil {
		t.Fatalf("StartReview failed: %v", err)
	}

	reloaded := NewService(WithExecutionStore(shared))
	got, ok := reloaded.GetReview(context.Background(), review.ID)
	if !ok {
		t.Fatal("expected persisted review")
	}
	if got.Status != ReviewStatusInProgress {
		t.Fatalf("expected persisted in-progress status, got %s", got.Status)
	}
	if len(got.Events) == 0 {
		t.Fatal("expected persisted events")
	}
	var eventTypes []string
	for _, event := range got.Events {
		eventTypes = append(eventTypes, event.Type)
	}
	joined := strings.Join(eventTypes, ",")
	if !strings.Contains(joined, "review.created") || !strings.Contains(joined, "review.started") {
		t.Fatalf("expected created/started events, got %#v", eventTypes)
	}
}

func TestServiceCreateReviewDoesNotAutoGenerateManualGraphCampaigns(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "user:alice",
		Kind:     graph.NodeKindUser,
		Name:     "alice@example.com",
		Provider: "aws",
		Account:  "123456789012",
	})
	g.AddNode(&graph.Node{
		ID:       "bucket:prod-data",
		Kind:     graph.NodeKindBucket,
		Name:     "prod-data",
		Provider: "aws",
		Account:  "123456789012",
		Risk:     graph.RiskCritical,
	})
	g.AddEdge(&graph.Edge{
		ID:     "alice-admin",
		Source: "user:alice",
		Target: "bucket:prod-data",
		Kind:   graph.EdgeKindCanAdmin,
		Effect: graph.EdgeEffectAllow,
	})

	svc := NewService(WithGraphResolver(func(context.Context) *graph.Graph { return g }))
	review, err := svc.CreateReview(context.Background(), &AccessReview{
		Name:      "Manual Review",
		CreatedBy: "secops@example.com",
		Scope: ReviewScope{
			Mode:      ReviewScopeModeResource,
			Resources: []string{"bucket:prod-data"},
			Users:     []string{"user:alice"},
		},
	})
	if err != nil {
		t.Fatalf("CreateReview failed: %v", err)
	}
	if review.GenerationSource != "manual" {
		t.Fatalf("expected manual generation source, got %q", review.GenerationSource)
	}
	if len(review.Items) != 0 {
		t.Fatalf("expected no auto-generated items for manual review, got %d", len(review.Items))
	}
}

func TestBuildRecommendationEscalatesToxicStaleAccess(t *testing.T) {
	stale := time.Now().Add(-120 * 24 * time.Hour).UTC()
	recommendation := buildRecommendation(ReviewItem{
		RiskScore:    90,
		LastActivity: &stale,
	}, &graph.Node{
		ID:   "bucket:prod-data",
		Kind: graph.NodeKindBucket,
		Risk: graph.RiskCritical,
	}, toxicReviewContext{
		IDs: []string{"toxic:1"},
	})
	if recommendation == nil {
		t.Fatal("expected recommendation")
	}
	if recommendation.Action != DecisionEscalate {
		t.Fatalf("expected escalate recommendation, got %#v", recommendation)
	}
}
