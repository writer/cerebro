package graph

import (
	"sync"
	"testing"
	"time"
)

func TestRiskEngine_ConcurrentOperations(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "customer:acme",
		Kind: NodeKindCustomer,
		Name: "Acme",
		Properties: map[string]any{
			"failed_payment_count":     2,
			"open_p1_tickets":          1,
			"days_since_last_activity": 25,
		},
	})

	engine := NewRiskEngine(g)
	const workers = 6
	const iterations = 20

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = engine.Analyze()
				_, _ = engine.RecordOutcome(OutcomeEvent{
					EntityID:   "customer:acme",
					Outcome:    "churn",
					OccurredAt: time.Now().UTC().Add(time.Duration(worker*iterations+i) * time.Second),
				})
				_ = engine.OutcomeFeedback(30*24*time.Hour, "default")
				_ = engine.DiscoverRules(RuleDiscoveryRequest{
					WindowDays:    30,
					MinDetections: 1,
					MaxCandidates: 5,
				})
			}
		}(worker)
	}
	wg.Wait()

	if len(engine.OutcomeEvents("", "")) == 0 {
		t.Fatal("expected outcomes after concurrent operations")
	}
}
