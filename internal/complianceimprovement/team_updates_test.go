package complianceimprovement

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type deliveryTestStore struct {
	receipt TeamUpdateReceipt
	update  TeamUpdate
	marked  bool
}

func (store *deliveryTestStore) EnqueueTeamUpdate(_ context.Context, _, _ string, update TeamUpdate) (TeamUpdateReceipt, error) {
	store.update = update
	if store.receipt.OutboxID == "" {
		store.receipt = TeamUpdateReceipt{OutboxID: "outbox-42", ProposalDigest: update.ProposalDigest, QueuedAt: testNow}
	}
	return store.receipt, nil
}

func (store *deliveryTestStore) MarkTeamUpdateDelivered(_ context.Context, _, outboxID string, deliveredAt time.Time) error {
	if outboxID != store.receipt.OutboxID || deliveredAt.IsZero() {
		return ErrInvalidRequest
	}
	store.marked = true
	return nil
}

type deliveryTestSink struct {
	deliveryID string
	update     TeamUpdate
	err        error
}

func (sink *deliveryTestSink) DeliverTeamUpdate(_ context.Context, deliveryID string, update TeamUpdate) error {
	sink.deliveryID = deliveryID
	sink.update = update
	return sink.err
}

func TestDeliveringTeamUpdateOutboxPersistsBeforeDeliveryAndMarksSuccess(t *testing.T) {
	store := &deliveryTestStore{}
	sink := &deliveryTestSink{}
	outbox := NewDeliveringTeamUpdateOutbox(store, sink)
	outbox.now = func() time.Time { return testNow }
	update := validTeamUpdate()
	receipt, err := outbox.EnqueueTeamUpdate(context.Background(), "tenant-a", "proposal-a", update)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.OutboxID != "outbox-42" || sink.deliveryID != receipt.OutboxID || sink.update.ProposalDigest != update.ProposalDigest || !store.marked {
		t.Fatalf("delivery = receipt %+v sink %+v marked %t", receipt, sink, store.marked)
	}
}

func TestDeliveringTeamUpdateOutboxLeavesFailedDeliveryPending(t *testing.T) {
	store := &deliveryTestStore{}
	sink := &deliveryTestSink{err: errors.New("channel unavailable")}
	outbox := NewDeliveringTeamUpdateOutbox(store, sink)
	_, err := outbox.EnqueueTeamUpdate(context.Background(), "tenant-a", "proposal-a", validTeamUpdate())
	if err == nil || store.marked || store.update.ProposalDigest == "" {
		t.Fatalf("failed delivery = err %v marked %t persisted %+v", err, store.marked, store.update)
	}
}

func TestSlackTeamUpdateSinkPostsConcreteDecisionRequest(t *testing.T) {
	var payload struct {
		Channel     string `json:"channel"`
		Text        string `json:"text"`
		ClientMsgID string `json:"client_msg_id"`
		UnfurlLinks bool   `json:"unfurl_links"`
		UnfurlMedia bool   `json:"unfurl_media"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/chat.postMessage" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		writeGitHubJSON(writer, http.StatusOK, map[string]any{"ok": true, "channel": "C123", "ts": "1.2"})
	}))
	t.Cleanup(server.Close)
	sink, err := NewSlackTeamUpdateSink(server.Client(), SlackTeamUpdateSinkConfig{BaseURL: server.URL, AllowLoopback: true, ChannelID: "C123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.DeliverTeamUpdate(context.Background(), "outbox-42", validTeamUpdate()); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Compliance program change needs review",
		"Current: 60 percent",
		"Target: >= 95 percent",
		"Supporting facts: 1; counterevidence: 1; unknowns: 1",
		"Draft PR: https://example.invalid/pulls/42",
		"Decision owner: grc-owner",
	} {
		if !strings.Contains(payload.Text, required) {
			t.Fatalf("Slack text missing %q:\n%s", required, payload.Text)
		}
	}
	if payload.Channel != "C123" || payload.ClientMsgID != "outbox-42" || payload.UnfurlLinks || payload.UnfurlMedia {
		t.Fatalf("Slack payload = %+v", payload)
	}
}

func TestSlackTeamUpdateSinkRejectsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeGitHubJSON(writer, http.StatusOK, map[string]any{"ok": false, "error": "not_in_channel"})
	}))
	t.Cleanup(server.Close)
	sink, err := NewSlackTeamUpdateSink(server.Client(), SlackTeamUpdateSinkConfig{BaseURL: server.URL, AllowLoopback: true, ChannelID: "C123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.DeliverTeamUpdate(context.Background(), "outbox-42", validTeamUpdate()); err == nil {
		t.Fatal("DeliverTeamUpdate() accepted Slack provider error")
	}
}

func validTeamUpdate() TeamUpdate {
	return TeamUpdate{
		ProposalDigest: "sha256:" + strings.Repeat("f", 64), State: StateDraftPROpened,
		GapSummary:      "Quarterly access evidence is incomplete.",
		Current:         Measurement{Name: "evidence_coverage", Value: 60, Unit: "percent"},
		Target:          TargetMeasurement{Name: "evidence_coverage", Comparator: ">=", Value: 95, Unit: "percent"},
		Supporting:      []ResearchClaim{{ID: "claim-1", Statement: "Evidence is incomplete.", CitationIDs: []string{"citation-1"}}},
		Counterevidence: []ResearchClaim{{ID: "counter-1", Statement: "The latest interval is current.", CitationIDs: []string{"citation-1"}}},
		Unknowns:        []string{"Earlier interval coverage."},
		Verification:    []VerificationResult{{VerifierID: "exact-inputs", Status: VerificationPass, Message: "Inputs match."}},
		PullRequest: DraftPullRequestReceipt{
			Repository: "writer/cerebro", Number: 42, URL: "https://example.invalid/pulls/42",
			HeadCommitSHA: strings.Repeat("c", 40), BaseCommitSHA: strings.Repeat("b", 40), Draft: true,
			ProposalDigest: "sha256:" + strings.Repeat("f", 64), OpenedAt: testNow,
		},
		DecisionOwner: "grc-owner", RequiredAction: "Review the evidence and draft changes.", CreatedAt: testNow,
	}
}
