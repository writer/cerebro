package complianceimprovementhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	improvement "github.com/writer/cerebro/internal/complianceimprovement"
	"github.com/writer/cerebro/internal/sourcehttp"
)

// DeliveringTeamUpdateOutbox persists the update before attempting delivery.
// A failed delivery leaves the outbox record pending; a retry reuses the same
// outbox and provider idempotency key.
type DeliveringTeamUpdateOutbox struct {
	store improvement.TeamUpdateDeliveryStore
	sink  improvement.TeamUpdateSink
	now   func() time.Time
}

func NewDeliveringTeamUpdateOutbox(store improvement.TeamUpdateDeliveryStore, sink improvement.TeamUpdateSink) *DeliveringTeamUpdateOutbox {
	return &DeliveringTeamUpdateOutbox{store: store, sink: sink, now: func() time.Time { return time.Now().UTC() }}
}

func (outbox *DeliveringTeamUpdateOutbox) EnqueueTeamUpdate(ctx context.Context, tenantID, idempotencyKey string, update improvement.TeamUpdate) (improvement.TeamUpdateReceipt, error) {
	if outbox == nil || outbox.store == nil || outbox.sink == nil || outbox.now == nil {
		return improvement.TeamUpdateReceipt{}, improvement.ErrUnavailable
	}
	receipt, err := outbox.store.EnqueueTeamUpdate(ctx, tenantID, idempotencyKey, update)
	if err != nil {
		return improvement.TeamUpdateReceipt{}, err
	}
	if err := outbox.sink.DeliverTeamUpdate(ctx, receipt.OutboxID, update); err != nil {
		return improvement.TeamUpdateReceipt{}, fmt.Errorf("deliver compliance team update: %w", err)
	}
	if err := outbox.store.MarkTeamUpdateDelivered(ctx, tenantID, receipt.OutboxID, canonicalAdapterTime(outbox.now())); err != nil {
		return improvement.TeamUpdateReceipt{}, fmt.Errorf("mark compliance team update delivered: %w", err)
	}
	return receipt, nil
}

type SlackTeamUpdateSinkConfig struct {
	BaseURL       string
	AllowLoopback bool
	ChannelID     string
}

// SlackTeamUpdateSink posts one concrete decision request to an allowlisted
// channel. Authentication is supplied by the injected HTTP client's transport;
// tokens never enter the update payload or durable outbox.
type SlackTeamUpdateSink struct {
	client        *http.Client
	baseURL       string
	allowLoopback bool
	channelID     string
}

func NewSlackTeamUpdateSink(client *http.Client, config SlackTeamUpdateSinkConfig) (*SlackTeamUpdateSink, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: Slack HTTP client is required", improvement.ErrInvalidRequest)
	}
	baseURL := strings.TrimSpace(config.BaseURL)
	if baseURL == "" {
		baseURL = "https://slack.com/api"
	}
	normalized, _, err := sourcehttp.NormalizeBaseURL("compliance-team-slack", baseURL, config.AllowLoopback)
	if err != nil {
		return nil, err
	}
	channelID := strings.TrimSpace(config.ChannelID)
	if channelID == "" || len(channelID) > 128 || strings.ContainsAny(channelID, " \t\r\n") {
		return nil, fmt.Errorf("%w: Slack channel ID is required", improvement.ErrInvalidRequest)
	}
	hardened := sourcehttp.HardenSourceClient(client, "compliance-team-slack", 10*time.Second, config.AllowLoopback, nil)
	return &SlackTeamUpdateSink{client: hardened, baseURL: normalized, allowLoopback: config.AllowLoopback, channelID: channelID}, nil
}

func (sink *SlackTeamUpdateSink) DeliverTeamUpdate(ctx context.Context, deliveryID string, update improvement.TeamUpdate) error {
	if sink == nil || sink.client == nil {
		return improvement.ErrUnavailable
	}
	deliveryID = strings.TrimSpace(deliveryID)
	if deliveryID == "" || strings.TrimSpace(update.ProposalDigest) == "" || strings.TrimSpace(update.PullRequest.URL) == "" || strings.TrimSpace(update.DecisionOwner) == "" {
		return fmt.Errorf("%w: complete team update and delivery ID are required", improvement.ErrInvalidRequest)
	}
	text := slackTeamUpdateText(update)
	if len(text) > 32*1024 {
		return fmt.Errorf("%w: team update exceeds Slack message limit", improvement.ErrInvalidRequest)
	}
	payload := struct {
		Channel     string `json:"channel"`
		Text        string `json:"text"`
		ClientMsgID string `json:"client_msg_id"`
		UnfurlLinks bool   `json:"unfurl_links"`
		UnfurlMedia bool   `json:"unfurl_media"`
	}{Channel: sink.channelID, Text: text, ClientMsgID: deliveryID}
	request, err := sourcehttp.NewJSONRequest(ctx, "compliance-team-slack", sink.baseURL, sink.allowLoopback, http.MethodPost, "/chat.postMessage", nil, payload)
	if err != nil {
		return err
	}
	response, err := sink.client.Do(request)
	if err != nil {
		return fmt.Errorf("post compliance team update to Slack: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Slack team update response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("slack team update returned HTTP %d", response.StatusCode)
	}
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode Slack team update response: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("slack team update was rejected: %s", strings.TrimSpace(result.Error))
	}
	return nil
}

func slackTeamUpdateText(update improvement.TeamUpdate) string {
	var builder strings.Builder
	builder.WriteString("Compliance program change needs review\n")
	builder.WriteString("Gap: ")
	builder.WriteString(update.GapSummary)
	builder.WriteString("\nCurrent: ")
	builder.WriteString(formatMeasurement(update.Current.Value, update.Current.Unit))
	builder.WriteString("\nTarget: ")
	builder.WriteString(update.Target.Comparator)
	builder.WriteByte(' ')
	builder.WriteString(formatMeasurement(update.Target.Value, update.Target.Unit))
	fmt.Fprintf(&builder, "\nSupporting facts: %d; counterevidence: %d; unknowns: %d", len(update.Supporting), len(update.Counterevidence), len(update.Unknowns))
	builder.WriteString("\nChecks: ")
	passing, warnings := 0, 0
	for _, result := range update.Verification {
		switch result.Status {
		case improvement.VerificationPass:
			passing++
		case improvement.VerificationWarn:
			warnings++
		}
	}
	fmt.Fprintf(&builder, "%d passed; %d warnings; 0 blocking", passing, warnings)
	builder.WriteString("\nDraft PR: ")
	builder.WriteString(update.PullRequest.URL)
	builder.WriteString("\nDecision owner: ")
	builder.WriteString(update.DecisionOwner)
	builder.WriteString("\nAction: ")
	builder.WriteString(update.RequiredAction)
	return builder.String()
}

func formatMeasurement(value float64, unit string) string {
	return fmt.Sprintf("%g %s", value, strings.TrimSpace(unit))
}
